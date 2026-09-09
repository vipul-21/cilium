# FQDN zombie-growth benchmark — runbook

Reproduces and measures the DNS lock-contention failure in cilium/cilium#48359,
and benchmarks any candidate fix against it.

Related: PR cilium/cilium#48424 (`--tofqdns-ttl-bound-zones`),
PR cilium/cilium#48360 (O(N) zombie de-dup).

---

## 1. What it measures

The bug: when many unique FQDNs resolve to the **same IP** and a live connection
pins that IP, every name is retained as a "zombie" forever. `DNSCache.GC` walks
them all while holding the global cache lock (`pkg/fqdn/cache.go:347`), and every
DNS response needs the same lock (`pkg/fqdn/cache.go:212`) — so DNS resolution
stalls agent-wide.

Reproducing it needs **three** conditions at once. Remove any one and nothing
happens:

1. Unbounded name cardinality — every lookup is a name never seen before
2. All names resolve to one IP
3. A long-lived connection pinning that IP

## 2. Files

All paths under `~/.copilot/session-state/<session>/files/` — copy them somewhere
permanent before relying on them.

| file | purpose |
|---|---|
| `fqdn-bench.sh` | harness: N endpoints share the load (distributed shape) |
| `fqdn-bench-mixed.sh` | harness: 1 heavy endpoint + N observers on one node (**production shape**) |
| `observer.py` | light DNS client; measures collateral damage |
| `workload-observer.yaml` | observer Deployment (node-pinned by the harness) |
| `client-fixed.py` | closed-loop DNS load generator (goes in a ConfigMap) |
| `fqdn-benchmark-spec.md` | full methodology, validity checks, pass criteria |
| `workload-client.yaml` | client Deployment (30 replicas, dnsConfig) |
| `workload-target.yaml` | target Deployment — the shared IP |
| `policy-benchmark.yaml` | CiliumNetworkPolicy: 12 toFQDNs selectors + host allow |
| `coredns-custom.yaml` | CoreDNS `template` block: whole zone -> one IP |

## 3. Cluster prerequisites

Built and validated on:

```
AKS BYO CNI, westus2, k8s 1.34, overlay, no kube-proxy
2 x Standard_D4_v3
Cilium installed from the branch under test (Helm, images in ACR)
```

Create with:

```bash
cd ~/ws/azure-container-networking/hack/aks
make overlay-byocni-nokubeproxy-up AZCLI=az SUB=<sub> \
  CLUSTER=<name> REGION=westus2 K8S_VER=1.34 NODE_COUNT=2 VM_SIZE=Standard_D4_v3
```

Note: k8s 1.33 is LTS-only in westus2 and will be rejected.

Build and push agent + operator from the branch:

```bash
make docker-cilium-image docker-operator-generic-image \
  DOCKER_REGISTRY=<acr>.azurecr.io DOCKER_DEV_ACCOUNT=cilium \
  DOCKER_IMAGE_TAG=<tag> DOCKER_FLAGS=--push
```

## 4. Workload setup (once per cluster)

```bash
kubectl create ns oai
kubectl apply -f workload-target.yaml          # the shared IP
kubectl apply -f policy-benchmark.yaml

# point the whole zone at the target's IP
TIP=$(kubectl -n oai get pod -l app=target -o jsonpath='{.items[0].status.podIP}')
sed "s/10\.10\.0\.4/$TIP/" coredns-custom.yaml | kubectl apply -f -
kubectl -n kube-system rollout restart deploy coredns

kubectl -n oai create cm oai-client-fixed --from-file=client.py=client-fixed.py
kubectl apply -f workload-client.yaml
```

**The target must NOT be a node IP.** A node IP carries `reserved:host`, which
outranks the CIDR identity `toFQDNs` creates, so the keepalive is denied and no
zombie is ever pinned. If the target lands on a node IP, add:

```yaml
egress:
  - toEntities: [host, remote-node]
    toPorts: [{ports: [{port: "80", protocol: TCP}]}]
```

## 5. Test parameters

### Fixed (do not vary between arms)

| parameter | value | env |
|---|---|---|
| unique FQDNs offered | **200,000** | `TOTAL_NAMES` |
| duration of offered load | **600 s** | `DURATION` |
| aggregate offered rate | **333 lookups/s** | derived |
| client pods | 30 | `PODS` |
| worker threads per pod | 24 | `WORKERS` |
| per pod | 6,666 names at 11.1/s | derived |
| name shape | `10-<a>-<b>-<c>-<uuid4hex>-<port>.<zone>.` | — |
| sampling | every 60 s | — |

Name shape mirrors production exactly:
`10-225-10-13-<uuid32>-22486.app.applied-caas16.internal.api.openai.org`

### The CiliumNetworkPolicy is a test parameter

`policy-benchmark.yaml` carries **12 toFQDNs selectors**, copied from the
affected production cluster. Selector count is not cosmetic:
`deriveLabelsForName()` (`pkg/fqdn/namemanager/manager.go:422`) walks **every**
selector for **every** resolved name, so label-derivation cost is
`names x selectors`. Changing the count changes the workload.

Two rules, each load-bearing:

| rule | why it must be there |
|---|---|
| DNS visibility (`port 53`, `rules.dns.matchPattern: "*"`) | without it the proxy never intercepts DNS, nothing is cached, and the bug cannot reproduce |
| `toFQDNs` with 12 selectors | `*.*.*.internal.api.openai.org` is the one that matches the generated names (3 dynamic labels above the zone) |

`oai-host-allow` is only needed when the target lands on a node IP — see §4.

Verify the agent registered them:

```bash
cilium-dbg metrics list | grep cilium_fqdn_selectors     # expect 12
cilium-dbg policy selectors | grep openai                # 12 FQDN rows
```

### Resolver options — REQUIRED, already in `workload-client.yaml`

```yaml
dnsConfig:
  options:
    - {name: timeout,  value: "30"}
    - {name: attempts, value: "1"}
    - {name: ndots,    value: "1"}
```

Without these the test is invalid:
- glibc defaults to `attempts:2`, so every timed-out lookup fires a second query
- `ndots:5` then expands failures across 4 cluster search domains
- combined: **up to 10 real queries per logical lookup**, and *more* in the
  degraded arm — so offered load is neither constant nor known
- `timeout:5` also truncates latency at exactly 5.004 s, hiding real waits

Names carry a trailing dot for the same reason (no search expansion).

### Varied

| variable | values |
|---|---|
| `tofqdns-min-ttl` | `0` (DNS TTL 60 s applies) or `3600` |
| change under test | off / on |

The **60 s** pair is the primary result — production's cache shows TTLs of 40-60 s.
The 3600 s pair is a control: at that TTL nothing expires inside the window, so no
zombies form and a zombie-targeting fix has nothing to act on.

## 6. Running

**Zombies are per-endpoint** (`ep.DNSZombies`, `pkg/fqdn/namemanager/gc.go:70`)
and the quadratic runs per zombie, i.e. per (endpoint, IP) pair. Spreading names
across 30 endpoints therefore understates the failure by ~6x versus concentrating
them on one. Production had **160,050 names on a single endpoint** (98.5% of its
whole cache), so the mixed harness is the faithful shape.

```bash
# distributed: N endpoints share the names
./fqdn-bench.sh <label> <min-ttl> <ttl-bound-zones> [sample-minutes]

# production shape: 1 heavy endpoint + 5 observers on the same node
./fqdn-bench-mixed.sh <label> <min-ttl> <ttl-bound-zones> [sample-minutes]

./fqdn-bench.sh base-60   0    ""                        11   # baseline
./fqdn-bench.sh flag-60   0    internal.api.openai.org   11   # fix on
./fqdn-bench.sh base-3600 3600 ""                        11   # control
./fqdn-bench.sh flag-3600 3600 internal.api.openai.org   11
```

Each arm takes ~15 min (2 min reset + 11 min sampling + reporting).
Results land in `/tmp/bench-<label>/`:

```
run.log       human-readable log + final report
samples.tsv   minute cache lookup conn lockwarns cpu
clients.txt   offered / done / failed / backlog
<agent>.log   full streamed agent log
```

The harness **aborts** if the cache is not empty after the agent restart —
that means state survived and the arm would not be comparable.

## 7. Metrics

Primary — name-lock wait distribution, from the `duration=` field of
`Name lock acquisition time took longer than expected`:
p50 / p90 / p99 / max, and **counts over 5 s, 10 s, 30 s**.

Secondary:

| metric | why |
|---|---|
| **cache composition** (`lookup` vs `connection`) | decisive. `connection` = zombies. Distinguishes "GC got faster" from "there is less to GC" |
| backlog | offered-but-unserved; the honest measure of collapse |
| client p50/p99 | customer-visible latency |
| warnings by type | `Name lock` = bug signal. `datapath updates` is a per-new-name cost, NOT a bug signal — it scales with throughput |
| agent CPU | detects saturation invalidating the run |

## 8. Baseline results (no fix, min-ttl=0, TTL 60 s)

Reference numbers on 2 x D4_v3:

| | |
|---|---|
| offered | 199,980 / 200,000 (99.99%) |
| completed | 101,589 (50.8%) |
| **backlog** | **96,307 (48.2%)** |
| failed | 1,364 (0.68%) |
| client p50 / p99 | 2.250 s / 30.03 s (at timeout ceiling) |
| lock waits | n=53,196, p50 3.83 s, p99 34.69 s, max 87.69 s |
| > 5 s / > 10 s | 40.7% / 20.5% |
| final cache | 49,870 / 44,373, **~92% zombies** |
| errors | **0** |
| log volume | ~53k warnings per agent per 10 min |

### Onset thresholds

| event | cache size |
|---|---|
| first warnings | ~10,000 (before any zombie exists) |
| **p99 crosses the 5 s resolver timeout** | ~10,000 |
| **p50 crosses 5 s** (half of lookups fail) | 10,000-18,000 |
| p50 exceeds 60 s | ~29,700 |
| p50 exceeds 240 s | ~42,700 |

### Scaling law

```
p50 wait ~ zombies ^ 2.00      (R2 = 0.92)
```

Empirical confirmation of the O(N^2) behaviour, measured on a live cluster.

### Fidelity to production

| | benchmark | production |
|---|---|---|
| cache composition | 92-99.7% `connection` | **99.8% `connection`** |
| names on one IP | up to 200,000 | 160,050 |
| errors logged | 0 | 0 |

## 9. Pass criteria for a candidate fix

At min-ttl=0 / TTL 60 s, versus its own baseline:

| | threshold |
|---|---|
| waits > 10 s | **0** |
| p99 wait | < 5 s |
| cache | flat, not merely growing slower |
| backlog | < 5% of offered |
| client p99 | < 1 s |
| errors | 0 |

A **perf fix** should improve wait times while leaving cache size and composition
unchanged. A **zombie-prevention fix** should drive `connection` entries to 0.
That difference is the point of tracking composition.

## 10. Gotchas

| | |
|---|---|
| Stream agent logs to disk | `kubectl logs` rotates; one count silently shrank 34,833 -> 1,343 |
| Stop streams at arm end | a stray stream captured later tests and inflated an arm 2.6x |
| Both arms from an empty cache | comparing from-empty against already-degraded once inverted the verdict |
| Read client counters before scaling down | they vanish with the pods |
| Take the **last** report line per pod | summing a window multi-counts (30 pods reported as 73) |
| Report per-agent, never averaged | between-agent spread inside one arm reached 1.8x |
| No extra pods with `app=client` | a debug probe polluted the label set once |
| Watch agent CPU | at 240 threads the agent saturated and the run measured the rig |
| Zombies need ~1 TTL to appear | at t+1m with TTL 60 s, `conn` is legitimately 0 |

## 11. Validity cross-checks

A run is only trustworthy if these hold:

1. **Little's Law** — `threads / mean-latency ~= throughput`
   (verified: 120 / 4.8 s = 25/s vs 24.9/s measured)
2. **Steady state** — with growth prevented, `cache ~= rate x TTL`
   (verified: 346.7/s x 60 s = 20,802 predicted vs 21,650 observed, +4%)
3. **Composition** — at min-ttl=3600 within the first hour, `connection` must be
   0 in both arms; nothing has expired, so no fix can act

If a check fails, repeat the run rather than reporting it.

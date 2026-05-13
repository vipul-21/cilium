# Upstream AKS Conformance vs. Azure Container Networking (ACN) Cilium Nightly

The Azure team runs an independent nightly pipeline against `master` Cilium in
[`Azure/azure-container-networking`](https://github.com/Azure/azure-container-networking)
at `.pipelines/cni/cilium/nightly-release-test.yml`. It exercises Cilium in
the **Azure-supported deployment shape** (Cilium dataplane on top of Azure
CNS for IPAM), which is materially different from upstream's BYOCNI
conformance documented in [`README.md`](./README.md).

> **TL;DR**
> Upstream runs **5 different AKS variants** (Base, KPR+adv, KPR+adv+IPsec,
> KPR+adv+WG, IPsec-only) on a pure BYOCNI cluster with Cilium IPAM and
> dual-stack. ACN nightly runs **1 variant** with `delegated-plugin` IPAM,
> native routing, IPv4-only, KPR + LRP always-on, no encryption. The two are
> intentionally complementary; neither is a superset of the other.

## 1. Variant inventory

These are the concrete, repeating jobs each pipeline runs (not opt-in flags).

| ID | Variant | Workflow / job | Trigger |
|---|---|---|---|
| **U-base** | Base AKS conformance | `.github/workflows/conformance-aks.yaml` (direct schedule) | every 12h `0 0/12 * * *` |
| **U-kpr** | KPR + advanced features | `conformance-kpr-aks.yaml` → `conformance-aks-kpr` (UID 1) | every 12h `0 4/12 * * *` |
| **U-kpr-ipsec** | KPR + advanced + IPsec | `conformance-kpr-aks.yaml` → `conformance-aks-kpr-ipsec` (UID 2) | every 12h `0 4/12 * * *` |
| **U-kpr-wg** | KPR + advanced + WireGuard | `conformance-kpr-aks.yaml` → `conformance-aks-kpr-wireguard` (UID 3) | every 12h `0 4/12 * * *` |
| **U-ipsec** | IPsec only (no KPR, no advanced) | `conformance-ipsec.yaml` → `conformance-aks-ipsec` | per ipsec workflow schedule |
| **ACN** | ACN cilium nightly | `.pipelines/cni/cilium/nightly-release-test.yml` | nightly |

## 2. Cluster shape

| Aspect | All upstream variants | ACN nightly |
|---|---|---|
| Cluster type | `--network-plugin none` (BYOCNI, kube-proxy enabled by default) | `--network-plugin none --network-plugin-mode overlay` + `--kube-proxy-config` disabling kube-proxy (`overlay-byocni-nokubeproxy-up`) |
| IPAM | Cilium `cluster-pool` (`192.168.0.0/16` / `fd00::/104`) | Azure CNS via `ipam: delegated-plugin` |
| Routing | Tunnel (default vxlan) | `routing-mode: native` + `enable-endpoint-routes: true` (Azure overlay) |
| IP family | Dual-stack (IPv4 + IPv6) | Single-stack IPv4 |
| K8s versions | Matrix 1.31 – 1.35 across 5 regions | Single version (cluster default) |
| VM SKU | `Standard_B2s`, OS disk 30 GB | `Standard_B2ms` |
| Cilium image | Released image, optional `--image-tag` | `master` built from source each run, pushed to ACR |
| Install method | `cilium install` (Helm under the hood) | Raw kubectl manifests under `test/integration/manifests/cilium/` |

## 3. Effective Cilium configuration per variant

Every upstream variant gets these base helm values from `conformance-aks.yaml`
(applied unconditionally):

```
--datapath-mode=aks-byocni
--helm-set=cluster.name=cilium
--helm-set=loadBalancer.l7.backend=envoy
--helm-set=ipv4.enabled=true
--helm-set=ipv6.enabled=true
--helm-set=ipam.operator.clusterPoolIPv4PodCIDRList=192.168.0.0/16
--helm-set=ipam.operator.clusterPoolIPv6PodCIDRList=fd00::/104
```

The columns below show what each variant **actually deploys** after applying
its `extra-args`. ACN's column is the static ConfigMap at
`test/integration/manifests/cilium/cilium-nightly-config.yaml`.

> Legend: ✅ = enabled, ❌ = disabled, `(default X)` = unset → helm chart
> default applies, `n/a` = setting does not apply to this deployment shape.

### Datapath / IPAM

| Setting | U-base | U-kpr | U-kpr-ipsec | U-kpr-wg | U-ipsec | ACN |
|---|---|---|---|---|---|---|
| `ipam` | cluster-pool | cluster-pool | cluster-pool | cluster-pool | cluster-pool | **delegated-plugin** |
| `routing-mode` | tunnel | tunnel | tunnel | tunnel | tunnel | **native** |
| `enable-endpoint-routes` | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Effective **host routing** | legacy (auto-fallback) | **BPF host routing** | **BPF host routing** | **BPF host routing** | legacy (auto-fallback) | legacy (explicit) |
| `local-router-ipv4` | unset | unset | unset | unset | unset | `169.254.23.0` |
| `cluster-pool*PodCIDRList` (v4/v6) | set | set | set | set | set | n/a |
| `enable-ipv4` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `enable-ipv6` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |

> **Note on host routing.** The Cilium binary defaults to BPF host routing
> (`enable-host-legacy-routing=false`, see
> `pkg/defaults/defaults.go: EnableHostLegacyRouting = false`). However,
> `pkg/kpr/initializer/kube_proxy_replacement.go` *automatically falls back*
> to legacy host routing when **KPR is off** or **iptables masquerade is in
> use** (i.e. `enable-ipv4-masquerade=true` or `enable-ipv6-masquerade=true`
> without `bpf.masquerade=true`). That's why only the variants that combine
> KPR + BPF masquerade (`U-kpr`, `U-kpr-ipsec`, `U-kpr-wg`) end up with the
> BPF host-routing fast path.
> ACN explicitly sets `enable-host-legacy-routing: "true"` in
> `cilium-nightly-config.yaml`, pinning it to legacy iptables-based routing
> regardless of KPR state — required because the AKS overlay datapath under
> CNS routes via the host stack.

### Service handling

| Setting | U-base | U-kpr | U-kpr-ipsec | U-kpr-wg | U-ipsec | ACN |
|---|---|---|---|---|---|---|
| `kubeProxyReplacement` | ❌ (default) | ✅ | ✅ | ✅ | ❌ | ✅ |
| Cluster runs kube-proxy | ✅ | ✅* | ✅* | ✅* | ✅ | ❌ |

\* KPR is enabled in Cilium but the cluster's kube-proxy DaemonSet is still
present (AKS default). Upstream relies on Cilium taking over service handling
at runtime. ACN removes kube-proxy at cluster-create time via
`--kube-proxy-config` so KPR is the only option.

### Masquerading

| Setting | U-base | U-kpr | U-kpr-ipsec | U-kpr-wg | U-ipsec | ACN |
|---|---|---|---|---|---|---|
| `bpf.masquerade` | ❌ (default) | ✅ | ✅ | ✅ | ❌ (default) | ❌ |
| `enableIPv4Masquerade` / `enable-ipv4-masquerade` | ✅ (default) | ✅ | ✅ | ✅ | ✅ (default) | ❌ |
| `enable-ipv6-masquerade` | ✅ (default) | ✅ (default) | ✅ (default) | ✅ (default) | ✅ (default) | ❌ |

ACN disables in-Cilium masquerade because Azure performs SNAT at the VNet
edge.

### Encryption

| Setting | U-base | U-kpr | U-kpr-ipsec | U-kpr-wg | U-ipsec | ACN |
|---|---|---|---|---|---|---|
| `encryption.enabled` | ❌ | ❌ | ✅ | ✅ | ✅ | ❌ |
| `encryption.type` | n/a | n/a | `ipsec` | `wireguard` | `ipsec` | n/a |

### Advanced features

| Setting | U-base | U-kpr | U-kpr-ipsec | U-kpr-wg | U-ipsec | ACN |
|---|---|---|---|---|---|---|
| `localRedirectPolicy` / `enable-local-redirect-policy` | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| `egressGateway.enabled` | ❌ | ✅ | ✅ | ✅ | ❌ | ❌ |

### Other notable diverging defaults

| Setting | U-base | U-kpr | U-kpr-ipsec | U-kpr-wg | U-ipsec | ACN |
|---|---|---|---|---|---|---|
| `loadBalancer.l7.backend` | `envoy` | `envoy` | `envoy` | `envoy` | `envoy` | unset (default) |
| `enable-cilium-endpoint-slice` / `ces-slice-mode` | ❌ (default) | ❌ (default) | ❌ (default) | ❌ (default) | ❌ (default) | ✅ / `fcfs` |
| `enable-bgp-control-plane` | ❌ (default) | ❌ (default) | ❌ (default) | ❌ (default) | ❌ (default) | ❌ |
| `enable-l7-proxy` | ✅ (default) | ✅ (default) | ✅ (default) | ✅ (default) | ✅ (default) | ✅ |
| `enable-k8s-networkpolicy` | ✅ (default) | ✅ (default) | ✅ (default) | ✅ (default) | ✅ (default) | ✅ |

## 4. Test-coverage differences

Once Cilium is up, each pipeline runs a different test suite.

### Run by every upstream variant

The exact same test split runs in **U-base, U-kpr, U-kpr-ipsec, U-kpr-wg, U-ipsec**:

- `cilium connectivity test --test "seq-.*"` — sequential tests.
- `cilium connectivity test --test-concurrency=5 --test '!seq-.*'` —
  concurrent tests with concurrency 5.
- Common flags from `.github/actions/cli-test-config`:
  `--collect-sysdump-on-failure`, `--external-target=nginx.external.svc.cluster.local`,
  `--external-cidr/--external-ip/--external-other-ip` (and v6 equivalents),
  `--external-target-ca-namespace=external-target-secrets`,
  `--external-target-ca-name=custom-ca`, `--external-target-fake-dns`,
  `--hubble=false`, `--flow-validation=disabled`.
- L7 TLS to external nginx targets via a generated CA, plus IPv6 endpoints.

So `pod-to-pod-encryption` and `node-to-node-encryption` are exercised in
**U-kpr-ipsec, U-kpr-wg, U-ipsec**; egress-gateway and BPF masquerade tests
are exercised in **U-kpr, U-kpr-ipsec, U-kpr-wg**.

### Run only by ACN nightly

Each item below is a separate pipeline step, with the actual test source and
what it asserts.

#### Image build (`init` stage)

Builds two images from upstream `master` and pushes to ACR before any test
runs (catches build/packaging regressions early):

- `quay.io/cilium/cilium:<tag>` → `<acr>.azurecr.io/cilium/cilium:<tag>`
- `quay.io/cilium/operator-generic:<tag>` → `<acr>.azurecr.io/cilium/operator-generic:<tag>`

The `operator-generic` Dockerfile is patched to add
`GOEXPERIMENT=boringcrypto` so the binary uses Microsoft Go's FIPS-compliant
crypto. `golang` and `alpine` base images are pinned to MCR / ACR mirrors.

#### Azilium / load test (`make test-load`)

Source: `test/integration/load/load_test.go::TestLoad`
(invoked via `make test-load SCALE_UP=32 OS_TYPE=linux VALIDATE_STATEFILE=true INSTALL_CNS=true INSTALL_OVERLAY=true CLEANUP=true`).

What it does:

1. Deploys a `noop-deployment-linux` (busybox sleep) to namespace `load-test`.
2. Loops `ITERATIONS=2` (default) cycles of: scale **down to 1**, then scale
   **up to 32** replicas. Times out at 10 min per iteration.
3. After all iterations, asserts every pod has an IP and is `Running`.
4. With `VALIDATE_STATEFILE=true`, runs `TestValidateState` which scales the
   deployment to `2 × node count` so every node has pods, then exec's into
   each node's privileged pod and compares IP sets across:
   - **CNS endpoint state file** — `cat /var/run/azure-cns/azure-endpoints.json`
   - **Cilium endpoint list** — `cilium endpoint list -o json`
   - **CNS local cache** — `curl localhost:10090/debug/ipaddresses -d '{"IPConfigStateFilter":["Assigned"]}'`

   All three sources must agree: same pod-IP set, no leaked IPs.

#### VMSS node restart + post-restart state validation

What it does:

1. Lists all VMSS scale sets in the node resource group
   (`MC_<cluster>_<cluster>_<region>`).
2. For each VMSS, runs `make -C ./hack/aks restart-vmss` which calls
   `az vmss restart`.
3. After all nodes return, re-runs the validator with `RESTART_CASE=true`,
   which performs the same CNS / Cilium / CNS-cache state-file comparison as
   above to confirm pod IP assignments survived (no leaks, no orphans).

#### Cluster scale up/down loop (`TestLoad` again, post-restart)

Source: `test/integration/load/load_test.go::TestLoad` invoked a second time
with `ITERATIONS=2 SCALE_UP=<scaleup> OS_TYPE=linux`. Same scale-down /
scale-up cycle as Azilium but executed *after* node restart, then
`make test-validate-state OS_TYPE=linux RESTART_CASE=true` re-validates the
state files.

#### Local Redirect Policy integration test

Source: `test/integration/lrp/lrp_test.go::TestLRP` (build tag `lrp`).

Pre-flight: asserts `cilium-config` has `enable-local-redirect-policy=true`.

Then deploys `node-local-dns` (DaemonSet + ConfigMap + Service +
ServiceAccount) with `__PILLAR__DNS__SERVER__` substituted with the
`kube-dns` ClusterIP, deploys a busybox client DaemonSet, and applies a
Cilium `CiliumLocalRedirectPolicy`. Picks one node and one client pod on
that node, port-forwards to the local node-local-dns pod's prometheus
endpoint (port 9253).

Asserts (each step `nslookup`s a domain via the kube-dns ClusterIP from the
client pod, then reads `coredns_dns_request_count_total` from prometheus
with labels `family=1, proto=udp, server=dns://0.0.0.0:53, zone=.`):

1. **Basic LRP**: counter strictly increases → DNS traffic was redirected to
   the node-local-dns pod, not sent to kube-dns.
2. **Pod restart persistence**: delete the client DaemonSet's pod, recreate,
   and re-run the lookup; counter increases again.
3. **Cilium command validation**: parses `cilium lrp list` output to confirm
   the LRP is still installed.
4. **Resource recreation**: delete and recreate the LRP, node-local-dns DS,
   and client DS; re-establish port-forward on a new port (9254); verify
   counter again increases for the new node-local-dns pod.

#### Cilium identity GC verification

Source: `.pipelines/templates/cilium-nightly-checks.yaml`.

After `cilium connectivity test` has finished:

1. Discovers the test namespace via `kubectl get ns | grep cilium-test`.
2. `kubectl delete ns <cilium-test*>` and waits for all pods to disappear.
3. After 20s settle, runs
   `kubectl get ciliumidentity -o json | grep cilium-test | jq -e 'length == 0'`.
4. Fails the job if any CiliumIdentity referencing the deleted namespace
   still exists (catches identity-GC leaks).

#### Wireserver + IMDS connectivity test

Source: `test/network/wireserver_metadata_test.sh`.

Two `kubectl run busybox` invocations from a pod (default service account,
default network policy):

1. `wget --header=Metadata:true http://168.63.129.16/machine/plugins?comp=nmagent&type=getinterfaceinfov1` —
   pod traffic to the **Azure Wireserver**. Test **expects this to fail**;
   passes only if wget returns non-zero. Verifies pod-to-host metadata
   plane is firewalled correctly.
2. `wget --header=Metadata:true http://169.254.169.254/metadata/instance?api-version=2021-02-01` —
   pod traffic to **IMDS**. Expects success.

#### Hubble metrics endpoint test

Source: `test/integration/networkobservability/hubble_test.go`
(build tag `networkobservability`).

Pre-step: `make deploy-hubble` enables hubble in `cilium-config`, restarts
the cilium DaemonSet, waits 3 min for rollout.

Then for each cilium pod, scrapes `http://localhost:9965/metrics` and
asserts the following metric series exist with the expected label keys:

| Metric | Required labels |
|---|---|
| `hubble_flows_processed_total` | `source`, `destination` |
| `hubble_tcp_flags_total` | `source`, `destination` |
| `hubble_dns_responses_total` | `query` |
| `hubble_dns_response_types_total` | `query` |
| `hubble_dns_queries_total` | `query` |
| `hubble_drop_total` | `source` |

#### Kubernetes e2e suites (sig-network conformance)

Source: `.pipelines/cni/k8s-e2e/k8s-e2e-job-template.yaml`. Downloads the
exact `kubernetes-test-linux-amd64.tar.gz` matching the cluster's k8s
version and runs upstream `e2e.test` via ginkgo:

| Suite | ginkgo focus | ginkgo skip | Procs | Flake attempts |
|---|---|---|---|---|
| **datapath** | `(.*).Networking.should\|(.*).Networking.Granular\|(.*)kubernetes.api\|(.*).NoSNAT` | `SCTP\|Disruptive\|Slow\|hostNetwork\|kube-proxy\|IPv6` | 8 | 10 |
| **dns** | `\[sig-network\].DNS.should` | `resolv\|256 search` | 8 | 3 |
| **portforward** | `\[sig-cli\].Kubectl.Port` | `port-forward should keep working after detect broken connection` | 8 | 3 |
| **service** (cilium variant) | `Services.*\[Conformance\].*` | `should serve endpoints on same port and different protocols` (Cilium gap, see [cilium#25135 referenced upstream](https://github.com/kubernetes/kubernetes/blame/e602e9e03cd744c23dde9fee09396812dd7bdd93/test/conformance/testdata/conformance.yaml#L1780-L1788)) | 8 | 3 |

#### `check-log-errors`

In the post-test "Nightly Logs" job:

```
cilium connectivity test --test check-log-errors --log-check-levels error
```

Scans the Cilium agent and operator logs for `level=error` entries.

Plus a separate `kubectl logs -l name=cilium-operator | grep level=error`
check via `log-check-template.yaml`.

#### MTU consistency check

Source: `hack/scripts/cilium-mtu-validation.sh`.

1. Deploys an nginx Deployment in `kube-system` and scales to
   `3 × node count` replicas so every node has an nginx pod.
2. For each node, reads `eth0` MTU from three sources:
   - cilium-agent pod (`/sys/class/net/eth0/mtu`)
   - nginx pod (`/sys/class/net/eth0/mtu`)
   - the node itself via `kubectl debug node/<node> --image=busybox`
3. Asserts all three MTUs match per node. Fails on any mismatch.
4. Cleans up the nginx Deployment and `node-debugger` pods.

#### `cilium-log-collector` sidecar

Source: `test/integration/manifests/cilium/v1.17/cilium-log-collector/`.

Patches the cilium DaemonSet to add a `cilium-log-collector` container that
streams agent logs to a configmap-controlled sink. Gives richer, timestamped
diagnostics for any test failure in the run.

### Existing upstream tests ACN could leverage

Many ACN-only steps re-implement coverage that already exists upstream in
`cilium connectivity test`. The table below maps each ACN test to its
closest upstream counterpart.

| ACN step | Closest upstream test | Source | Could replace? |
|---|---|---|---|
| `check-log-errors` (operator + agent) | **`check-log-errors`** | `cilium-cli/connectivity/builder/check_log_errors.go` → `tests.NoErrorsInLogs`. Auto-registered into every `cilium connectivity test` run via `finalTests()` (`cilium-cli/connectivity/builder/builder.go:356-361`). | ⚠️ **Used inefficiently** — ACN explicitly *skips* it in the main connectivity-test run and then re-invokes it as a separate step. Two invocations doing one job. See §6.1 for the fix. |
| LRP + node-local-dns integration test | **`local-redirect-policy-with-node-dns`** | `cilium-cli/connectivity/builder/local_redirect_policy_with_nodedns.go` → `tests.LRPWithNodeDNS` | ⚠️ Partially — upstream test curls an external echo through node-local-dns and checks the path works. ACN additionally asserts `coredns_dns_request_count_total` increments at the node-local-dns pod's prometheus and exercises pod-restart / full-recreation lifecycle. Upstream covers the redirect itself; ACN's lifecycle assertions are extra. Requires `IncludeUnsafeTests`, `NodeLocalDNS`, `NodeWithoutCilium`, `LocalRedirectPolicy` features |
| LRP base case | **`local-redirect-policy`** | `cilium-cli/connectivity/builder/local_redirect_policy.go` → `tests.lrp` | ⚠️ Partially — covers core LRP semantics across IP families; doesn't cover node-local-dns wiring or metrics |
| MTU consistency check (cilium agent / nginx / node) | **`pod-to-pod-no-frag`** | `cilium-cli/connectivity/builder/no_fragmentation.go` → `tests.podToPodNoFrag` | ⚠️ Partially — derives the route MTU and pings with `-M do` payload-size = MTU − headers, validating no fragmentation across the datapath. ACN's script directly compares `/sys/class/net/eth0/mtu` between cilium-agent / nginx / node. Different goals: upstream proves MTU is *honored end-to-end*; ACN proves all interfaces are *configured the same*. Both useful |
| Hubble metrics endpoint test | **`allow-all-with-metrics-check`** (closest pattern) | `cilium-cli/connectivity/builder/allow_all_with_metrics_check.go` | ❌ Not a substitute — upstream test checks `cilium_forward_count_total` on the agent metrics endpoint after pod-to-pod traffic. ACN scrapes 6 Hubble-specific series (`hubble_flows_processed_total`, `hubble_tcp_flags_total`, `hubble_dns_responses_total`, `hubble_dns_response_types_total`, `hubble_dns_queries_total`, `hubble_drop_total`) on the Hubble metrics port (`:9965`) and asserts label keys. The upstream framework has `ExpectMetricsIncrease` machinery that *could* be extended, but no ready-made test for these series |
| Cilium identity GC verification (post-namespace-delete) | none | `operator/pkg/ciliumidentity/` and `operator/pkg/identitygc` are the production code, not a connectivity test | ❌ No upstream connectivity test asserts CiliumIdentity GC after namespace deletion. Could be contributed |
| Azilium load test (state-file consistency: CNS ↔ Cilium ↔ CNS cache) | none | — | ❌ Not applicable — relies on `delegated-plugin` IPAM; upstream uses `cluster-pool` and has no equivalent state to compare. CNS-specific |
| VMSS node restart + post-restart state validation | none | — | ❌ Cloud-specific (Azure VMSS API). Closest upstream coverage is `tests-e2e-upgrade.yaml` (workflow-level node lifecycle), but it's a different scenario |
| Cluster scale up/down loop | none | — | ❌ Closest is the GCE-only `scale-test-*.yaml` workflows but those measure scale on Cilium-managed clusters, not Azure VMSS scale + state revalidation |
| Wireserver (`168.63.129.16`) firewall test | none | — | ❌ Azure-specific host endpoint; no upstream equivalent |
| IMDS (`169.254.169.254`) reachability test | none | — | ❌ Cloud-specific; could be modeled as a `ToCIDR` test but the assertion is cloud-platform-specific |
| K8s sig-network e2e (`datapath`, `dns`, `portforward`, `service`) | none in cilium-cli | upstream Kubernetes `e2e.test` (sig-release tarball) | ⚠️ **Used by ACN, but not by upstream Cilium for AKS conformance.** Upstream `conformance-aks.yaml` runs *only* `cilium connectivity test` — no K8s ginkgo. The `k8s-kind-network-e2e.yaml` workflow that still uses ginkgo is Kind-only (CNI conformance + kube-apiserver HA), not the AKS gate. See §6.2 for the recommendation to drop these from ACN. |
| Image build from `master` + ACR push | none | — | ❌ Pipeline-only step; no test equivalent |
| `cilium-log-collector` sidecar | none | — | ❌ Diagnostic tooling; not a test |

**Net of overlap:**

- `check-log-errors` is **double-invoked** — once skipped, once run separately.
  Should be a single auto-run inside the main connectivity-test invocation.
- K8s sig-network ginkgo suites are **ACN-only** — upstream Cilium does not
  run them for AKS conformance.
- The LRP and MTU steps **could be partially replaced** with
  `local-redirect-policy-with-node-dns` and `pod-to-pod-no-frag`, but the
  ACN versions assert additional lifecycle / configuration properties the
  upstream tests don't cover.
- The Hubble-metrics, identity-GC, Azilium, VMSS restart, scale loop, and
  wireserver/IMDS steps have no upstream equivalent today.

### `cilium connectivity test` in ACN

ACN also runs `cilium connectivity test`, but with a different shape:

- One single invocation with `--force-deploy` (no sequential/concurrent split).
- Skips: `pod-to-pod-encryption`, `node-to-node-encryption`,
  `check-log-errors`, `no-unexpected-packet-drops`, `to-fqdns`.
- No `external-cidr` / `external-ip` / external-target-CA plumbing
  (no L7-TLS-to-external target).
- IPv4 only (cluster is single-stack).

## 5. What each pipeline really validates

- **Upstream conformance** owns **breadth of Cilium feature coverage** —
  five distinct datapath/encryption combinations on a pure BYOCNI cluster
  with Cilium IPAM, dual-stack, and the full connectivity-test surface
  including L7 TLS and egress-gateway/IPsec/WireGuard.
- **ACN nightly** owns **depth of the Azure delivery shape** — delegated
  IPAM + native overlay routing + CNS integration, exercised under VMSS
  node-restart, scale churn, Azure metadata/wireserver, LRP and Hubble
  metrics, against `master` Cilium images built from source.

Anything that exists only in one column above is a real gap on the other side.

## 6. Migration roadmap: leveraging upstream Cilium in place of ACN nightly

**Goal:** use upstream Cilium tests (specifically `cilium connectivity
test`) in place of ACN's bespoke equivalents wherever possible, and
drop ACN-only steps that upstream Cilium itself does not run for AKS
conformance. Steps with no upstream equivalent today stay in ACN.

### 6.1 Stop duplicating tests upstream already runs inside `cilium connectivity test`

These changes are pure simplification — the test already runs (or
already would run) as part of `cilium connectivity test`; ACN is just
working around it.

#### 6.1.1 `check-log-errors` — drop the separate invocation

- **Today.** ACN's main connectivity-test step explicitly **skips**
  `check-log-errors`, then re-invokes it as a separate step
  (`cilium connectivity test --test check-log-errors --log-check-levels error`).
- **Why it's redundant.** `checkLogErrors{}` is registered into
  `finalTests()` (`cilium-cli/connectivity/builder/builder.go:356-361`),
  which runs at the end of every `cilium connectivity test` invocation
  (default and `--test-concurrency` paths both call it — see
  `builder.go:198,218`).
- **Fix.**
  1. Remove `check-log-errors` from ACN's `--test` skip list.
  2. Pass `--log-check-levels error` to the main connectivity-test
     invocation.
  3. Delete the separate step in
     `.pipelines/cni/cilium/nightly-release-test.yml` and the
     `kubectl logs cilium-operator | grep level=error` block in
     `.pipelines/templates/log-check-template.yaml` (the connectivity
     test now scans both agent and operator logs).

#### 6.1.2 `no-unexpected-packet-drops` — stop skipping it

- **Today.** ACN's connectivity-test invocation skips
  `no-unexpected-packet-drops`.
- **Why.** Same root cause — `noUnexpectedPacketDrops{}` is also in
  `finalTests()` and would auto-run otherwise.
- **Fix.** Remove from skip list. If it surfaces a real failure on
  the ACN cluster, file an upstream issue and either fix the
  underlying drop or scope the skip to the specific drop reason
  rather than blanket-skipping.

#### 6.1.3 `to-fqdns` — investigate and most likely re-enable

- **Today.** Skipped.
- **Why it should run.** ACN's ConfigMap has `enable-l7-proxy: true`,
  so the DNS proxy is available. The skip is most likely stale.
- **Fix.** Remove from skip list, run, triage any failures.

### 6.2 Drop K8s sig-network ginkgo suites

- **Today.** ACN nightly downloads `kubernetes-test-linux-amd64.tar.gz`
  and runs four ginkgo focuses (`datapath`, `dns`, `portforward`,
  `service`) via `.pipelines/cni/k8s-e2e/k8s-e2e-job-template.yaml`.
- **Upstream Cilium does not do this for AKS conformance.**
  `conformance-aks.yaml` runs **only** `cilium connectivity test` —
  no K8s ginkgo. The `k8s-kind-network-e2e.yaml` workflow that still
  uses ginkgo is Kind-only (CNI conformance + kube-apiserver HA),
  not part of the AKS gate. The K8s project itself is moving away
  from the monolithic ginkgo conformance pattern for networking.
- **Recommendation.** Drop the four K8s ginkgo steps from ACN
  nightly. The connectivity coverage that matters for Cilium is
  exercised by `cilium connectivity test`. Cluster-shape-independent
  K8s API behavior is owned by AKS itself.
- **Files to delete after the drop:**
  `.pipelines/cni/k8s-e2e/k8s-e2e-job-template.yaml` and the four
  ginkgo job invocations that reference it.

### 6.3 Replace ACN-bespoke tests with upstream cilium-cli equivalents

#### 6.3.1 LRP integration test → `local-redirect-policy-with-node-dns`

- **Action.** Add `local-redirect-policy-with-node-dns` to ACN's
  `cilium connectivity test` invocation.
- **Prerequisites cilium-cli auto-gates on:**
  - `--include-unsafe-tests` flag.
  - `NodeWithoutCilium` feature: at least one node tainted /
    unmanaged so cilium-cli can land the external-echo there.
  - `NodeLocalDNS` feature: deploy node-local-dns before running.
  - `LocalRedirectPolicy` feature: already enabled in
    `cilium-nightly-config.yaml`.
- **Coverage delta.** Upstream test validates the redirect path
  (HTTP curl through node-local-dns to external echo). ACN's
  `test/integration/lrp/lrp_test.go` additionally asserts:
  1. `coredns_dns_request_count_total` strictly increases on the
     node-local-dns pod's prometheus port (proves traffic actually
     terminated at node-local-dns).
  2. Persistence across client-pod restart.
  3. `cilium lrp list` output parses correctly.
  4. Persistence across full LRP + DS + client recreation.
- **Migration path.**
  1. **Now:** add `local-redirect-policy-with-node-dns` to ACN's
     invocation. Keep `lrp_test.go` for the four lifecycle assertions.
  2. **Next:** contribute the lifecycle assertions upstream as
     sub-scenarios on the same test.
  3. **Then:** retire `test/integration/lrp/lrp_test.go` and the
     LRP step in the nightly pipeline.

#### 6.3.2 MTU consistency check → `pod-to-pod-no-frag`

- **Action.** Enable `pod-to-pod-no-frag` in ACN's connectivity-test
  invocation. No extra config — runs by default when `--single-node`
  is unset.
- **Coverage delta.** Different failure modes:
  - `pod-to-pod-no-frag` proves the datapath does **not silently
    fragment** at the negotiated MTU (end-to-end behavior).
  - `cilium-mtu-validation.sh` proves `/sys/class/net/eth0/mtu` is
    **identically configured** on cilium-agent, application pod,
    and node (configuration drift).
- **Recommendation.** Add `pod-to-pod-no-frag` immediately. After
  ~60 days, if the bespoke script hasn't caught anything the
  upstream test missed, retire `hack/scripts/cilium-mtu-validation.sh`
  and the MTU step in the pipeline.

### 6.4 Broaden ACN's `cilium connectivity test` invocation toward upstream parity

ACN today: one invocation, `--force-deploy`, no concurrency split,
no external-target plumbing. Upstream pattern (from
`conformance-aks.yaml` + `.github/actions/cli-test-config`):

```
cilium connectivity test --test "seq-.*"
cilium connectivity test --test-concurrency=5 --test '!seq-.*'
```

Action items:

a) **Adopt the seq/concurrent split.** Tests prefixed `seq-` are
   known sensitive to concurrency interference. Splitting also
   reduces wall-clock since the bulk runs at `--test-concurrency=5`.

b) **Wire in external-target plumbing**:

   ```
   --external-target=nginx.external.svc.cluster.local
   --external-cidr=<VNet CIDR>
   --external-ip=<node IP>     --external-other-ip=<node IP>
   --external-target-ca-namespace=external-target-secrets
   --external-target-ca-name=custom-ca
   --external-target-fake-dns
   ```

   Without these, the L7-TLS-to-external, `to-cidr-external`, and
   `client-egress-to-cidrs` test families silently no-op. To enable:

   1. Reserve 1–2 nodes labeled `cilium.io/no-schedule=true` in the
      ACN cluster (mirrors `test/aks/run-conformance.sh`).
   2. Deploy nginx external-target DaemonSets in `external` and
      `external-other` namespaces on those nodes.
   3. Generate a self-signed CA into
      `external-target-secrets/custom-ca` (re-use upstream's
      cert-generation step).
   4. Pass the flags above to both connectivity-test invocations.

c) **Drop `--force-deploy`.** With the seq/concurrent split it would
   reinstall test resources twice. Upstream omits it.

d) **Skip-list audit** — covered in §6.1; the only remaining skips
   should be `pod-to-pod-encryption` and `node-to-node-encryption`
   (ACN has no encryption configured; cilium-cli would auto-skip on
   missing features anyway, but explicit is fine).

### 6.5 Stays in ACN nightly (no upstream substitute today)

| Step | Why it stays |
|---|---|
| Azilium load test + state-file consistency | No upstream test asserts this. |
| VMSS node restart + post-restart state revalidation | No upstream test asserts this. |
| Cluster scale up/down loop | No upstream test asserts this. |
| Wireserver / IMDS firewall test | Azure host endpoints; no upstream equivalent. |
| Cilium identity-GC verification after namespace delete | No upstream connectivity test for this today. Could be contributed; out of current scope. |
| Hubble metrics endpoint test | No upstream test scrapes the six Hubble series ACN asserts on. Could be contributed; out of current scope. |
| Image build from `master` + ACR push | Pipeline plumbing — gives ACN bleeding-edge validation. |
| `cilium-log-collector` sidecar | Diagnostic tooling, not a test. |

### 6.6 Cleanup checklist for `azure-container-networking`

Each row is unblocked once the corresponding migration step lands and
has run cleanly for one release cycle.

| Once this lands | Files / pipeline blocks ready to delete or shrink |
|---|---|
| §6.1 — skip-list cleanup + `--log-check-levels error` on main invocation | The separate `cilium connectivity test --test check-log-errors` step in `.pipelines/cni/cilium/nightly-release-test.yml`; the `kubectl logs cilium-operator \| grep level=error` block in `.pipelines/templates/log-check-template.yaml` |
| §6.2 — K8s ginkgo dropped | `.pipelines/cni/k8s-e2e/k8s-e2e-job-template.yaml` and the four ginkgo job invocations that reference it |
| §6.3.1 — `local-redirect-policy-with-node-dns` adopted **and** lifecycle sub-scenarios merged upstream | `test/integration/lrp/lrp_test.go` and the LRP step in the nightly pipeline |
| §6.3.2 — `pod-to-pod-no-frag` enabled, no script-only regressions for ~60 days | `hack/scripts/cilium-mtu-validation.sh` and the MTU step in the nightly pipeline |
| §6.4 — seq/concurrent split + external-target plumbing landed | Bespoke connectivity-test block shrinks to the upstream two-invocation pattern; `--force-deploy` removed |

### 6.7 Out of scope, noted for future

The largest possible win — adding an ACN-shape variant to upstream
`conformance-aks.yaml` so upstream catches Cilium regressions in the
Azure delivery shape directly — would let ACN drop its
connectivity-test invocation entirely. Feasibility hinges on whether
Azure CNS can be installed from a public GitHub Actions runner. Not
part of this roadmap.

# FQDN zombie growth — flag vs no-flag, measured

Issue: cilium/cilium#48359 · PR: cilium/cilium#48424 (`--tofqdns-ttl-bound-zones`)

## 1. Production evidence

From the customer FQDN cache dump (`cilium-dbg fqdn cache list -o json`) and the
agent log in the sysdump.

| | |
|---|---|
| total cache entries | **162,515** |
| **`connection`-sourced (zombies)** | **162,120 — 99.8%** |
| `lookup`-sourced (live) | 395 — 0.2% |
| distinct IPs | 2,367 |
| **names on a single IP** (`10.224.3.152`) | **160,050 — 98.5% of the cache** |
| zone of all 160,050 | **`applied-caas16.internal.api.openai.org`** |

Name shape: `10-<ip-dashed>-<uuid32>-<port>.app.applied-caas16.internal.api.openai.org`
— generated per connection, so cardinality is unbounded by construction. Workloads
named in the CNP are Kafka-behind-proxy, CDC streams, Rockset and nanobase gateways:
long-lived connections plus generated names, which is exactly the shape that pins a
zombie forever.

Agent log, 18-minute window: **66,166 warnings, 0 errors.** 66,161 of them are
`Name lock acquisition time took longer than expected`:

| p50 | p90 | p99 | max | >10 s | >60 s |
|---|---|---|---|---|---|
| **39.1 s** | 73.3 s | 84.1 s | **90.6 s** | 90.1% | 25.7% |

Warnings cluster on exactly the 1-minute GC cycle (two minutes of stalls, one clear,
repeating) — the signature of GC holding the global cache lock for the whole pass.

**Mechanism:** `DNSCache.Update` (`cache.go:212`) and `DNSCache.GC` (`cache.go:347`)
contend on one mutex. A DNS response takes its name-shard lock *first*
(`message_handler.go:317`) and then blocks on the cache lock, so it holds the shard
while stalled — which is why one endpoint's GC degrades the whole agent.

## 2. Test setup

AKS BYO CNI, westus2, k8s 1.34, overlay, no kube-proxy, 2 × Standard_D4_v3.
Cilium built from the PR branch; agent verified in-cluster as `81cd3a9a0f`.
30 client pods × 4 threads generating unique names in one zone, all answered by a
single IP via a CoreDNS `template` block, one live keepalive per pod pinning that IP.
Both arms always started from an **empty cache**; agent logs streamed to disk so
rotation cannot lose counts.

## 3. Results — TTL 60 s (matches production's observed 40–60 s), 30 min

| | flag OFF | flag ON |
|---|---|---|
| cache @30 min | **56,044 / 66,582**, still climbing | **10,153 / 11,497**, flat |
| lock-wait samples | 71,919 | 29,731 |
| p50 | 6.54 s | **0.72 s** |
| p90 | 43.55 s | **1.30 s** |
| p99 | **112.82 s** | **2.32 s** |
| max | **211.16 s** | **5.39 s** |
| waits > 5 s | 40,000 (55.6%) | **3 (0.0%)** |
| waits > 10 s | 29,143 (40.5%) | **0** |
| waits > 30 s | 11,426 (15.9%) | **0** |
| DNS throughput | **24.9/s** | **346.7/s** |
| latency per lookup | **4.8 s** | **0.35 s** |
| DNS failures | — | 35 / 956,472 = **0.00%** |

Throughput follows directly from lock contention (Little's Law, 120 threads):
120 ÷ 4.8 s = 25/s and 120 ÷ 0.35 s = 343/s — both match measurement.

**Steady-state cache with the flag on = rate × TTL:** 346.7/s × 60 s = 20,802
predicted vs 21,650 observed (within 4%).

## 4. Results — TTL 3600 s (`tofqdns-min-ttl` as set in their ConfigMap), 15 min

| | flag OFF | flag ON |
|---|---|---|
| cache @15 min | 47,209 / 42,781 | 44,885 / 49,159 |
| **`connection`-sourced** | **0** | **0** |
| p50 | 2.02 s | 1.66 s |
| p99 | 25.06 s | 12.85 s |
| max | 44.84 s | 30.04 s |
| waits > 10 s | 9.6% | 2.4% |

**No effect attributable to the flag.** At a 3600 s TTL nothing expires inside the
window, so no zombies form, and the flag's guard (`m.ttlExpired && isTTLBound(...)`)
never fires. The apparent improvement is within run-to-run noise: the spread
*between the two agents inside the flag-off arm alone* was 9,652 vs 16,984 warnings,
larger than the difference between arms.

Note this is a first-hour snapshot, not a steady state — we ran 15 minutes against a
60-minute TTL, so expiry could not be observed by construction.

## 5. Recovery: flag applied to an already-degraded cluster

Enabled at ~60–70k retained zombies, load unchanged, 15 minutes:

- Cache **flat** (70,020 / 59,568) — growth stops completely
- Existing zombies **persist**, including across an agent restart (70,432 / 60,479
  restored from endpoint JSON)
- GC stays slow, because it still walks the same entries

**Prevention, not cure** — matching the PR's own wording. An operator already at
160k gets no immediate relief; recovery requires the connections to close or the
client endpoints to be recreated.

## 6. Observability gap (separate from the flag)

**Zero `level=error` in production and in all eight test runs.** A cluster with p50
39-second DNS resolution is completely silent to error-based alerting. Both symptom
sites are unconditional `logger.Warn` (`message_handler.go:321`, `:367`), and a
101 ms wait logs identically to a 400 s one. `stat.QnameLockTime` is already measured
at `message_handler.go:316` but never exported as a metric.

## 7. Verdict

**The flag is well-targeted for this customer.** Their cache is 99.8% zombies —
precisely and only what the flag prevents — and **a single zone entry covers 160,050
of 162,515 entries (98.5%)**. That zone is already named in their own CNP, so it
requires no new discovery on their part.

At the TTL their cache actually exhibits (40–60 s), the flag **eliminates the failure
mode**: p99 112.82 s → 2.32 s, and 29,143 waits over 10 seconds become zero.

Caveats to carry into review:

1. **Measured against a pre-perf-fix baseline.** cilium/cilium#48360 plus the
   snapshot-index change take one GC pass from 63.9 s to 0.58 s and help regardless
   of whether entries are live or zombie. Re-baselining on top of them is owed to
   @odinuge and will likely shrink the flag's marginal benefit.
2. **Prevention only** — no relief for a cluster already degraded.
3. **Unreconciled:** the ConfigMap says `tofqdns-min-ttl: "3600"` but live cache
   entries show TTLs of 40–60 s. Worth understanding, since if min-ttl were in
   effect the zombie list would fill ~60× more slowly. It does not change what the
   data shows actually happened.

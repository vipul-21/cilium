# FQDN zombie-growth: benchmark archive

Everything needed to reproduce and re-run the measurements behind
[cilium/cilium#48359](https://github.com/cilium/cilium/issues/48359) and the two
candidate fixes:

| PR | branch | what it does |
|---|---|---|
| [#48424](https://github.com/cilium/cilium/pull/48424) | `singhvipul/fqdn-disable-deferred-deletes-zones` | `--tofqdns-ttl-bound-zones`: named zones expire on TTL instead of becoming zombies |
| [#48360](https://github.com/cilium/cilium/pull/48360) | `singhvipul/fqdn-zombie-names-set` | holds `DNSZombieMapping.Names` as a set, making de-dup O(N) instead of O(N²) |

Referred to below as **flag** and **set**. **base** is the same image as flag with
the zone list empty, so flag-vs-base isolates one config key.

## Layout

```
RUNBOOK.md               how to run it; cluster prereqs, parameters, gotchas
fqdn-benchmark-spec.md   methodology, validity checks, pass criteria
harness/                 fqdn-bench.sh (distributed), fqdn-bench-mixed.sh (production shape),
                         client-fixed.py (load generator), observer.py (bystander probe)
workloads/               client/target/observer Deployments, CNP, CoreDNS template
results/<arm>/           samples.tsv, observers.tsv, clients.txt, waits.txt, run.log
repro136/                minimal kind-based reproduction
notes/                   issue write-ups and the internal flag report
```

Sysdumps are deliberately **not** archived here.

## The bug in one paragraph

When many unique FQDNs resolve to the same IP and a live connection pins that IP,
every name is retained as a zombie forever. Zombies are held **per endpoint**
(`ep.DNSZombies`). The FQDN GC job walks them every 60 s
(`DNSGCJobInterval`, `pkg/fqdn/namemanager/gc.go:22`), and the expensive part —
`ReplaceFromCacheByNames` — holds the global DNS cache lock
(`pkg/fqdn/cache.go:449`) over a name set sized by the zombie count
(`gc.go:93,102` → `gc.go:137`). Every DNS response needs the same lock
(`cache.go:212`), so DNS stalls agent-wide.

## Results

Three shapes were run. All offered the identical input: 200,000 unique FQDNs over
600 s, all resolving to one IP pinned by a live connection, TTL 60 s, 11 minutes,
cache empty at the start of every arm. 2 × Standard_D4_v3, AKS BYO CNI.

### 1. Distributed shape — 30 client pods (`base-60`, `flag-60`, `set-60`)

~3,500 names per endpoint. This is **not** the production shape.

| | base | set | flag |
|---|---|---|---|
| GC pass (final) | 10.17 / 9.22 s | 9.62 / 8.40 s | **0.25 / 0.11 s** |
| zombies | 43,788 / 38,378 | 45,952 / 40,528 | **0** |
| lookups completed | 86,217 (43%) | 87,387 (44%) | **199,978 (100%)** |
| backlog | 111,158 | 109,297 | **0** |
| lock p99 | 38.50 s | 47.13 s | **10.73 s** |
| waits > 10 s | 25.3% | 24.0% | **1.3%** |

**The set fix is worth only 5–9% here.** Names are spread thin, so the O(N²) term
is small.

### 2. Mixed shape — 1 heavy endpoint + 5 bystanders, 48 workers

The production shape: one endpoint accumulates, others do ordinary DNS on the
same node.

| | base | set | flag |
|---|---|---|---|
| GC pass | 19.8–23.4 s | 1.03–6.04 s | **0.20 s** |
| zombies | 40,313 | 35,139 | **0** |
| heavy completed | 42,192 | 37,589 | **89,660** |
| bystander p99 | 5.09 s | 6.47 s | **1.53 s** |

### 3. Mixed shape at 200 workers — the definitive run

GC compared at **matched zombie counts**, not matched wall-clock, because the
arms serve lookups at different rates:

| zombies | base | set | flag |
|---|---|---|---|
| ~11k / 9k | 13.78 s | **0.97 s** | 0.38 s (0 zombies) |
| ~17k | 18.59 s | **2.13 s** | 0.23 s |
| ~23k / 22k | 32.53 s | **2.92 s** | 0.21 s |
| ~32k / 27k | 28.43 s | **4.24 s** | 0.20 s |
| ~37k / 32k | 26.16 s | **5.49 s** | 0.21 s |
| ~45k / 39k | 28.39 s | **7.24 s** | 0.19 s |

| | base | set | flag |
|---|---|---|---|
| heavy completed | 47,870 | 40,511 | **107,067** |
| backlog | 151,872 | 159,248 | **92,732** |
| agent lock p99 | 19.19 s | 20.40 s | **6.49 s** |
| waits > 10 s | 6.7% | 9.7% | **0.1%** |
| bystander p99 (5 pods) | 19.7–24.6 s | 21.9–29.1 s | **7.6–7.8 s** |
| bystander max | 29.98–30.03 s | 24.86–30.03 s | **11.6–13.5 s** |
| **bystander timeouts** | **4 of 5 pods** | **4 of 5 pods** | **0** |
| bystander lookups | ~204 | ~162 | **~448** |
| agent CPU | 1.54–1.68 cores | **1.15–1.20** | 1.24–1.28 |

An endpoint resolving **ten static names** had DNS queries time out entirely
(30 s ceiling) because a *different* endpoint on the same node was accumulating
zombies. Only the flag prevents that.

## Conclusions

**The flag fixes the user-visible problem.** Zombies never form, so the GC pass
stays flat at ~0.2 s regardless of load, bystanders stop timing out, and 2.2×
more lookups complete.

**The set fix is a GC-cost fix, not a latency fix.** It makes the GC pass 3.9–11×
cheaper and returns ~0.4 cores of agent CPU, but leaves DNS latency unchanged
because it does not reduce the zombie *count* that sizes the lock-held section.
The two are complementary: the flag removes the zombies, the set fix makes
whatever zombies remain cheap to process.

**Concentration is the variable that decides whether the set fix matters.**
Zombies are per-endpoint, so cost is driven by names-per-*endpoint*, not
names-per-cluster: 5–9% when spread over 30 endpoints, 3.9–11× when concentrated
on one. Production's endpoint 2410 held 160,050 names on a single IP.

## Method notes worth keeping

- **Compare at matched zombie counts.** A faster arm completes more lookups,
  which creates more zombies, so same-minute comparison flatters the slower arm.
- **Micro-benchmarks mislead here.** An off-cluster benchmark putting all N names
  on one zombie showed 2,580× (26 m 39 s → 0.62 s at 160k names). In-cluster the
  same change was worth 5–9% in the distributed shape. The synthetic shape did
  not exist on the cluster.
- **`observers.tsv` records one arbitrary bystander pod**, because the harness
  takes `logs -l role=observer | tail -1`. Use `observers-final.txt` for all five.
- **`max = 30.03 s` means a hard timeout**, not just a slow lookup — that is the
  resolver ceiling (`dnsConfig timeout:30, attempts:1`).
- Agent CPU stayed at 1.2–1.7 of 4 cores in every arm, so no run was
  rig-saturated.
- All arms are single runs. Differences of a few percent (e.g. set's lower heavy
  throughput) are not separable from run-to-run variance without repeats.

## Corrections made during this work

Recorded because each was believed and reported before being disproved:

1. *"`DNSCache.GC` never holds the cache lock, so the O(N²) is off the critical
   path."* Wrong. `GC` does release `c.mu` before its `Upsert` loop
   (`cache.go:344`), but the GC **job** re-takes it later in
   `ReplaceFromCacheByNames` (`cache.go:449`) over a set containing every zombie
   name. The runbook's premise was right.
2. *"GC is ~2,110× faster with the set fix."* That was the single-zombie
   micro-benchmark. In-cluster it is 3.9–11× at production concentration and
   5–9% when names are spread.
3. *"Bystander `max` improves with the set fix (20.49 s vs 30.03 s)."* An
   artifact of reading one pod from `observers.tsv`. Across all five pods, 4 of 5
   still hit the 30 s ceiling in both arms.
4. *"`cache_test.go:613` is order-sensitive, so `Names` cannot become a map."*
   Wrong — it sorts first (`:608`). Ordering was never the blocker; the on-disk
   JSON format was.
5. A `pkg/endpoint` race attributed to the set fix was measured at **1 in 5 on
   an unmodified baseline** — pre-existing flake in `TestComputeCIDRLabels`.

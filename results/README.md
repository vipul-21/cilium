# Benchmark results — cilium/cilium#48424 (`--tofqdns-ttl-bound-zones`)

Method: `../RUNBOOK.md`. Regenerate this table with `./summarise.py .`

Both arms offered **identical** input: 199,980 of 200,000 unique FQDNs at
333 lookups/s (666 DNS queries/s — musl sends A+AAAA), all resolving to one IP
pinned by a live connection. TTL 60 s. 11 min. Cache empty at start of each arm.
2 x Standard_D4_v3, AKS BYO CNI, k8s 1.34. Agent built from the PR branch.

## Headline

| metric | baseline | flag | |
|---|---|---|---|
| **GC pass duration** | **10.17 / 9.22 s** | **0.25 / 0.11 s** | **~40-80x faster** |
| cache (final) | 46,557 / 41,154 growing | **7,990 / 6,359 flat** | |
| **zombies** | **43,788 / 38,378** | **0 / 0** | eliminated |
| lookups completed | 86,217 (43%) | **199,978 (100%)** | |
| **backlog (unserved)** | **111,158 (56%)** | **0** | eliminated |
| failed | 1,885 | **2** | |

## DNS lock wait distribution

| | baseline | flag |
|---|---|---|
| p50 | 4.77 s | **1.94 s** |
| p90 | 17.92 s | **5.47 s** |
| p99 | 38.50 s | **10.73 s** |
| max | 67.18 s | **21.87 s** |
| > 5 s | 48.6% | **12.3%** |
| > 10 s | 25.3% | **1.3%** |
| **> 30 s** | **1,320** | **0** |

## GC pass duration vs zombie count (baseline)

The root cause, measured directly:

| min | cache | zombies | GC pass |
|---|---|---|---|
| 1 | 10,154 | 0 | 0.006 s |
| 2 | 18,866 | 5,375 | 0.86 s |
| 3 | 24,131 | 15,376 | 3.10 s |
| 5 | 30,825 | 26,651 | 5.30 s |
| 7 | 37,292 | 33,827 | 7.46 s |
| 9 | 42,198 | 39,967 | 9.13 s |
| 11 | 46,557 | 43,788 | **10.17 s** |

With the flag, zombies stay at 0 and the pass stays at **0.21-0.28 s** for the
whole run.

GC runs every 60 s (`DNSGCJobInterval`, `pkg/fqdn/namemanager/gc.go:22`) and
holds the global DNS cache lock for the entire pass
(`pkg/fqdn/cache.go:347`), which every DNS response needs
(`pkg/fqdn/cache.go:212`). At 10 s per pass the agent is holding that lock ~17%
of wall-clock time; production reached ~90 s passes against a 60 s interval,
i.e. permanently locked.

## Onset — where DNS starts breaking (baseline)

| cache | effect |
|---|---|
| ~10,000 | first warnings; p99 already past the 5 s resolver timeout |
| ~19,000 | GC pass ~0.9 s; 18% of waits over 5 s |
| ~31,000 | GC pass ~5 s; **p50 crosses 5 s — half of lookups fail** |
| ~47,000 | GC pass ~10 s; 49% over 5 s, max 67 s |

Scaling law measured across the run: **p50 wait ~ zombies^2.00 (R2=0.92)** —
empirical confirmation of the O(N^2) behaviour.

## Note on raw warning counts

The flag arm logged **more** lock warnings (109,738 vs 45,857) while being
dramatically healthier. It served 2.3x more lookups (199,978 vs 86,217), so each
completed lookup is an opportunity to contend. Normalised: 0.53 warnings per
completed lookup with the flag vs 0.53 without — identical — while every
percentile is 2-4x better and waits over 30 s go to zero.

**Count warnings per unit of work, or not at all.** The distribution is the
signal.

## Files

| | |
|---|---|
| `base-60/`, `flag-60/` | one directory per arm |
| `samples.tsv` | minute, agent, cache, lookup, conn, lockwarns, cpu, gcsec, gcdels |
| `clients.txt` | offered / done / failed / backlog |
| `waits.txt` | every lock-wait duration observed |
| `run.log` | harness log + final report |
| `SUMMARY.txt` | generated comparison |
| `summarise.py` | regenerates SUMMARY.txt from the arm directories |

## Still outstanding

- **Re-baseline on top of cilium/cilium#48360 + the snapshot index** — odinuge's
  request. These numbers are against an unfixed baseline, so they show the
  flag's benefit *before* the O(N) work, not on top of it.
- `base-3600` / `flag-3600` arms: at `tofqdns-min-ttl=3600` nothing expires
  inside the window, no zombies form, and the flag has nothing to act on.
- Idle-connection drop risk: a name resolved once, never re-resolved, whose
  connection outlives the TTL. Untested here — the generator re-resolves
  constantly.

---

# Concentration matters: zombies are PER-ENDPOINT

`DNSZombies` hangs off each `Endpoint` (`pkg/fqdn/namemanager/gc.go:70`), and the
quadratic `ciliumslices.Unique` runs per zombie, i.e. per **(endpoint, IP)** pair
(`pkg/fqdn/cache.go:1007`). So the same total number of names costs far more when
concentrated on one endpoint.

## Production is maximally concentrated

| | |
|---|---|
| distinct endpoints in the dump | 10 |
| **endpoint 2410** | **160,143 names (98.5%)** |
| ...of which on one IP | **160,050** |
| next largest endpoint | 1,120 names |

## Measured effect, same total load

| shape | zombies | **GC pass** |
|---|---|---|
| 30 endpoints (`base-60`) | 15,376 | **3.10 s** |
| **1 endpoint (`conc-1pod`)** | 16,889 | **19.49 s** |

**6.3x slower when concentrated**, at an equivalent zombie count.
Expected from the maths: 30 x 6,666^2 = 1.3e9 vs 200,000^2 = 4.0e10.

Client outcome for the single endpoint: 200,000 offered, **36,409 done (18%)**,
**163,543 backlog (82%)** — versus 43% done / 56% backlog spread across 30.

## Consequence for benchmarking

`base-60` and `flag-60` **understate** the production failure, because they
distribute names across 30 endpoints. They are still a valid A/B — both arms use
the same shape — but the absolute GC durations are conservative.

Note also that `conc-1pod` logged *fewer* lock warnings (3,365 vs 45,857):
only one pod was issuing DNS, so there were few concurrent requesters to
observe the stall, even though GC was 6x slower.

**The true production shape is both at once**: one endpoint holding a huge
zombie list (slow GC) *plus* many other endpoints on the node doing normal DNS
(who then observe the stall). A future arm should run 1 heavy generator +
N light observers on the same node, and measure the observers' latency.

---

# Mixed shape: 1 heavy generator + 5 observers on the same node

The production shape. One endpoint accumulates the zombie list; **other endpoints
on the same node pay for it**, because GC holds the global DNS cache lock that
every DNS response needs.

Directly tests the concern raised in review: *"if a single pod on a node doing a
long-running request to a fqdn used in this flag ... but if unrelated endpoint on
a node does similar lookups concurrently this will not be the case."*

Setup: 1 heavy pod offering 200,000 unique FQDNs at 333/s, plus 5 observer pods
**pinned to the same node**, each resolving only **10 fixed names** at 2/s. The
observers contribute ~nothing to the zombie list; their latency is pure
collateral damage.

Run with `./fqdn-bench-mixed.sh <label> <min-ttl> <zones> [minutes]`.

## Heavy endpoint

| | baseline | flag |
|---|---|---|
| **GC pass** | **19.8 / 23.4 / 20.1 s** | **0.20 / 0.21 / 0.20 s** | 
| zombies | 21,087 -> 33,000+ | **0** |
| lookups done | 42,192 (21%) | **89,660 (45%)** |
| backlog | 157,760 (79%) | 110,292 (55%) |

## OBSERVERS — the collateral damage (median of 5 pods)

| | baseline | flag | |
|---|---|---|---|
| p50 | 0.399 s | 0.342 s | |
| p90 | 1.940 s | **0.909 s** | 2.1x |
| **p99** | **5.297 s** | **1.716 s** | **3.1x** |
| **max** | **12.72 s** | **2.94 s** | **4.3x** |

Observer p99 climbs in lockstep with the heavy endpoint's GC pass:

| t | heavy GC | observer p99 | observer max |
|---|---|---|---|
| 1m | 0.01 s | 1.55 s | 1.98 s |
| 2m | 8.75 s | 1.48 s | 1.97 s |
| 3m | 20.05 s | 2.10 s | 2.66 s |
| 4m | 20.66 s | 2.67 s | 5.01 s |
| final | ~20 s | **6.17 s** | **12.72 s** |

**An endpoint resolving ten static names crossed the 5 s resolver timeout**
purely because a different endpoint on the same node was accumulating zombies.
With the flag its worst case stayed at 2.9 s.

## Agent-wide lock waits

| | baseline | flag |
|---|---|---|
| p50 / p90 / p99 | 0.97 / 2.34 / 6.48 s | **0.66 / 1.08 / 1.70 s** |
| max | 12.70 s | **2.46 s** |
| > 5 s | 2.0% | **0.0%** |

Absolute counts are far lower than the 30-pod arms (4,440 vs 45,857) because
only six pods are issuing DNS here - fewer requesters to observe the stall. That
is exactly why the observer latency, not the warning count, is the metric that
matters for this shape.

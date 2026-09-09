# FQDN zombie-growth benchmark — test specification

Purpose: a repeatable A/B that measures whether a given change fixes the
`DNSCache` lock-contention failure in cilium/cilium#48359, and by how much.

Designed so the same procedure can benchmark **any** of the candidate fixes:
`--tofqdns-ttl-bound-zones` (#48424), the O(N) `Upsert` dedup (#48360), the
snapshot index, or any combination.

---

## 1. What the test reproduces

The failure needs **three** conditions simultaneously. All three are required;
drop any one and the bug does not appear:

1. **Unbounded name cardinality** — every lookup is a name never seen before.
2. **All names resolve to one IP** — so one zombie accumulates all of them.
3. **A live connection pinning that IP** — so the zombie is never reaped.

Production shape being modelled (from the customer cache dump):

```
10-<ip-dashed>-<uuid32>-<port>.app.applied-caas16.internal.api.openai.org
                                162,515 entries, 99.8% connection-sourced
                                160,050 of them on ONE address (98.5%)
```

## 2. Fixed parameters

| parameter | value | why |
|---|---|---|
| nodes | 2 × Standard_D4_v3 | matches prior runs; keep constant across arms |
| client pods | 30 | enough to saturate; matches prior runs |
| threads per pod | 4 | 120 concurrent resolvers total |
| name generator | `10-<a>-<b>-<c>-<uuid4hex>-<port>.<zone>` | 3 dynamic labels, mirrors production |
| target | single pod IP, all names → it | the shared-IP condition |
| keepalive | 1 long-lived HTTP connection per pod | the pinning condition |
| CoreDNS | `template` plugin answering the whole zone | one IP for every name |
| run length | **20 min per arm** | divergence is unambiguous by 9 min |
| starting cache | **empty (verified `== 1`)** | non-negotiable, see §5 |

## 3. Variables

| variable | values | note |
|---|---|---|
| `tofqdns-min-ttl` | **0** (DNS TTL 60 s) and **3600** | 0 = the regime the customer's cache exhibits; 3600 = what their ConfigMap says |
| change under test | off / on | flag, perf fix, or both |

Full matrix = 4 runs. The **60 s arm is the primary result**; the 3600 s arm is
the control that shows whether the fix depends on names expiring.

## 4. Metrics

Primary — **name-lock wait distribution**, parsed from the `duration=` field of
`Name lock acquisition time took longer than expected`:

- p50 / p90 / p99 / max
- **count and % over 5 s, 10 s, 30 s** ← the client-visible thresholds
  (glibc's resolver gives up at 5 s)

Secondary:

| metric | source | why it matters |
|---|---|---|
| cache size | `cilium-dbg fqdn cache list \| wc -l` | the driver of GC cost |
| **cache composition** | count of ` lookup ` vs ` connection ` | decisive: `connection` = zombies. A fix that leaves zombies at 0 but the cache full has not fixed the customer's problem |
| DNS throughput | client `rate=` lines, summed | customer-visible |
| DNS loss | client `sent=`/`lost=`, **last line per pod** | customer-visible |
| warning counts by type | agent log | `Name lock` = bug signal; `datapath updates` = per-name cost, not bug signal |
| agent CPU | `kubectl top pod` | detects saturation invalidating the run |

## 5. Procedure (order matters)

```
1. Scale clients to 0, wait 25 s          ← so no DNS state survives
2. Apply config (min-ttl, change-under-test)
3. Delete cilium pods, wait 110 s
4. ASSERT cache == 1 on every agent       ← abort if not: zombies were restored
5. Start log streaming to disk            ← BEFORE clients, see §6
6. Scale clients to 30, await rollout
7. Sample every 60 s for 20 min
8. Stop log streams
9. Read client counters BEFORE scaling down
```

## 6. Methodology rules (each fixes a specific error made in ad-hoc runs)

| rule | the failure it prevents |
|---|---|
| Stream agent logs to a file, never `kubectl logs` after the fact | `kubectl logs` rotates; counts silently shrink (observed 34,833 → 1,343) |
| Stop the stream at the end of the arm | a stream left running captured later tests and inflated one arm 2.6× |
| Both arms start from an empty cache | comparing a from-empty arm against an already-degraded one inverted the verdict once |
| Equal run length in both arms | 30 min vs 15 min is not comparable |
| Read client `sent`/`lost` before scaling down | those counters are lost with the pods |
| Take the **last** report line per pod, do not sum a time window | summing a window multi-counts (73 "pods" from 30 pods) |
| Record per-agent numbers separately | between-agent spread inside one arm reached 1.8×; a smaller cross-arm delta is noise |
| No extra workloads sharing `app=client` | a debug probe polluted the label set once |
| Check agent CPU | at 240 threads the agent saturated and the result measured the rig, not the bug |

## 7. Validity cross-checks

A run is only trusted if these hold:

1. **Little's Law**: `threads ÷ mean-latency ≈ throughput`.
   Verified previously: 120 ÷ 4.8 s = 25/s vs 24.9/s measured; 120 ÷ 0.35 s =
   343/s vs 346.7/s measured.
2. **Steady state**: with growth prevented, `cache ≈ rate × TTL`.
   Verified: 346.7/s × 60 s = 20,802 predicted vs 21,650 observed (+4%).
3. **Composition**: at min-ttl=3600 within the first hour, `connection` must be
   0 in both arms — nothing has expired yet, so no fix can act.

If a check fails, the run is suspect and should be repeated rather than reported.

## 8. Pass criteria for a candidate fix

At **min-ttl=0 / TTL 60 s**, versus its own baseline:

| | threshold |
|---|---|
| waits > 10 s | must reach **0** |
| p99 | must fall below **5 s** |
| cache | must stop growing (flat, not merely slower) |
| `connection`-sourced entries | should be 0 (flag) or unchanged (perf fixes) |
| DNS loss | must be < 1% |
| throughput | must not regress |

A perf fix is expected to pass on wait times while leaving cache size and
composition **unchanged** — that difference is exactly what distinguishes
"GC is faster" from "there is less to GC".

## 9. Known limitations

- 2 nodes only; pod placement is uneven (observed 11/19 and 2/4 splits), so
  per-agent numbers differ substantially. Report both, never average them.
- The rig contributes a sub-second warning floor from shard contention
  (`--dnsproxy-lock-count` 131 vs 120 threads). It is present in every arm and
  is not part of the bug signal.
- The system self-throttles: as the agent degrades, DNS slows, so names arrive
  more slowly. Growth **rate** therefore understates severity over time; use
  cache size and the wait distribution instead.
- 20 min at 60 s TTL cannot reach production's 160k. It does not need to — the
  symptom is a function of GC pass duration, and production-equivalent waits
  appeared at ~60k on this hardware.

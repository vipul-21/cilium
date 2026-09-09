# DRAFT — NOT POSTED
# Comment for https://github.com/cilium/cilium/issues/48359
# Topic: the candidate approaches, with what is measured vs. what is mechanism-only

---

I have been working through this and wanted to lay out the approaches I see,
with what I have actually measured for each, before opening PRs so the direction
can be discussed first.

Throughout: numbers labelled **measured** come from a run I can reproduce;
anything I have only reasoned about is labelled as such.

## What the data says the bottleneck is

From the sysdump attached to this issue:

- one IP holds **160,050 of 162,515** FQDN cache entries (98.5%)
- **162,120 of 162,515** entries are zombie-sourced (`source: connection`), so
  the cache is almost entirely deferred deletes rather than live lookups
- in the ~17.9 minutes of agent log retained, there are **66,161 warnings and 0
  errors**, and all 66,161 warnings are `Name lock acquisition time took longer
  than expected`. Only **5** are `Timed out waiting for datapath updates`.
- name-lock acquisition over that window: **p50 30.4 s, p90 52.8 s, p99 59.3 s,
  max 60 s**, against a 500 ms threshold
- FQDN GC completions are 86–94 s apart. The job is a strict `time.NewTicker` at
  60 s with `doGC` run inline, so a pass *shorter* than the interval would give
  exactly 60 s spacing. The pass itself is therefore ~90 s, and GC is running
  back to back with no idle gap.

The goroutine dump names the function directly. One goroutine is `[runnable]` —
actively burning CPU, not blocked:

```
goroutine 4342 [runnable]:
pkg/fqdn.(*DNSCache).partialRestoreFromCache(...)   cache.go:417
pkg/fqdn.(*DNSCache).ReplaceFromCacheByNames(...)   cache.go:457
pkg/fqdn/namemanager.(*manager).doGC(...)           gc.go:137
```

with a slice argument of `0x27186` = **160,646 names**, and **2,888** goroutines
blocked in `LockName` plus **160** in `UpdateGenerateDNS` queued behind it.

So the failure is: GC holds the global `DNSCache` write lock inside a quadratic
loop, and every DNS response needs that lock to record its result.

One clarification on the cost model, because it tripped me up: production does
not pay the full O(N²) build on each pass. It pays the *marginal* cost —
roughly `(names expiring this pass) × O(names retained)`. At ~5,000 expiring
against 160k retained that is still ~90 s, but it is not the same quantity as
constructing the 160k state from scratch, and conflating the two makes the field
numbers look inconsistent.

## Approach 1 — remove the quadratic complexity

Two independent O(N²) loops run under the global lock, where N is the number of
names on a single IP:

- `DNSZombieMappings.Upsert` re-runs `slices.Unique` over the whole `Names`
  slice on every call, and `DNSCache.GC` calls it once per expired entry.
- `partialRestoreFromCache` tests membership with
  `slices.Contains(oldEntries[ip], name)`, where `oldEntries[ip]` holds every
  name recorded for that IP, once per restored name.

Fix: keep a membership set alongside `DNSZombieMapping.Names` so de-duplication
is O(1), and index the pre-expiry snapshot so the restore does a map lookup
instead of a linear scan.

**Measured**, at the production working point (one IP, 160k names):

| | before | after |
|---|---|---|
| 1,000 `Upsert`s onto a 160k zombie | 13.49 s, 6.99 GB, 514,168 allocs | 0.206 ms, 0 B, 0 allocs |
| one `ReplaceFromCacheByNames` pass | 45.7 s | 502 ms |

No behavioural change: `Names` keeps the same contents and the same order; only
the way uniqueness and membership are computed changes.

**Cost, since it is not free:** mass removal gets slower, because it now pays a
map delete per removed name where it previously allocated a replacement slice.
Removing 80k names from a 160k-name zombie goes from ~30 ms to ~44 ms, for half
the allocations (7.1 MB vs 14.1 MB). That path is reached only from
`cilium-dbg fqdn cache clean`, not from periodic GC, which drops whole zombies
rather than individual names. The per-DNS-response removal path
(`ForceExpireByNameIP`) is ~35% *faster*. There is also one extra map per
zombie, bounded by `--tofqdns-max-deferred-connection-deletes`.

This is the approach with direct production evidence behind it, and the only one
that changes no behaviour. It lowers the constant; it does not stop the cache
from growing.

## Approach 2 — stop re-inserting every alive-zombie name each pass

Today, every GC pass adds *all* of an alive zombie's names to `namesToClean`,
expires them from the global cache, and immediately restores them with a fresh
TTL. For an IP holding 160k names that is 160k expiries and 160k restores per
pass, to arrive back at the state it started in.

### 2a — re-insert one name per selector (does not work as written)

The first thing I tried: since `deriveLabelsForName` derives an IP's FQDN
identity from the matching `FQDNSelector` rather than from the name, one name
per matched selector should reproduce the same label set. Prototyped, this
collapses 200,000 names to 1 representative for a single selector.

**This has a correctness problem I could not resolve, so I am not proposing it.**
`RegisterFQDNSelector` resolves a newly registered selector against the global
DNS cache (`mapSelectorsToNamesLocked` → `n.cache.Lookup`), and pruning is
one-way: `partialRestoreFromCache` only restores pairs present in the pre-expiry
snapshot, so once a name is dropped from the global cache no later pass can put
it back. A toFQDNs policy applied *after* a GC pass therefore never picks up the
alive zombie's IP — permanently, for the life of the connection, fail-closed.
With no selectors registered at GC time at all, nothing is re-inserted and the
IP leaves ipcache entirely, which is the common "GC ran before the policy was
applied" ordering.

### 2b — refresh in place instead (what I would propose)

The observation behind 2a still holds; the mistake was *dropping* names. The
narrower change is to not expire them at all:

- alive-zombie names are no longer added to `namesToClean`
- `n.cache.UpdateFromCache(activeConnections)` is hoisted above the
  `namesToClean.Len() == 0` early return, so those entries have their expiry
  refreshed in place on every pass

Nothing is ever removed from the global cache, so 2a's fail-closed window cannot
occur — the backfill in `RegisterFQDNSelector` still finds every name. Reusing
`UpdateFromCache` here follows the same pattern `RestorationNotify` already uses
to seed the cache from restored endpoints.

The win is the early return. When no *other* name expired in a pass,
`namesToClean` is now empty and the whole `ReplaceFromCacheByNames` body is
skipped — including `getIPsLocked()`, which snapshots the entire reverse cache
under the write lock regardless of how few names actually expired. Work becomes
proportional to genuinely new DNS activity rather than to accumulated zombies.

There is one subtlety that is easy to get wrong, and I did get it wrong on the
first attempt. Removing the names from `namesToClean` is not sufficient on its
own: they have already aged out of `ep.DNSHistory`, so the leaked-name sweep
(`initialNames.Difference(allEndpointNames)`) immediately reclassifies them as
orphaned and cleans them anyway. The alive-zombie names have to be recorded in
`allEndpointNames` as well, otherwise the change does nothing but move the churn
to a different code path. My first build did exactly that, and the GC log made
it obvious — it was still reporting ~70,000 entries cleaned per pass.

**Verified, unit level:** a regression test that registers a selector only
*after* a GC pass and asserts the alive zombie's IP still receives that
selector's label. It fails on 2a with exactly the expected symptom
(`[]string{"cilium.io."} does not contain "github.com."`), and passes both on
current `main` and on 2b — i.e. the test is load-bearing, and 2b restores the
behaviour 2a broke. Full `pkg/fqdn/...` is green.

**Verified, end to end**, on a kind cluster driving ~500 concurrent resolvers at
a single shared A record, same cluster and same workload for each arm:

| | baseline | 2b (first, buggy) | 2b (corrected) |
|---|---|---|---|
| entries cleaned per GC pass | not captured | 69,579–73,718 | **850–1,161** |
| GC cadence | — | irregular, 58–66 s | **exactly 60 s** |
| cache size at measurement | 54,527 | 73,726 | 87,033 |
| name-lock p50 | 948.4 s | 805.6 s | **292.9 s** |
| name-lock p99 | 1,041.5 s | 1,005.5 s | **561.2 s** |
| DNS responses processed | 2,212 | 8,404 | **14,512** |

The per-pass count is the number this change is aimed at, and it drops ~70x
while the cache it is maintaining is *larger* (87k vs 54.5k names). The cadence
matters too: at 60 s exactly, the pass is finishing inside its interval and the
job is idle between passes, where before it was overrunning.

**An important caveat on those latency numbers, because they are not a clean
read.** In this kind environment the dominant consumer of agent CPU is not the
FQDN GC path at all — a 30 s CPU profile taken during the corrected run puts
`ipcache.(*prefixInfo).flatten` at **72.8% cumulative**, with no FQDN GC
function in the top 8. So the residual ~5 minute p50 is mostly that second
bottleneck, not this one, and the 3.2x p50 improvement understates what this
change does to the path it actually targets. I would treat the per-pass count
and the cadence as the attributable results here, and the latency figures as
directional only.

## Approach 3 — let operators exclude a zone from deferred deletes

A flag, empty by default, listing DNS zones whose names expire outright instead
of becoming zombies. This attacks the input rather than the cost: if the names
never accumulate, N stays small and the quadratic never grows.

**Measured** — paired experiment, same cluster, same binary, same workload, only
the flag differing. Both arms sampled over the same ~6 minute window, at which
point the baseline had reached ~30k zombie names; it had not yet converged, and
kept degrading afterwards:

| | baseline | zone flag |
|---|---|---|
| zombie entries | 27,282 | **0** |
| name-lock p50 | 2,614 ms | **638 ms** |
| name-lock p90 | 13,627 ms | **1,035 ms** |
| name-lock p99 | **42,252 ms** | **1,491 ms** |
| name-lock max | **50,749 ms** | **2,217 ms** |

Left running, the baseline tracked the same curve as production (p50 2.6 s at
30k names, 15 s at 46k, against production's 30 s at 160k).

**Cost:** a connection in a listed zone that outlives its DNS TTL *without* the
client re-resolving loses the IP's labels and may be dropped. That is precisely
what zombies exist to prevent, so this is a real trade — the same one as
`--tofqdns-max-deferred-connection-deletes=0`, but scoped to one zone instead of
applied globally. In the capture attached here it would affect 143 IPs; 142 of
them hold fewer than 100 names each, and those are exactly the low-churn entries
where zombies earn their keep.

It also only prevents further growth. It does not shrink a zombie that has
already accumulated names.

## Approach 4 — make the FQDN GC interval configurable

`DNSGCJobInterval` is hardcoded at one minute. An operator whose GC pass has
started overrunning its interval currently has no lever at all, so exposing it
would at least restore idle gaps between passes.

It does not reduce total work — the number of names expiring per pass scales
with the interval, so a longer interval mostly redistributes the same work into
fewer, longer stalls. Shorter intervals are actively worse, because
`ReplaceFromCacheByNames` snapshots the entire reverse cache every pass
regardless of how many names expired. There is also a coupling to be careful
with: the interval derives the synthetic TTL applied to re-inserted zombie names
(`activeConnectionsTTL = 2 * DNSGCJobInterval`), so exposing one exposes the
other.

Worth having as an escape hatch, but a stopgap rather than a fix.

## How they compose

They are largely independent and address different links in the chain:

| | what it changes | growth | risk |
|---|---|---|---|
| 1 | constant factor of the existing work | unbounded | none |
| 2b | how often that work is done at all | unbounded | low |
| 3 | whether the names accumulate | bounded | real trade |
| 4 | how often the work is attempted | unbounded | none |

Approach 1 is the one I would like to put up first: it is the only one with a
production stack trace pointing at the exact function, it changes no behaviour,
and it can be measured on its own. 2b is complementary and is the one that stops
the per-pass cost scaling with the accumulated zombie set at all — measured at
~70x fewer entries touched per pass, with GC back inside its interval. 3 is a
containment lever for operators who can accept the trade in a specific zone. 4
is a knob, not a fix.

Happy to split these into separate PRs, and to share the reproduction (a script
that stands up a kind cluster, points CoreDNS at a single shared A record, and
drives DNS churn against a toFQDNs policy) if that is useful for verifying any
of it.

---

Separately, while reproducing this I ran into a second, unrelated bottleneck in
`pkg/ipcache`: the name manager creates one ipcache resource per DNS name, and
`prefixInfo.flatten()` re-sorts every resource on a prefix on each label
injection, with two map lookups per comparison. With many names on one IP this
dominates the agent: 72.8% of cumulative CPU in a 30 s profile from my kind
cluster, with `sortedBySourceThenResourceID` alone at 53%. It does **not**
appear in the capture attached to this issue — zero `flatten` frames in the
goroutine dump, and only 5 datapath-update warnings — so I believe it is a
separate problem that this workload can provoke, and I will raise it
independently rather than conflate it with this issue. It is worth flagging
here only because it means a kind reproduction is *not* a faithful end-to-end
proxy for the production bottleneck: it will mask FQDN GC improvements behind a
defect production is not hitting.

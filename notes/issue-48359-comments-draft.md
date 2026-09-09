# DRAFT — NOT POSTED
# Two comments for https://github.com/cilium/cilium/issues/48359
# 1) reply to @kartikmengane09-oss
# 2) the four candidate fixes, with measurements

================================================================================
COMMENT 1 — reply to @kartikmengane09-oss
================================================================================

Thanks for digging into this. Both of your suggestions target the right lock, so
I want to share what I found when I went looking there, because it changed my
mind about where the fix belongs.

**On (1), snapshot under the lock and reapply afterwards.** That sequence is
explicitly what `ReplaceFromCacheByNames` is written to avoid. Its doc comment
says so:

> operates as an atomic combination of ForceExpire and multiple
> partialRestoreFromCache invocations [...] We do this to ensure that this
> process does not upsert new entries to the global DNSCache that has not been
> seen yet [...] so the lookups can correctly wait for ipcache propagation of
> new IPs.

If the lock is released between the expire and the restore, a DNS response
landing in that window can observe a name expired but not yet restored, and the
IP loses its FQDN labels for that instant. That is a fail-open/fail-closed
window on the policy path, so it would need a lot more than chunking to be safe.

**On (2), finer-grained locking.** Plausible in principle, but I think it treats
the symptom. The reason the lock is held for tens of seconds is not that the
critical section is large — it is that there is quadratic work inside it. Two
independent O(N²) loops run while that lock is held, where N is the number of
names on a single IP:

- `DNSZombieMappings.Upsert` re-runs `slices.Unique` over the whole `Names`
  slice on every call, and `DNSCache.GC` calls it once per expired entry.
- `partialRestoreFromCache` tests membership with
  `slices.Contains(oldEntries[ip], name)`, where `oldEntries[ip]` holds every
  name recorded for that IP, once per restored name.

Measured with one IP carrying 160k names, which is the shape in the capture
attached to this issue:

| | before | after |
|---|---|---|
| 1,000 `Upsert`s onto a 160k zombie | 13.49 s, 6.99 GB, 514,168 allocs | 0.206 ms, 0 B, 0 allocs |
| one `ReplaceFromCacheByNames` pass | 45.7 s | 502 ms |

Once those are linear, the lock is held for milliseconds and there is very
little left for granular locking to win. I would rather not restructure a
deliberately atomic function to work around a constant factor that can be
removed directly. If stalls persist after the complexity fix, then the lock
scope is worth revisiting — with measurements to justify the risk.


================================================================================
COMMENT 2 — candidate fixes
================================================================================

I have been working through this and wanted to lay out the options I see,
with what I have measured for each. Sharing before opening PRs so the approach
can be discussed first.

## What the data says the bottleneck is

From the sysdump attached to this issue:

- one IP holds **160,050 of 162,515** FQDN cache entries (98.5%)
- **162,120 of 162,515** entries are zombie-sourced (`source: connection`), so
  the cache is almost entirely deferred deletes rather than live lookups
- the agent log for that window is **66,161 warnings, 0 errors**, and 66,161 of
  them are `Name lock acquisition time took longer than expected`. There are
  only **5** `Timed out waiting for datapath updates` in 17.9 minutes.
- name-lock acquisition **p50 30.4 s, p90 52.8 s, p99 59.3 s, max 60 s**,
  against a 500 ms threshold
- FQDN GC completions are 86–94 s apart. The job is a strict `time.NewTicker`
  at 60 s with `doGC` run inline, so a pass shorter than the interval would give
  exactly 60 s. The pass itself is therefore ~90 s and GC is running back to
  back with no idle gap.

The goroutine dump names the function directly. One goroutine is `[runnable]`,
i.e. actively burning CPU, not blocked:

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

Worth noting the practical impact is worse than "slow DNS". In my reproduction,
once the agent reached this state, **77 of 104 new client pods could not
complete a single DNS resolution** and never became functional. A workload that
cannot resolve at startup does not start at all.

## Option 1 — remove the quadratic complexity

Keep a membership set alongside `DNSZombieMapping.Names` so de-duplication on
`Upsert` is O(1) instead of O(len(Names)), and index the pre-expiry snapshot in
`ReplaceFromCacheByNames` so `partialRestoreFromCache` does a map lookup instead
of a linear scan.

Measured on the production working point (~5,000 names expiring per pass against
160k retained): a pass goes from **~90 s to under a millisecond** for the
`Upsert` half, and **45.7 s to 502 ms** for the restore half.

No behavioural change: `Names` keeps the same contents and the same order, only
the way uniqueness and membership are computed changes.

**Cost, since it is not free:** mass removal gets slower, because it now pays a
map delete per removed name where it previously allocated a replacement slice.
Removing 80k names from a 160k-name zombie goes from ~30 ms to ~44 ms, for half
the allocations (7.1 MB vs 14.1 MB). That path is reached only from
`cilium-dbg fqdn cache clean`, not from the periodic GC, which drops whole
zombies rather than individual names. The per-DNS-response removal path
(`ForceExpireByNameIP`) is ~35% *faster*. There is also one extra map per
zombie, bounded by `--tofqdns-max-deferred-connection-deletes`.

This is the option with direct production evidence behind it, and the only one
that changes no behaviour.

## Option 2 — re-insert one name per selector instead of every name

Every GC pass re-inserts *all* of an alive zombie's names into the global cache
with a fresh TTL. What actually keeps the connection allowed is the IP retaining
its FQDN identity labels, and `deriveLabelsForName` derives those from the
matching `FQDNSelector` rather than from the name — so in principle one name per
matched selector reproduces the same label set. Prototyped, this collapses
200,000 names to 1 representative for a single selector.

**I am not proposing this as written, because it has a correctness problem I
could not resolve.** `RegisterFQDNSelector` resolves a newly registered selector
against the global DNS cache (`mapSelectorsToNamesLocked` -> `n.cache.Lookup`),
and the pruning is one-way: `partialRestoreFromCache` only restores pairs
present in the pre-expiry snapshot, so once a name is dropped from the global
cache no later GC pass can put it back. A toFQDNs policy applied *after* a GC
pass therefore never picks up the alive zombie's IP, permanently, for the life
of the connection. With no selectors registered at GC time at all, nothing is
re-inserted and the IP is dropped from ipcache entirely — which is the common
"GC ran before the policy was applied" ordering.

Recording it here because the underlying observation still seems right; it needs
a different mechanism, for example having selector registration also consult
`ep.DNSZombies` rather than only the global cache.

## Option 3 — let operators exclude a zone from deferred deletes

A flag, empty by default, listing DNS zones whose names expire outright instead
of becoming zombies. This attacks the input rather than the cost: if the names
never accumulate, N stays small and the quadratic never grows.

Paired experiment on the same cluster, same binary, same workload, only the flag
differing:

| | baseline | zone flag |
|---|---|---|
| zombie entries | 27,282 | **0** |
| name-lock p50 | 2,614 ms | **638 ms** |
| name-lock p90 | 13,627 ms | **1,035 ms** |
| name-lock p99 | **42,252 ms** | **1,491 ms** |
| name-lock max | **50,749 ms** | **2,217 ms** |

Left running, the baseline kept degrading along the same curve as production
(p50 2.6 s at 30k names, 15 s at 46k, against production's 30 s at 160k), and
client-side DNS loss reached 36%.

**Cost:** a connection in a listed zone that outlives its DNS TTL *without* the
client re-resolving loses the IP's labels and may be dropped. That is the entire
point of zombies, so this is a real trade — the same one as
`--tofqdns-max-deferred-connection-deletes=0`, but scoped to one zone instead of
applied globally. In the capture attached here it would affect 143 IPs; 142 of
them hold fewer than 100 names each, and those are exactly the low-churn entries
where zombies earn their keep.

It also only prevents further growth. It does not shrink a zombie that has
already accumulated names.

## Option 4 — make the FQDN GC interval configurable

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

## Where I have landed

Option 1 is the one I would like to put up first: it is the only one with a
production stack trace pointing at the exact function, it changes no behaviour,
and it can be measured on its own. Option 3 is a useful containment lever for
operators who can accept the trade in a specific zone. Option 2 needs a
different design. Option 4 is a knob, not a fix.

Happy to split these into separate PRs, and to share the reproduction (a script
that stands up a kind cluster, points CoreDNS at a single shared A record, and
drives DNS churn against a toFQDNs policy) if that is useful for verifying any
of it.

Separately, while reproducing this I ran into a second, unrelated bottleneck in
`pkg/ipcache`: the name manager creates one ipcache resource per DNS name, and
`prefixInfo.flatten()` re-sorts every resource on a prefix on each label
injection, with two map lookups per comparison. With many names on one IP that
was 81% of agent CPU in my environment. It does *not* appear in the capture
attached to this issue — zero `flatten` frames in the goroutine dump and only 5
datapath-update warnings — so I believe it is a separate problem that this
workload can provoke, and I will raise it independently rather than conflate it
with this issue.

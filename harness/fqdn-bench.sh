#!/usr/bin/env bash
# FQDN zombie-growth benchmark harness.
# Implements fqdn-benchmark-spec.md. One invocation = one arm.
#
#   ./fqdn-bench.sh <label> <min-ttl> <ttl-bound-zones> [minutes]
#
#   ./fqdn-bench.sh base-60      0    ""                        20
#   ./fqdn-bench.sh flag-60      0    internal.api.openai.org   20
#   ./fqdn-bench.sh base-3600    3600 ""                        20
#   ./fqdn-bench.sh flag-3600    3600 internal.api.openai.org   20
set -u

CTX=${CTX:-singhvipul-fqdn-zone}
NS=oai
PODS=${PODS:-30}                     # endpoints sharing the load; zombies are PER-ENDPOINT
TOTAL_NAMES=${TOTAL_NAMES:-200000}   # unique FQDNs offered per arm - CONSTANT
DURATION=${DURATION:-600}            # seconds of offered load

LABEL=$1; MINTTL=$2; ZONES=$3; MINUTES=${4:-11}
OUT=/tmp/bench-$LABEL
rm -rf "$OUT"; mkdir -p "$OUT"

k() { kubectl --context "$CTX" "$@"; }
say() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$OUT/run.log"; }

say "=== arm '$LABEL': min-ttl=$MINTTL zones='${ZONES:-<none>}' pods=$PODS names=$TOTAL_NAMES over ${DURATION}s ==="

# --- 1. drain client DNS state -------------------------------------------
say "draining clients"
k -n $NS scale deploy client --replicas=0 >/dev/null 2>&1
sleep 25

# --- 2. apply config ------------------------------------------------------
k -n kube-system patch cm cilium-config --type merge \
  -p "{\"data\":{\"tofqdns-min-ttl\":\"$MINTTL\",\"tofqdns-ttl-bound-zones\":\"$ZONES\"}}" >/dev/null 2>&1
k -n $NS set env deploy client \
  TOTAL_NAMES=$TOTAL_NAMES FLEET=$PODS DURATION=$DURATION WORKERS=${WORKERS:-24} >/dev/null 2>&1

# --- 3. restart agents ----------------------------------------------------
say "restarting agents"
k -n kube-system delete pod -l k8s-app=cilium --wait=false >/dev/null 2>&1
sleep 110
AGENTS=$(k -n kube-system get pod -l k8s-app=cilium -o jsonpath='{.items[*].metadata.name}')
say "agents: $AGENTS"

# --- 4. ASSERT empty cache ------------------------------------------------
for A in $AGENTS; do
  C=$(k -n kube-system exec "$A" -c cilium-agent -- sh -c "cilium-dbg fqdn cache list 2>/dev/null|wc -l" 2>/dev/null)
  say "  $A cache=$C"
  if [ "${C:-0}" != "1" ]; then
    say "ABORT: cache not empty on $A (got '$C', want 1) - state survived the restart"
    exit 1
  fi
done

# --- 5. stream logs BEFORE load ------------------------------------------
for A in $AGENTS; do
  nohup kubectl --context "$CTX" -n kube-system logs -f "$A" -c cilium-agent > "$OUT/$A.log" 2>/dev/null &
  echo $! >> "$OUT/streams.pid"
done
sleep 5

# --- 6. load --------------------------------------------------------------
say "scaling to $PODS clients"
k -n $NS scale deploy client --replicas=$PODS >/dev/null 2>&1
k -n $NS rollout status deploy client --timeout=400s >/dev/null 2>&1

# --- 7. sample ------------------------------------------------------------
printf 'minute agent cache lookup conn lockwarns cpu gcsec gcdels\n' > "$OUT/samples.tsv"
for i in $(seq 1 "$MINUTES"); do
  sleep 60
  for A in $AGENTS; do
    O=$(k -n kube-system exec "$A" -c cilium-agent -- sh -c "cilium-dbg fqdn cache list 2>/dev/null" 2>/dev/null)
    TOT=$(echo "$O"|wc -l); LK=$(echo "$O"|grep -c ' lookup '); CN=$(echo "$O"|grep -c ' connection ')
    W=$(grep -c "Name lock acquisition" "$OUT/$A.log" 2>/dev/null)
    CPU=$(k -n kube-system top pod "$A" --no-headers 2>/dev/null|awk '{print $2}')
    # GC pass duration: the root-cause metric. doGC runs as a hive job.Timer.
    M=$(k -n kube-system exec "$A" -c cilium-agent -- sh -c "cilium-dbg metrics list 2>/dev/null" 2>/dev/null)
    GC=$(echo "$M" | awk '/jobs_timer_last_run_duration_seconds.*dns-garbage-collector-job/{print $NF}')
    GD=$(echo "$M" | awk '/cilium_fqdn_gc_deletions_total/{print $NF}')
    printf '%s %s %s %s %s %s %s %s %s\n' "$i" "$A" "$TOT" "$LK" "$CN" "$W" "${CPU:-?}" "${GC:-?}" "${GD:-?}" >> "$OUT/samples.tsv"
  done
  say "t+${i}m $(grep "^$i " "$OUT/samples.tsv" | awk '{printf "%s cache=%s conn=%s warns=%s gc=%ss | ", $2,$3,$5,$6,$8}')"
done

# --- 9. client counters BEFORE teardown -----------------------------------
OFF=0; DONE=0; FAIL=0; BL=0; N=0
for p in $(k -n $NS get pod -l app=client -o jsonpath='{.items[*].metadata.name}'); do
  LN=$(k -n $NS logs "$p" --tail=12 2>/dev/null | grep -oE 'offered=[0-9]+ done=[0-9]+ failed=[0-9]+ backlog=[0-9]+' | tail -1)
  [ -n "$LN" ] || continue
  o=${LN#offered=}; o=${o%% *}
  d=${LN#*done=};   d=${d%% *}
  f=${LN#*failed=}; f=${f%% *}
  b=${LN#*backlog=}; b=${b%% *}
  OFF=$((OFF+o)); DONE=$((DONE+d)); FAIL=$((FAIL+f)); BL=$((BL+b)); N=$((N+1))
done
say "clients: pods=$N offered=$OFF done=$DONE failed=$FAIL backlog=$BL failPct=$(awk "BEGIN{printf \"%.2f\", $FAIL*100/($OFF+1)}")"
printf 'pods=%s offered=%s done=%s failed=%s backlog=%s failPct=%s\n' "$N" "$OFF" "$DONE" "$FAIL" "$BL" \
  "$(awk "BEGIN{printf \"%.2f\", $FAIL*100/($OFF+1)}")" > "$OUT/clients.txt"

say "--- client-side latency (p50/p99 per pod, last report) ---"
k -n $NS logs -l app=client --tail=12 2>/dev/null | grep -oE 'p50=[0-9.]+ p99=[0-9.]+' | tail -30 \
  | python3 -c "
import sys
r=[l.split() for l in sys.stdin if l.strip()]
if r:
    p50=sorted(float(x[0].split('=')[1]) for x in r)
    p99=sorted(float(x[1].split('=')[1]) for x in r)
    print('  across %d pods: median p50=%.3fs  median p99=%.3fs  worst p99=%.3fs' % (len(r),p50[len(p50)//2],p99[len(p99)//2],p99[-1]))
" | tee -a "$OUT/run.log"

# --- 8. stop streams ------------------------------------------------------
while read -r P; do kill "$P" 2>/dev/null; done < "$OUT/streams.pid"

# --- report ---------------------------------------------------------------
say "--- wait distribution ---"
cat "$OUT"/*.log 2>/dev/null | grep -oE 'duration=[0-9hms.µ]+' | sed 's/duration=//' | python3 -c "
import sys,re
def sec(s):
    t=0.0
    for v,u in re.findall(r'([0-9.]+)(h|ms|m|s|µs|ns)', s):
        t+=float(v)*{'h':3600,'m':60,'s':1,'ms':1e-3,'µs':1e-6,'ns':1e-9}[u]
    return t
d=sorted(sec(l.strip()) for l in sys.stdin if l.strip())
if not d: print('  no lock warnings'); raise SystemExit
n=len(d); p=lambda q: d[min(int(n*q),n-1)]
o=lambda t: (sum(1 for x in d if x>t), 100*sum(1 for x in d if x>t)/n)
print('  samples=%d p50=%.2fs p90=%.2fs p99=%.2fs max=%.2fs' % (n,p(.5),p(.9),p(.99),d[-1]))
print('  >5s=%d (%.1f%%)  >10s=%d (%.1f%%)  >30s=%d (%.1f%%)' % (o(5)+o(10)+o(30)))
" | tee -a "$OUT/run.log"

say "--- warnings by type ---"
cat "$OUT"/*.log 2>/dev/null | grep 'level=warn' | grep -oE 'msg="[^"]{0,52}' | sed 's/^msg="//' \
  | sort | uniq -c | sort -rn | head -5 | tee -a "$OUT/run.log"
say "errors: $(cat "$OUT"/*.log 2>/dev/null | grep -c 'level=error')"
say "results in $OUT"

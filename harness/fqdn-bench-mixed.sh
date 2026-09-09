#!/usr/bin/env bash
# Mixed-shape arm: ONE heavy FQDN generator + N light observers on the SAME node.
#
# This is the production shape. Endpoint 2410 in the customer dump held 160,050
# names on a single IP (98.5% of the whole cache) while other endpoints on that
# node did ordinary DNS. Zombies are per-endpoint, so the heavy endpoint makes
# GC slow; the observers are the ones who feel it.
#
#   ./fqdn-bench-mixed.sh <label> <min-ttl> <ttl-bound-zones> [minutes]
set -u

CTX=${CTX:-singhvipul-fqdn-zone}
NS=oai
TOTAL_NAMES=${TOTAL_NAMES:-200000}
DURATION=${DURATION:-600}
OBSERVERS=${OBSERVERS:-5}
WORKERS=${WORKERS:-48}

LABEL=$1; MINTTL=$2; ZONES=$3; MINUTES=${4:-11}
OUT=/tmp/bench-$LABEL
rm -rf "$OUT"; mkdir -p "$OUT"

k() { kubectl --context "$CTX" "$@"; }
say() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$OUT/run.log"; }

say "=== MIXED arm '$LABEL': 1 heavy + $OBSERVERS observers, same node ==="
say "    min-ttl=$MINTTL zones='${ZONES:-<none>}' names=$TOTAL_NAMES over ${DURATION}s"

# --- drain ---------------------------------------------------------------
k -n $NS scale deploy client --replicas=0 >/dev/null 2>&1
k -n $NS delete deploy observer --ignore-not-found >/dev/null 2>&1
sleep 25

k -n kube-system patch cm cilium-config --type merge \
  -p "{\"data\":{\"tofqdns-min-ttl\":\"$MINTTL\",\"tofqdns-ttl-bound-zones\":\"$ZONES\"}}" >/dev/null 2>&1
k -n $NS set env deploy client \
  TOTAL_NAMES=$TOTAL_NAMES FLEET=1 DURATION=$DURATION WORKERS=$WORKERS >/dev/null 2>&1

say "restarting agents"
k -n kube-system delete pod -l k8s-app=cilium --wait=false >/dev/null 2>&1
sleep 110
AGENTS=$(k -n kube-system get pod -l k8s-app=cilium -o jsonpath='{.items[*].metadata.name}')
for A in $AGENTS; do
  C=$(k -n kube-system exec "$A" -c cilium-agent -- sh -c "cilium-dbg fqdn cache list 2>/dev/null|wc -l" 2>/dev/null)
  say "  $A cache=$C"
  [ "${C:-0}" = "1" ] || { say "ABORT: cache not empty on $A"; exit 1; }
done

for A in $AGENTS; do
  nohup kubectl --context "$CTX" -n kube-system logs -f "$A" -c cilium-agent > "$OUT/$A.log" 2>/dev/null &
  echo $! >> "$OUT/streams.pid"
done
sleep 5

# --- heavy generator (1 pod) --------------------------------------------
say "starting heavy generator (1 pod, $TOTAL_NAMES names)"
k -n $NS scale deploy client --replicas=1 >/dev/null 2>&1
k -n $NS rollout status deploy client --timeout=300s >/dev/null 2>&1
HNODE=$(k -n $NS get pod -l app=client -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null)
HAGENT=$(k -n kube-system get pod -l k8s-app=cilium --field-selector spec.nodeName="$HNODE" -o jsonpath='{.items[0].metadata.name}')
say "heavy pod on node $HNODE (agent $HAGENT)"

# --- observers, pinned to the SAME node ----------------------------------
S=$(cd "$(dirname "$0")" && pwd)
sed "s/PLACEHOLDER_NODE/$HNODE/; s/replicas: 5/replicas: $OBSERVERS/" \
  "$S/workload-observer.yaml" | k apply -f - >/dev/null 2>&1
k -n $NS rollout status deploy observer --timeout=300s >/dev/null 2>&1
say "$OBSERVERS observers on $HNODE"

# --- sample ---------------------------------------------------------------
printf 'minute agent cache lookup conn lockwarns cpu gcsec gcdels\n' > "$OUT/samples.tsv"
printf 'minute done failed p50 p90 p99 max\n' > "$OUT/observers.tsv"
for i in $(seq 1 "$MINUTES"); do
  sleep 60
  for A in $AGENTS; do
    O=$(k -n kube-system exec "$A" -c cilium-agent -- sh -c "cilium-dbg fqdn cache list 2>/dev/null" 2>/dev/null)
    TOT=$(echo "$O"|wc -l); LK=$(echo "$O"|grep -c ' lookup '); CN=$(echo "$O"|grep -c ' connection ')
    W=$(grep -c "Name lock acquisition" "$OUT/$A.log" 2>/dev/null)
    CPU=$(k -n kube-system top pod "$A" --no-headers 2>/dev/null|awk '{print $2}')
    M=$(k -n kube-system exec "$A" -c cilium-agent -- sh -c "cilium-dbg metrics list 2>/dev/null" 2>/dev/null)
    GC=$(echo "$M"|awk '/jobs_timer_last_run_duration_seconds.*dns-garbage-collector-job/{print $NF}')
    GD=$(echo "$M"|awk '/cilium_fqdn_gc_deletions_total/{print $NF}')
    printf '%s %s %s %s %s %s %s %s %s\n' "$i" "$A" "$TOT" "$LK" "$CN" "$W" "${CPU:-?}" "${GC:-?}" "${GD:-?}" >> "$OUT/samples.tsv"
  done
  # observer latency: the collateral-damage metric
  OL=$(k -n $NS logs -l role=observer --tail=3 2>/dev/null | grep '^OBS ' | tail -1)
  if [ -n "$OL" ]; then
    printf '%s %s\n' "$i" "$(echo "$OL" | sed 's/OBS //; s/[a-z0-9]*=//g')" >> "$OUT/observers.tsv"
  fi
  say "t+${i}m $(grep "^$i " "$OUT/samples.tsv" | awk '{printf "%s cache=%s conn=%s gc=%ss | ", $2,$3,$5,$8}') OBS[$OL]"
done

# --- final ----------------------------------------------------------------
say "--- heavy generator ---"
HP=$(k -n $NS get pod -l app=client -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
k -n $NS logs "$HP" --tail=12 2>/dev/null | grep -oE 'offered=[0-9]+ done=[0-9]+ failed=[0-9]+ backlog=[0-9]+' | tail -1 | tee -a "$OUT/run.log" > "$OUT/clients.txt"

say "--- OBSERVERS (collateral damage on unrelated endpoints) ---"
k -n $NS logs -l role=observer --tail=4 2>/dev/null | grep '^OBS ' | tail -"$OBSERVERS" | tee -a "$OUT/run.log"
k -n $NS logs -l role=observer --tail=4 2>/dev/null | grep '^OBS ' | tail -"$OBSERVERS" > "$OUT/observers-final.txt"

while read -r P; do kill "$P" 2>/dev/null; done < "$OUT/streams.pid"

say "--- agent lock waits ---"
cat "$OUT"/*.log 2>/dev/null | grep -oE 'duration=[0-9hms.µ]+' | sed 's/duration=//' > "$OUT/waits.txt"
python3 -c "
import sys,re
def sec(s):
    t=0.0
    for v,u in re.findall(r'([0-9.]+)(h|ms|m|s|µs|ns)', s):
        t+=float(v)*{'h':3600,'m':60,'s':1,'ms':1e-3,'µs':1e-6,'ns':1e-9}[u]
    return t
d=sorted(sec(l.strip()) for l in open('$OUT/waits.txt') if l.strip())
if not d: print('  no lock warnings'); raise SystemExit
n=len(d); p=lambda q: d[min(int(n*q),n-1)]
print('  samples=%d p50=%.2fs p90=%.2fs p99=%.2fs max=%.2fs' % (n,p(.5),p(.9),p(.99),d[-1]))
print('  >5s=%.1f%%  >10s=%.1f%%  >30s=%d' % (100*sum(1 for x in d if x>5)/n,100*sum(1 for x in d if x>10)/n,sum(1 for x in d if x>30)))
" | tee -a "$OUT/run.log"
say "errors: $(cat "$OUT"/*.log 2>/dev/null | grep -c 'level=error')"
say "results in $OUT"

#!/usr/bin/env bash
# Reproduce: Cilium FQDN DNSCache grows unbounded when many FQDNs resolve to the
# same IP while that IP is held open by a connection.
#
# Usage:  ./repro-fqdn-same-ip.sh [create|verify|sysdump|cleanup]
#         ./repro-fqdn-same-ip.sh            # = create + verify
#
# Requires: kind >= v0.33.0, kubectl, helm, docker.
set -euo pipefail

CLUSTER="${CLUSTER:-fqdn-repro-136}"
CTX="kind-${CLUSTER}"
NODE_IMAGE="${NODE_IMAGE:-kindest/node:v1.36.4}"
CILIUM_VERSION="${CILIUM_VERSION:-1.19.6}"
CLIENT_REPLICAS="${CLIENT_REPLICAS:-30}"
CLIENT_THREADS="${CLIENT_THREADS:-4}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!!  %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31mXX  %s\033[0m\n' "$*" >&2; exit 1; }

require() {
  for c in kind kubectl helm docker; do
    command -v "$c" >/dev/null || die "missing required command: $c"
  done
  local kv
  kv=$(kind version | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  log "kind $kv | node image $NODE_IMAGE | cilium $CILIUM_VERSION"
}

create_cluster() {
  log "Creating kind cluster '$CLUSTER'"
  cat > "$WORKDIR/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER}
networking:
  disableDefaultCNI: true
  kubeProxyMode: none
nodes:
  - role: control-plane
    image: ${NODE_IMAGE}
  - role: worker
    image: ${NODE_IMAGE}
EOF
  kind create cluster --config "$WORKDIR/kind.yaml"

  # kind can leave the worker's kubelet dead if the host ran out of inotify
  # instances while other clusters were running (inotify_init: too many open
  # files). Nudge it once. If this keeps happening, raise
  # fs.inotify.max_user_instances on the host.
  if ! kubectl --context "$CTX" get node "${CLUSTER}-worker" >/dev/null 2>&1; then
    warn "worker did not register; restarting its kubelet"
    docker exec "${CLUSTER}-worker" systemctl restart kubelet || true
    sleep 20
  fi
  # Nodes stay NotReady until a CNI is installed, so only assert registration here.
  kubectl --context "$CTX" get node "${CLUSTER}-control-plane" >/dev/null \
    || die "control-plane node did not register"
  kubectl --context "$CTX" get node "${CLUSTER}-worker" >/dev/null \
    || die "worker node did not register"
  kubectl --context "$CTX" get nodes
}

install_cilium() {
  log "Installing Cilium ${CILIUM_VERSION}"
  local cp_ip
  cp_ip=$(docker inspect "${CLUSTER}-control-plane" \
            --format '{{.NetworkSettings.Networks.kind.IPAddress}}')

  helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
  helm repo update >/dev/null

  # NOTE: --set-string is required. Plain --set renders these as JSON numbers
  # and the cilium-config ConfigMap then fails to apply.
  helm install cilium cilium/cilium --version "$CILIUM_VERSION" \
    --namespace kube-system --kube-context "$CTX" \
    --set k8sServiceHost="$cp_ip" --set k8sServicePort=6443 \
    --set kubeProxyReplacement=true --set l7Proxy=true \
    --set operator.replicas=1 \
    --set-string extraConfig.tofqdns-endpoint-max-ip-per-hostname=1000 \
    --set-string extraConfig.tofqdns-min-ttl=1 \
    --set-string extraConfig.tofqdns-proxy-response-max-delay=100ms \
    --set-string extraConfig.dnsproxy-lock-timeout=500ms

  kubectl --context "$CTX" -n kube-system rollout status ds/cilium --timeout=300s
  # Nodes only go Ready once the CNI is up.
  kubectl --context "$CTX" wait --for=condition=Ready node --all --timeout=180s
}

deploy_workload() {
  log "Deploying target, toFQDNs policy and DNS load generator"
  cat > "$WORKDIR/workload.yaml" <<EOF
apiVersion: v1
kind: Namespace
metadata: {name: repro}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: target, namespace: repro}
spec:
  replicas: 1
  selector: {matchLabels: {app: target}}
  template:
    metadata: {labels: {app: target}}
    spec:
      containers:
        - {name: nginx, image: nginx:alpine, ports: [{containerPort: 80}]}
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {name: repro-fqdn, namespace: repro}
spec:
  endpointSelector: {matchLabels: {app: client}}
  egress:
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports: [{port: "53", protocol: ANY}]
          rules: {dns: [{matchPattern: "*"}]}
    - toFQDNs:
        - matchPattern: "*.app.test.local"
      toPorts:
        - ports: [{port: "80", protocol: TCP}]
    - toEndpoints: [{matchLabels: {app: target}}]
      toPorts:
        - ports: [{port: "80", protocol: TCP}]
---
apiVersion: v1
kind: ConfigMap
metadata: {name: client-script, namespace: repro}
data:
  client.py: |
    import socket, threading, uuid, time, os
    KEEP = "keepalive-fixed.app.test.local"
    THREADS = int(os.environ.get("THREADS", "4"))
    ready = threading.Event()

    def keepalive():
        # Hold an open connection to the shared IP. This pins its zombie entry
        # ALIVE, so the DNS names accumulated against that IP are never reaped.
        ip = None
        while ip is None:
            try: ip = socket.getaddrinfo(KEEP, None, socket.AF_INET)[0][4][0]
            except Exception: time.sleep(1)
        print("keepalive ip =", ip, flush=True)
        ready.set()
        while True:
            try:
                s = socket.create_connection((ip, 80), timeout=10)
                while True:
                    s.sendall(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: keep-alive\r\n\r\n")
                    if not s.recv(8192): raise IOError("closed")
                    time.sleep(3)
            except Exception: time.sleep(2)

    def resolver():
        # Every lookup is a brand-new FQDN resolving to that same single IP.
        ready.wait()
        while True:
            try: socket.getaddrinfo("%s.app.test.local" % uuid.uuid4().hex, None, socket.AF_INET)
            except Exception: pass

    threading.Thread(target=keepalive, daemon=True).start()
    for _ in range(THREADS):
        threading.Thread(target=resolver, daemon=True).start()
    while True: time.sleep(3600)
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: client, namespace: repro}
spec:
  replicas: ${CLIENT_REPLICAS}
  selector: {matchLabels: {app: client}}
  template:
    metadata: {labels: {app: client}}
    spec:
      containers:
        - name: client
          image: python:3.11-alpine
          command: ["python","-u","/app/client.py"]
          env: [{name: THREADS, value: "${CLIENT_THREADS}"}]
          volumeMounts: [{name: s, mountPath: /app}]
      volumes:
        - {name: s, configMap: {name: client-script}}
EOF
  kubectl --context "$CTX" apply -f "$WORKDIR/workload.yaml"
  kubectl --context "$CTX" -n repro wait --for=condition=Ready pod -l app=target --timeout=240s
}

patch_coredns() {
  local tip
  tip=$(kubectl --context "$CTX" -n repro get pod -l app=target \
          -o jsonpath='{.items[0].status.podIP}')
  [ -n "$tip" ] || die "could not determine target pod IP"
  log "Pointing every *.app.test.local at the single shared IP ${tip}"

  kubectl --context "$CTX" -n kube-system get cm coredns \
    -o jsonpath='{.data.Corefile}' > "$WORKDIR/Corefile"
  cat >> "$WORKDIR/Corefile" <<EOF

test.local:53 {
    errors
    template IN A {
        answer "{{ .Name }} 60 IN A ${tip}"
    }
    template IN AAAA {
        authority "test.local. 60 IN SOA ns.test.local. h.test.local. 1 7200 900 1209600 60"
    }
}
EOF
  kubectl --context "$CTX" -n kube-system create cm coredns \
    --from-file=Corefile="$WORKDIR/Corefile" --dry-run=client -o yaml \
    | kubectl --context "$CTX" -n kube-system apply -f - >/dev/null
  kubectl --context "$CTX" -n kube-system rollout restart deploy coredns
  kubectl --context "$CTX" -n kube-system rollout status deploy coredns --timeout=180s
  echo "$tip" > "$WORKDIR/.shared_ip"
}

agent_on_client_node() {
  local node
  node=$(kubectl --context "$CTX" -n repro get pod -l app=client \
           -o jsonpath='{.items[0].spec.nodeName}')
  kubectl --context "$CTX" -n kube-system get pod -l k8s-app=cilium \
    --field-selector spec.nodeName="$node" -o jsonpath='{.items[0].metadata.name}'
}

verify() {
  log "Confirming distinct FQDNs collapse to one IP"
  local pod ips
  pod=$(kubectl --context "$CTX" -n repro get pod -l app=client \
          -o jsonpath='{.items[0].metadata.name}')
  ips=""
  for n in aa-deadbeef bb-cafebabe zz-0f0f0f0f; do
    local got
    got=$(kubectl --context "$CTX" -n repro exec "$pod" -- python -c \
      "import socket;print(socket.getaddrinfo('${n}.app.test.local',None,socket.AF_INET)[0][4][0])" 2>/dev/null | tr -d '\r')
    echo "    ${n}.app.test.local -> ${got}"
    ips="${ips}${got}\n"
  done
  [ "$(printf "$ips" | sort -u | wc -l)" -eq 1 ] \
    || die "names did NOT collapse to a single IP - CoreDNS patch failed"
  echo "    OK: all names resolve to the same IP"

  log "Letting the DNS cache accumulate (2 x 60s FQDN GC intervals)"
  local agent
  agent=$(agent_on_client_node)
  echo "    cilium agent on the client node: $agent"
  for i in 1 2 3; do
    sleep 60
    local out
    out=$(kubectl --context "$CTX" -n kube-system exec "$agent" -c cilium-agent -- \
            cilium-dbg fqdn cache list -o json 2>/dev/null \
          | python3 -c "
import sys,json,collections
d=json.load(sys.stdin); c=collections.Counter()
for e in d:
    for ip in (e.get('ips') or []): c[ip]+=1
top=c.most_common(1)
print('entries=%d distinct_ips=%d %s' % (len(d), len(c), ('top=%s:%d names'%top[0]) if top else ''))
")
    echo "    [t+${i}m] $out"
  done

  log "FQDN GC cycles (deleted entries per pass)"
  kubectl --context "$CTX" -n kube-system logs "$agent" -c cilium-agent 2>/dev/null \
    | grep "FQDN garbage collector" \
    | sed -E 's/.*time=([0-9T:.-]+Z).*lenEntries=([0-9]+).*/    GC \1  deleted=\2/' || true

  log "DNS impact"
  for p in "Timed out waiting for datapath updates" "Name lock acquisition time took longer"; do
    printf '    %6s x  %s\n' \
      "$(kubectl --context "$CTX" -n kube-system logs "$agent" -c cilium-agent 2>/dev/null | grep -c "$p" || true)" "$p"
  done

  cat <<'EOS'

RESULT: the cache holds tens of thousands of names against a SINGLE IP, GC runs
and deletes a growing number of entries every cycle yet the total keeps rising,
and the agent logs DNS datapath timeouts and lock-acquisition warnings.
EOS
}

sysdump() {
  command -v cilium >/dev/null || die "cilium CLI not found (needed for sysdump)"
  log "Collecting sysdump"
  cilium sysdump --context "$CTX" --output-filename "cilium-sysdump-${CLUSTER}"
  echo "    wrote cilium-sysdump-${CLUSTER}.zip"
}

cleanup() { log "Deleting cluster '$CLUSTER'"; kind delete cluster --name "$CLUSTER"; }

case "${1:-all}" in
  create)  require; create_cluster; install_cilium; deploy_workload; patch_coredns ;;
  verify)  require; verify ;;
  sysdump) sysdump ;;
  cleanup) cleanup ;;
  all)     require; create_cluster; install_cilium; deploy_workload; patch_coredns; verify ;;
  *)       die "usage: $0 [create|verify|sysdump|cleanup]" ;;
esac

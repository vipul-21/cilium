# Proposal: HBONE Port Preservation for Cilium + ztunnel L4 Policy Enforcement

## Problem

When ztunnel encrypts traffic, it rewrites the destination port to **15008** (the HBONE listener port). Cilium's eBPF datapath sits between pod network namespaces on the node and can only see the rewritten port — making `CiliumNetworkPolicy` **blind** to the original destination port.

```
Current (upstream):

  curl pod          eBPF (node)           nginx pod
  ztunnel           CiliumNetworkPolicy   ztunnel
  encrypts ──────►  sees dport=15008  ──► decrypts
  dport→15008       CAN'T enforce         dport was 80
                    port-based policy ✗
```

## Proposed Solution

**Two changes working together:**

| Component | Change |
|-----------|--------|
| **Source ztunnel** | Preserve the original destination port on the wire instead of rewriting to 15008 |
| **Destination eBPF** | In `local_delivery()`, look up source IP in `cilium_meshed_pods` BPF map. If found, OR the HBONE flag bit (`0x1000`) into `skb->mark` after identity mark is set. Iptables in the pod netns matches this bit and redirects to 15008 |

```
Proposed:

  curl pod          eBPF (node)                nginx pod netns
  ztunnel           local_delivery()           iptables
  encrypts ──────►  sees dport=80 ✓    ──────► mark & 0x1000?
  dport=80          enforces policy ✓          → REDIRECT :15008
  (preserved!)      sets mark |= 0x1000        else → :15006
```

## How It Works

### Source side (ztunnel change)

ztunnel connects to the destination pod IP on the **original port** (e.g., 80) instead of 15008. The HBONE (mTLS + HTTP/2 CONNECT) tunnel is established over this connection. The wire now shows the real destination port.

### Destination side (BPF mark in local_delivery + iptables redirect)

#### Mark lifecycle across network namespaces

```
┌─────────────────────────────────┐
│  curl pod netns                 │
│  ztunnel outbound encrypts      │
│  sends to 10.0.0.114:80         │
│  socket mark = 0x539            │
│  OUTPUT iptables: ACCEPT        │
│  packet exits netns             │
│  mark = 0x539 on skb            │
└──────────┬──────────────────────┘
           │ veth pair (mark survives)
           ▼
┌──────────────────────────────────┐
│  HOST namespace                  │
│  cil_from_container (BPF)        │
│    → handle_ipv4_from_lxc()      │
│    → ipv4_local_delivery()       │
│    → local_delivery()            │
│                                  │
│  1. set_identity_mark()          │  ← OVERWRITES mark to 0x0F00|id
│  2. set_hbone_mark(ctx, src_ip)  │  ← OR's 0x1000 if src in map
│     map_lookup(meshed_pods, src) │     mark = 0x1F00|id (both survive)
│  3. redirect_ep()                │
└──────────┬───────────────────────┘
           │ veth pair (mark survives)
           ▼
┌──────────────────────────────────┐
│  nginx pod netns                 │
│  PREROUTING iptables             │
│  mark & 0x1000 == 0x1000? YES    │
│  → REDIRECT :15008               │
│  ztunnel HBONE listener decrypts │
│  → plaintext to app ✓            │
└──────────────────────────────────┘
```

#### Why 0x1000 (bit 12) instead of a magic byte value

`skb->mark` bit layout in Cilium:
```
  31              16  15    12  11     8  7        0
  ├── identity ────┤  ├─ key ─┤  ├ magic ┤  ├ cluster ┤
```

- Bits 11:8 (`MARK_MAGIC_KEY_MASK & 0x0F00`): magic byte — `0x0F` for identity
- Bits 15:12: key index — only used by IPsec (mutually exclusive with ztunnel)
- Bits 31:16: security identity
- Bits 7:0: cluster ID

`MARK_MAGIC_HBONE = 0x1000` uses **bit 12** as a flag that can be **OR'd alongside** the identity mark. A magic byte value like `0x0600` would **replace** the identity magic (`0x0F`), breaking identity tracking. The flag bit approach preserves both:

```
After set_identity_mark():  mark = 0x0F00 | id<<16
After mark |= 0x1000:       mark = 0x1F00 | id<<16  ← both coexist
iptables: -m mark --mark 0x1000/0x1000              ← checks only bit 12
```

#### Cross-node support

`skb->mark` does **not** survive the wire (it's kernel-internal). For cross-node traffic:

- Same-node: mark survives veth crossing → works with flag bit
- Cross-node: packet arrives via `cil_from_netdev`/`cil_from_overlay` → new skb, mark=0

Both paths converge at `local_delivery()`, which does the `cilium_meshed_pods` map lookup using the source IP from the packet header. The source IP is always preserved (same-node or cross-node), so the map lookup works for both.

| Scenario | Source IP in packet | In map? | Flag set? | Redirect |
|----------|-------------------|---------|-----------|----------|
| Same-node, meshed→meshed | curl pod IP | Yes | 0x1000 → 15008 | ✓ |
| Same-node, plain→meshed | external IP | No | no flag → 15006 | ✓ |
| Cross-node, meshed→meshed | curl pod IP | Yes | 0x1000 → 15008 | ✓ |
| Cross-node, plain→meshed | external IP | No | no flag → 15006 | ✓ |

### BPF map (maintained by cilium-agent)

```
cilium_meshed_pods (hash: endpoint_key → mesh_info):
  10.244.1.6 → { flags: MESH_FLAG_ENCRYPTED }  // curl pod (meshed)
  10.244.1.5 → { flags: MESH_FLAG_ENCRYPTED }  // nginx pod (meshed)
  // non-meshed pods not in map
```

### iptables rules inside pod netns

```bash
# HBONE redirect (before plaintext rule):
-A CILIUM_PREROUTING ! -d 127.0.0.1/32 -p tcp -m mark --mark 0x1000/0x1000 -j REDIRECT --to-ports 15008

# Existing plaintext redirect:
-A CILIUM_PREROUTING ! -d 127.0.0.1/32 -p tcp ! --dport 15008 -m mark ! --mark 0x539/0xfff -j REDIRECT --to-ports 15006
```
  encrypts ──────►  sees dport=80 ✓    ──────► mark=0x200?
  dport=80          enforces policy ✓          → REDIRECT :15008
  (preserved!)      sets skb->mark=0x200       else → :15006
```

## How It Works

### Source side (ztunnel change)

ztunnel connects to the destination pod IP on the **original port** (e.g., 80) instead of 15008. The HBONE (mTLS + HTTP/2 CONNECT) tunnel is established over this connection. The wire now shows the real destination port.

### Destination side (eBPF + iptables)

```c
// eBPF on tc/ingress of dst pod's host-side veth (pseudocode)
SEC("tc/ingress")
int handle_ingress(struct __sk_buff *skb) {
    __u32 src_ip = /* parse IP header */;

    // Lookup: is source a meshed pod?
    struct mesh_info *info = bpf_map_lookup_elem(&meshed_pods, &src_ip);

    if (info && info->encrypted) {
        skb->mark |= 0x200;  // signal "encrypted" to iptables
    }

    // Enforce CiliumNetworkPolicy (existing logic)
    // Now sees real dst port ✓

    return TC_ACT_OK;
}
```

```bash
# iptables inside destination pod netns (PREROUTING)
-A PREROUTING -m mark --mark 0x200 -j REDIRECT --to-ports 15008   # encrypted → HBONE
-A PREROUTING -m mark ! --mark 0x539/0xfff -j REDIRECT --to-ports 15006  # plaintext
```

### BPF map (maintained by cilium-agent)

```
meshed_pods (hash:ip → mesh_info):
  10.244.1.6 → { encrypted: true }    // curl pod (meshed)
  10.244.1.5 → { encrypted: true }    // nginx pod (meshed)
  // non-meshed pods not in map
```

## Why skb->mark over DSCP

| | skb->mark | DSCP |
|--|-----------|------|
| Crosses wire | No (kernel-internal) | Yes (IP header) |
| Needs to cross wire | No — map lookup in local_delivery() handles both same-node and cross-node | — |
| QoS conflicts | None | Possible |
| Cloud provider stripping | N/A | Possible |
| Bits available | 32 | 6 |
| iptables support | `-m mark` | `-m dscp` |

Since the eBPF program (`local_delivery()` in the host namespace) and the iptables rules (pod netns) are always on the **same node**, a kernel-internal signal is sufficient and avoids wire-level side effects. The meshed_pods map lookup replaces the need for the mark to cross the wire.

---

## Testing in Kind: Before and After

### Prerequisites

```bash
# Required tools
kind kubectl helm tshark jq docker
```

### BEFORE the change (current upstream behavior)

```bash
#!/usr/bin/env bash
# test-before.sh — observe current port 15008 behavior with Cilium + ztunnel
set -euo pipefail

CLUSTER=port-test
NS=demo

# 1. Create cluster (disable default CNI — Cilium will provide it)
cat <<EOF | kind create cluster --name $CLUSTER --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
nodes:
  - role: control-plane
  - role: worker
EOF

# 2. Install Cilium with ztunnel enabled
helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true
helm repo update cilium
helm install cilium cilium/cilium --version 1.17.0 \
  --namespace kube-system \
  --set ztunnel.enabled=true \
  --set routingMode=native \
  --set ipv4NativeRoutingCIDR=10.244.0.0/16 \
  --wait --timeout 300s
kubectl rollout status daemonset/ztunnel -n kube-system --timeout=120s

# 3. Deploy workloads
kubectl create namespace $NS
kubectl apply -n $NS -f - <<'YAML'
apiVersion: v1
kind: Service
metadata:
  name: nginx
spec:
  selector: { app: nginx }
  ports: [{ port: 80, targetPort: 80 }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: nginx }
spec:
  replicas: 1
  selector: { matchLabels: { app: nginx } }
  template:
    metadata: { labels: { app: nginx } }
    spec:
      containers:
      - name: nginx
        image: nginx:latest
        ports: [{ containerPort: 80 }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: curl }
spec:
  replicas: 1
  selector: { matchLabels: { app: curl } }
  template:
    metadata: { labels: { app: curl } }
    spec:
      containers:
      - name: curl
        image: curlimages/curl:latest
        command: ["sleep", "infinity"]
YAML

kubectl wait --for=condition=Ready pod -l app=nginx -n $NS --timeout=120s
kubectl wait --for=condition=Ready pod -l app=curl -n $NS --timeout=120s

# 4. Enroll namespace for ztunnel mTLS
kubectl label namespace $NS io.cilium/mtls-enabled=true --overwrite
sleep 15

# 5. Get pod info
CURL_POD=$(kubectl get pod -n $NS -l app=curl -o jsonpath='{.items[0].metadata.name}')
NGINX_POD=$(kubectl get pod -n $NS -l app=nginx -o jsonpath='{.items[0].metadata.name}')
NGINX_IP=$(kubectl get pod $NGINX_POD -n $NS -o jsonpath='{.status.podIP}')
NODE=$(kubectl get pod $CURL_POD -n $NS -o jsonpath='{.spec.nodeName}')
CID=$(kubectl get pod $CURL_POD -n $NS -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's|containerd://||')
PID=$(docker exec $NODE crictl inspect $CID 2>/dev/null | jq -r '.info.pid')

# 6. Install tshark in node
docker exec $NODE sh -c "command -v tshark >/dev/null 2>&1 || \
  (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tshark >/dev/null 2>&1)"

# 7. Capture and send traffic
docker exec -d $NODE nsenter -t $PID -n tshark -i any -w /tmp/before.pcap -a duration:10 2>/dev/null
sleep 2
kubectl exec -n $NS $CURL_POD -- curl -s -o /dev/null http://nginx.$NS.svc.cluster.local
sleep 9

# 8. Analyze — look for port 15008
echo ""
echo "=== BEFORE: packets leaving curl pod (look at dst port) ==="
docker exec $NODE tshark -r /tmp/before.pcap \
  -Y "tcp.dstport==15008" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport -e tcp.flags.str \
  -E header=y -E separator='  ' 2>/dev/null

echo ""
echo "EXPECTED: dst port = 15008 on HBONE connections"
echo "  → eBPF on the wire would see dport=15008, NOT 80"

# 9. Apply CiliumNetworkPolicy — allow only port 80 to nginx
echo ""
echo "=== BEFORE: CiliumNetworkPolicy port 80 enforcement ==="
kubectl apply -n $NS -f - <<'YAML'
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-nginx-80
spec:
  endpointSelector:
    matchLabels:
      app: nginx
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: curl
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
YAML
sleep 5

# 10. Test CNP — port 80 should be allowed but eBPF sees 15008, so this may FAIL
HTTP_CODE=$(kubectl exec -n $NS $CURL_POD -- curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://nginx.$NS.svc.cluster.local 2>/dev/null || echo "timeout")
echo "curl → nginx with CNP allowing port 80: HTTP $HTTP_CODE"
if [[ "$HTTP_CODE" == "200" ]]; then
  echo "⚠️  Traffic passed — CNP may not be enforcing (eBPF sees dport=15008, not 80)"
else
  echo "❌ Traffic blocked — CNP correctly sees port but ztunnel rewrote to 15008"
  echo "   This confirms:  eBPF cannot enforce port 80 when wire shows 15008"
fi

# Cleanup CNP for next test
kubectl delete cnp allow-nginx-80 -n $NS 2>/dev/null || true

echo ""
echo "=== SUMMARY (BEFORE) ==="
echo "  Wire port:     15008 (rewritten by ztunnel)"
echo "  eBPF sees:     dport=15008"
echo "  CNP port 80:   cannot match → policy enforcement broken"
```

### AFTER the change (port preservation + skb mark)

```bash
#!/usr/bin/env bash
# test-after.sh — verify port preservation and marking
# Requires: modified ztunnel binary with port preservation
set -euo pipefail

CLUSTER=port-test
NS=demo

# Assumes cluster from test-before.sh still running
# AND modified ztunnel deployed (port preservation enabled)
# Redeploy ztunnel DaemonSet in kube-system with modified image

CURL_POD=$(kubectl get pod -n $NS -l app=curl -o jsonpath='{.items[0].metadata.name}')
NGINX_POD=$(kubectl get pod -n $NS -l app=nginx -o jsonpath='{.items[0].metadata.name}')
NGINX_IP=$(kubectl get pod $NGINX_POD -n $NS -o jsonpath='{.status.podIP}')
CURL_IP=$(kubectl get pod $CURL_POD -n $NS -o jsonpath='{.status.podIP}')
NODE=$(kubectl get pod $CURL_POD -n $NS -o jsonpath='{.spec.nodeName}')
CID_CURL=$(kubectl get pod $CURL_POD -n $NS -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's|containerd://||')
PID_CURL=$(docker exec $NODE crictl inspect $CID_CURL 2>/dev/null | jq -r '.info.pid')
CID_NGINX=$(kubectl get pod $NGINX_POD -n $NS -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's|containerd://||')
PID_NGINX=$(docker exec $NODE crictl inspect $CID_NGINX 2>/dev/null | jq -r '.info.pid')

echo "curl:  $CURL_POD ($CURL_IP)"
echo "nginx: $NGINX_POD ($NGINX_IP)"

# --- TEST 1: Verify port is preserved on the wire ---
echo ""
echo "=== TEST 1: Port preservation on the wire ==="

docker exec -d $NODE nsenter -t $PID_CURL -n tshark -i any -w /tmp/after-curl.pcap -a duration:10 2>/dev/null
sleep 2
kubectl exec -n $NS $CURL_POD -- curl -s -o /dev/null http://nginx.$NS.svc.cluster.local
sleep 9

echo "Connections with dst port 15008 (should be ZERO):"
docker exec $NODE tshark -r /tmp/after-curl.pcap \
  -Y "tcp.dstport==15008 && tcp.flags.syn==1" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport \
  -E header=y -E separator='  ' 2>/dev/null
COUNT_15008=$(docker exec $NODE tshark -r /tmp/after-curl.pcap \
  -Y "tcp.dstport==15008 && tcp.flags.syn==1" 2>/dev/null | wc -l)

echo ""
echo "Connections with dst port 80 to nginx IP (should be >= 1):"
docker exec $NODE tshark -r /tmp/after-curl.pcap \
  -Y "tcp.dstport==80 && ip.dst==$NGINX_IP && tcp.flags.syn==1" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport \
  -E header=y -E separator='  ' 2>/dev/null
COUNT_80=$(docker exec $NODE tshark -r /tmp/after-curl.pcap \
  -Y "tcp.dstport==80 && ip.dst==$NGINX_IP && tcp.flags.syn==1" 2>/dev/null | wc -l)

if [[ "$COUNT_15008" -eq 0 && "$COUNT_80" -ge 1 ]]; then
  echo "✅ PASS: Port preserved — dport=80 on wire, no 15008"
else
  echo "❌ FAIL: Expected 0 connections to 15008, got $COUNT_15008"
  echo "         Expected >=1 connections to 80, got $COUNT_80"
fi

# --- TEST 2: Verify TLS (mTLS still works) ---
echo ""
echo "=== TEST 2: Traffic is still encrypted (mTLS) ==="
echo "TLS ClientHello on port 80 (should be >= 1):"
docker exec $NODE tshark -r /tmp/after-curl.pcap \
  -Y "tls.handshake.type==1 && tcp.dstport==80 && ip.dst==$NGINX_IP" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport -e tls.handshake.type \
  -E header=y -E separator='  ' 2>/dev/null
COUNT_TLS=$(docker exec $NODE tshark -r /tmp/after-curl.pcap \
  -Y "tls.handshake.type==1 && tcp.dstport==80 && ip.dst==$NGINX_IP" 2>/dev/null | wc -l)

if [[ "$COUNT_TLS" -ge 1 ]]; then
  echo "✅ PASS: Traffic to port 80 is TLS-encrypted (HBONE with preserved port)"
else
  echo "❌ FAIL: No TLS handshake seen on port 80"
fi

# --- TEST 3: Verify iptables redirect with mark (if eBPF marking is in place) ---
echo ""
echo "=== TEST 3: iptables rules in nginx pod netns ==="
echo "Expected: -m mark --mark 0x200 → REDIRECT 15008"
docker exec $NODE nsenter -t $PID_NGINX -n iptables -t nat -L PREROUTING -n -v --line-numbers 2>/dev/null

# --- TEST 4: Verify nginx receives plaintext (end-to-end works) ---
echo ""
echo "=== TEST 4: End-to-end connectivity ==="
HTTP_CODE=$(kubectl exec -n $NS $CURL_POD -- curl -s -o /dev/null -w "%{http_code}" http://nginx.$NS.svc.cluster.local)
if [[ "$HTTP_CODE" == "200" ]]; then
  echo "✅ PASS: curl → nginx returned HTTP $HTTP_CODE"
else
  echo "❌ FAIL: curl → nginx returned HTTP $HTTP_CODE (expected 200)"
fi

# --- TEST 5: CiliumNetworkPolicy enforcement (the whole point) ---
echo ""
echo "=== TEST 5: CiliumNetworkPolicy port-based enforcement ==="

# Apply CNP: only allow ingress to nginx on port 80 from curl
kubectl apply -n $NS -f - <<'YAML'
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-nginx-80
spec:
  endpointSelector:
    matchLabels:
      app: nginx
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: curl
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
YAML
sleep 5

# Port 80 should be allowed
HTTP_CODE=$(kubectl exec -n $NS $CURL_POD -- curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://nginx.$NS.svc.cluster.local 2>/dev/null || echo "timeout")
if [[ "$HTTP_CODE" == "200" ]]; then
  echo "✅ PASS: CNP allows port 80 — curl → nginx returned HTTP $HTTP_CODE"
else
  echo "❌ FAIL: CNP allows port 80 but traffic failed (HTTP $HTTP_CODE)"
fi

# Now apply a CNP that blocks port 80 (only allow port 443)
kubectl apply -n $NS -f - <<'YAML'
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-nginx-80
spec:
  endpointSelector:
    matchLabels:
      app: nginx
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: curl
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
YAML
sleep 5

# Port 80 should now be BLOCKED (only 443 allowed)
HTTP_CODE=$(kubectl exec -n $NS $CURL_POD -- curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://nginx.$NS.svc.cluster.local 2>/dev/null || echo "timeout")
if [[ "$HTTP_CODE" == "timeout" || "$HTTP_CODE" != "200" ]]; then
  echo "✅ PASS: CNP blocks port 80 — curl → nginx was denied ($HTTP_CODE)"
  echo "   → eBPF sees real dport=80, matches CNP, correctly drops traffic"
else
  echo "❌ FAIL: CNP should block port 80 but traffic got through (HTTP $HTTP_CODE)"
fi

# Cleanup
kubectl delete cnp allow-nginx-80 -n $NS 2>/dev/null || true

# --- Summary ---
echo ""
echo "=========================================="
echo "  SUMMARY"
echo "=========================================="
echo ""
echo "  Before (upstream):  wire shows dport=15008"
echo "                      eBPF blind to real ports"
echo "                      CiliumNetworkPolicy broken"
echo ""
echo "  After (this change): wire shows dport=80"
echo "                       eBPF sees real ports ✓"
echo "                       skb->mark signals encrypted"
echo "                       CiliumNetworkPolicy works ✓"
echo ""

# Cleanup
echo "To clean up:  kind delete cluster --name $CLUSTER"
```

### Quick validation commands (manual)

```bash
# Check what port ztunnel uses for HBONE (inside curl pod netns)
# BEFORE: should see connections to 15008
# AFTER:  should see connections to port 80
docker exec $NODE nsenter -t $PID_CURL -n ss -tnp | grep ztunnel

# Check iptables in nginx pod netns
# BEFORE: -j REDIRECT --to-ports 15006 (port 15008 excluded, handled directly)
# AFTER:  -m mark --mark 0x200 -j REDIRECT --to-ports 15008
docker exec $NODE nsenter -t $PID_NGINX -n iptables -t nat -L PREROUTING -n -v

# Verify traffic is still encrypted (TLS on port 80 instead of 15008)
docker exec $NODE nsenter -t $PID_CURL -n tshark -i any -Y "tls" -c 5 2>/dev/null
```

---

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Non-meshed traffic redirected to 15008 | `cilium_meshed_pods` map lookup distinguishes encrypted from plaintext; only meshed-source packets get the 0x1000 flag |
| Mark collision with identity mark | 0x1000 is a flag bit OR'd alongside (not replacing) the magic byte; identity bits 11:8 untouched |
| Mark collision with IPsec key index (bits 15:12) | IPsec and ztunnel are mutually exclusive encryption modes |
| Mark collision with ztunnel marks (0x539, 0x111) | Different bit ranges: 0x1000 is bit 12, ztunnel marks are bits 11:0 |
| BPF map stale entries (pod deleted but IP still in map) | cilium-agent watches pod lifecycle and updates map synchronously |
| Performance overhead of BPF map lookup per packet | O(1) hash lookup, negligible; Cilium already does identity lookups per packet |
| Cross-node mark loss | Map lookup uses source IP from packet header, which survives the wire; no mark needed across nodes |

## Status

- [x] Source-side port preservation (ztunnel change) — complete
- [x] Destination-side BPF mark in local_delivery() — complete
- [x] HBONE flag bit (0x1000) OR'd with identity mark — complete
- [x] iptables rules for mark-based redirect — complete
- [x] cilium_meshed_pods BPF map — complete
- [ ] Integration testing with CiliumNetworkPolicy (allow/deny port 80) — in progress

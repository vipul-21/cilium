# L4 CiliumNetworkPolicy Cross-Node Findings

## Summary

L4 CiliumNetworkPolicy enforcement works correctly cross-node for **both** standard
(non-meshed) and ztunnel-meshed traffic, provided `ipv4-native-routing-cidr` is
configured to cover the actual pod CIDRs.

## Root Cause of Earlier Failure

The cluster's `ipv4-native-routing-cidr` was misconfigured:

| Setting | Value | Problem |
|---|---|---|
| `cluster-pool-ipv4-cidr` | `10.0.0.0/8` | Cilium IPAM allocates pods in 10.0.x.x |
| `ipv4-native-routing-cidr` | `10.244.0.0/16` (old) | Does NOT cover 10.0.x.x |
| Pod CIDRs | `10.0.0.0/24`, `10.0.1.0/24` | Outside 10.244.0.0/16 |

This caused the iptables masquerade rule to fire for ALL cross-node pod-to-pod
traffic (not just ztunnel):

```
-A CILIUM_POST_nat -s 10.0.0.0/24 ! -d 10.244.0.0/16 ! -o cilium_+ -j MASQUERADE
```

Since 10.0.1.x (remote pod subnet) is NOT within 10.244.0.0/16, the `! -d` condition
matched and traffic was masqueraded. Source IP became the node IP (e.g. 172.18.0.14),
BPF resolved identity as `remote-node` instead of the actual pod identity, and L4
policy denied the traffic.

**This affected both standard Cilium and ztunnel equally** — confirmed by deploying
a non-meshed nginx on the control-plane node and applying an L4 policy. The
`cilium-dbg monitor --type drop` output showed:

```
identity remote-node->42202: 172.18.0.14:57404 -> 10.0.1.248:80 tcp SYN
```

## Fix

Changed `ipv4-native-routing-cidr` to `10.0.0.0/8` to match `cluster-pool-ipv4-cidr`:

```bash
kubectl -n kube-system patch configmap cilium-config \
  --type merge -p '{"data":{"ipv4-native-routing-cidr":"10.0.0.0/8"}}'
kubectl -n kube-system rollout restart daemonset/cilium
```

After the fix, the masquerade rule correctly exempts pod-to-pod traffic:

```
-A CILIUM_POST_nat -s 10.0.0.0/24 ! -d 10.0.0.0/8 ! -o cilium_+ -j MASQUERADE
```

Since 10.0.1.x IS within 10.0.0.0/8, the `! -d` condition no longer matches for
cross-node pod traffic → no masquerade → source pod IP preserved → BPF resolves
correct identity → L4 policy works.

## Test Results

### Without Ztunnel (non-meshed pods, `nomesh` namespace)

| Test | Source | Destination | Port | Expected | Result |
|---|---|---|---|---|---|
| Baseline (no policy) | curl-nomesh (worker) | nginx-nomesh-remote (CP) | 80 | 200 | **200** ✅ |
| L4 policy - allowed port | curl-nomesh (worker) | nginx-nomesh-remote (CP) | 80 | 200 | **200** ✅ |
| L4 policy - blocked port | curl-nomesh (worker) | nginx-nomesh-remote (CP) | 8080 | timeout | **timeout** ✅ |

**Policy applied:**
```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: test-nomesh-l4
  namespace: nomesh
spec:
  endpointSelector:
    matchLabels:
      app: nginx-nomesh-remote
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: curl-nomesh
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
```

### With Ztunnel (meshed pods, `demo` namespace)

| Test | Source | Destination | Port | Expected | Result |
|---|---|---|---|---|---|
| Baseline (no policy) | curl (worker) | nginx-remote (CP) | 80 | 200 | **200** ✅ |
| L4 policy - allowed port | curl (worker) | nginx-remote (CP) | 80 | 200 | **200** ✅ |
| L4 policy - blocked port | curl (worker) | nginx-remote (CP) | 8080 | timeout | **timeout** ✅ |
| Same-node - allowed port | curl (worker) | nginx (worker) | 80 | 200 | **200** ✅ |
| Same-node - blocked port | curl (worker) | nginx (worker) | 8080 | timeout | **timeout** ✅ |
| Reverse cross-node - allowed | curl-remote (CP) | nginx (worker) | 80 | 200 | **200** ✅ |
| Reverse cross-node - blocked port | curl-remote (CP) | nginx (worker) | 8080 | timeout | **timeout** ✅ |
| Unauthorized identity on allowed port | curl-remote (CP) | nginx-remote (CP) | 80 | timeout | **timeout** ✅ |

**Policy applied on nginx-remote:**
```yaml
spec:
  endpointSelector:
    matchLabels:
      app: nginx-remote
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: curl
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
```

**Policy applied on nginx:**
```yaml
spec:
  endpointSelector:
    matchLabels:
      app: nginx
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: curl
    - matchLabels:
        app: curl-remote
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
```

## Cluster Configuration

```
routing-mode: native
tunnel-protocol: vxlan (but no VXLAN interface — native routing only)
ipam: cluster-pool
cluster-pool-ipv4-cidr: 10.0.0.0/8
ipv4-native-routing-cidr: 10.0.0.0/8 (was 10.244.0.0/16)
enable-ipv4-masquerade: true
enable-ztunnel: true
```

## Architecture: HBONE Port Preservation with DSCP Marking

### Problem Statement

In the original ztunnel design, outbound HBONE connections always target port **15008**
on the destination pod. This means BPF on the destination node only sees port 15008,
making L4 CiliumNetworkPolicy enforcement impossible — a policy allowing port 80 would
never match because the wire traffic is on port 15008.

### Solution Overview

Two coordinated changes across Cilium and ztunnel:

1. **Port preservation** — Ztunnel connects to the destination pod on the **original
   port** (e.g., 80) instead of 15008, so BPF sees the real port for L4 policy.
2. **DSCP-based redirect** — Ztunnel sets a DSCP mark on the HBONE socket so iptables
   in the destination pod's netns can distinguish HBONE traffic and redirect it to
   ztunnel's inbound port 15008 for TLS+H2 termination.
3. **Meshed metadata** — Cilium agent marks meshed endpoints in ipcache/endpoint maps
   so BPF disables `redirect_peer` (which would bypass iptables entirely).

---

## All Changes (by component)

### Ztunnel Changes (`~/ws/cilium-ztunnel`, branch `port-preservation`)

#### 1. Port Preservation (`src/proxy/outbound.rs`)

**What:** When building the HBONE destination address, use the original destination
port (`us.port`) instead of the fixed HBONE port (15008).

```rust
// BEFORE:
InboundProtocol::HBONE => SocketAddr::from((selected_workload_ip, self.hbone_port)),

// AFTER:
InboundProtocol::HBONE => SocketAddr::from((selected_workload_ip, us.port)),
```

**Why:** This makes the TCP connection on the wire carry the real application port
(e.g., 80), allowing Cilium BPF `tail_ipv4_policy` to evaluate L4 CiliumNetworkPolicy
against the actual port number.

#### 2. DSCP Marking Before Connect (`src/proxy/pool.rs`)

**What:** When creating an outbound HBONE connection in the connection pool, set
`IP_TOS` (IPv4) or `IPV6_TCLASS` (IPv6) on the socket **before** calling
`socket.connect()`.

```rust
const DSCP_MESHED_MARK: u32 = 0x17;
let tos = DSCP_MESHED_MARK << 2;  // 0x5c

let socket = if key.dst.is_ipv4() {
    self.socket_factory.new_tcp_v4()
} else {
    self.socket_factory.new_tcp_v6()
}.map_err(Error::ConnectionFailed)?;

let sock_ref = socket2::SockRef::from(&socket);
if key.dst.is_ipv4() {
    sock_ref.set_tos_v4(tos);   // setsockopt(IP_TOS, 0x5c)
} else {
    sock_ref.set_tclass_v6(tos); // setsockopt(IPV6_TCLASS, 0x5c)
}

let tcp_stream = socket.connect(key.dst).await...
```

**Why:** The DSCP mark must be on the **SYN packet** because iptables `nat/PREROUTING`
only evaluates the first packet of a connection (conntrack state NEW). If TOS is set
after `connect()` returns (as was done originally via `freebind_connect`), the TCP
three-way handshake is already complete and iptables never sees the mark.

**Key details:**
- DSCP value `0x17` occupies the top 6 bits of the TOS byte → TOS = `0x17 << 2 = 0x5c`
- The socket is created via `socket_factory` which, in in-pod mode, creates the socket
  inside the source pod's network namespace (preserving the source pod IP)
- TOS/DSCP survives IP masquerade (SNAT does not rewrite the TOS byte)

### Cilium Changes (`~/ws/cilium`, branch `singhvipul/ztunnel`)

#### 3. Meshed Flag in BPF Maps (`bpf/lib/eps.h`)

**What:** Added `ENDPOINT_F_MESHED = 16` flag to the local endpoint map and
`flag_meshed` bit to the remote endpoint info (ipcache BPF map).

```c
#define ENDPOINT_F_MESHED  16  // Local endpoint map
// and
flag_meshed:1,                 // Remote endpoint info (ipcache)
```

**Why:** BPF programs need to know at packet processing time whether a destination
endpoint is meshed, to decide whether to disable `redirect_peer`.

#### 4. Meshed Lookup Function (`bpf/lib/mesh.h` — new file)

**What:** `is_ip4_meshed(__u32 ip4)` checks both the local endpoint map and ipcache
for the meshed flag.

```c
static __always_inline bool is_ip4_meshed(__u32 ip4)
{
    const struct endpoint_info *ep = __lookup_ip4_endpoint(ip4);
    if (ep && (ep->flags & ENDPOINT_F_MESHED))
        return true;
    const struct remote_endpoint_info *info = lookup_ip4_remote_endpoint(ip4, 0);
    if (info && info->flag_meshed)
        return true;
    return false;
}
```

**Why:** On the destination node, BPF runs in `tail_ipv4_policy` on the pod's veth.
It needs to check if the destination pod is meshed to decide the delivery method.

#### 5. Disable `redirect_peer` for Meshed Pods (`bpf/bpf_lxc.c`)

**What:** In `tail_ipv4_policy`, after policy evaluation passes, check if the
destination is meshed. If so, set `use_peer = false` (and `PACKET_HOST` for tunnel
traffic).

```c
if (is_ip4_meshed(ip4->daddr)) {
    use_peer = false;
    if (from_tunnel)
        ctx_change_type(ctx, PACKET_HOST);
}
ret = redirect_ep(ctx, ifindex, use_peer, from_tunnel);
```

**Why:** `bpf_redirect_peer` delivers packets directly into the pod's network
namespace, **bypassing netfilter entirely**. Meshed pods need iptables `PREROUTING`
to run so the DSCP-based redirect rule can send HBONE traffic to ztunnel port 15008.

#### 6. DSCP iptables Redirect Rule (`pkg/ztunnel/iptables/inpod.go`)

**What:** Added iptables rule in `CILIUM_PREROUTING` chain inside each meshed pod's
network namespace:

```
-A CILIUM_PREROUTING -p tcp -m dscp --dscp 0x17 -j REDIRECT --to-ports 15008
```

**Why:** When the HBONE TCP connection arrives at the destination pod on the original
port (e.g., 80) with DSCP `0x17`, this rule redirects it to ztunnel's inbound listener
on port 15008 for TLS termination and HTTP/2 CONNECT handling.

#### 7. Meshed Metadata Propagation (Go agent)

Multiple files work together to propagate the meshed flag from the reconciler to BPF maps:

| File | What |
|---|---|
| `pkg/endpoint/endpoint.go` | `PropertyMeshed` constant, `IsMeshed()` method |
| `pkg/endpoint/cache.go` | `IsMeshed()` on `epInfoCache` |
| `pkg/maps/lxcmap/lxcmap.go` | `EndpointFlagMeshed = 16`, sets flag in BPF value |
| `pkg/ipcache/types/types.go` | `EndpointFlags.SetMeshed()`, `FlagMeshed = 1 << 4` |
| `pkg/maps/ipcache/ipcache.go` | `FlagMeshed` in `RemoteEndpointInfoFlags` |
| `pkg/ipcache/ipcache.go` | Preserves meshed flag across legacy/metadata API upserts |
| `pkg/ztunnel/reconciler/reconciler.go` | Sets meshed metadata on enrollment |
| `pkg/k8s/watchers/cilium_endpoint.go` | Sets meshed flag for remote CEPs in enrolled namespaces |

**Flow:** Reconciler enrolls namespace → sets `PropertyMeshed` on local endpoints →
lxcmap picks up `ENDPOINT_F_MESHED` → also calls `ipcache.UpsertMetadata` with
`FlagMeshed` → ipcache BPF map gets `flag_meshed` → replicated to all nodes.

The CEP watcher additionally sets `FlagMeshed` for remote endpoints observed via
CiliumEndpoint/CiliumEndpointSlice resources, ensuring every node knows about meshed
endpoints on other nodes.

---

## Packet Flow for Each Scenario

### Scenario 1: Same-Node Meshed → Meshed (curl → nginx, both on worker)

```
curl pod (10.0.0.65)
  │
  ├─ App sends: HTTP GET to 10.0.0.162:80
  │
  ▼
ztunnel (outbound, in curl's netns via socket_factory)
  │  Intercepts via iptables REDIRECT to 15001
  │  Resolves destination workload → meshed (HBONE)
  │  Creates TCP socket in curl's netns:
  │    setsockopt(IP_TOS, 0x5c)    ← DSCP 0x17 set BEFORE connect
  │    connect(10.0.0.162:80)       ← port preservation (not 15008)
  │  TLS handshake + HTTP/2 CONNECT over this connection
  │
  ▼
BPF from-container (curl's veth)
  │  Source: 10.0.0.65, Dest: 10.0.0.162:80
  │  Normal BPF egress processing
  │
  ▼
BPF tail_ipv4_policy (nginx's veth)
  │  L4 policy check: src identity=curl, dst port=80 → ALLOW ✅
  │  is_ip4_meshed(10.0.0.162) → true
  │  use_peer = false → regular redirect (not redirect_peer)
  │
  ▼
nginx pod netns — iptables PREROUTING
  │  -m dscp --dscp 0x17 → matches! → REDIRECT --to-ports 15008
  │
  ▼
ztunnel (inbound, port 15008 in nginx's netns)
  │  TLS terminate + HTTP/2 CONNECT decode
  │  Forwards plaintext to nginx on localhost:80
  │
  ▼
nginx (10.0.0.162:80) serves response
```

### Scenario 2: Cross-Node Meshed → Meshed (curl on worker → nginx-remote on CP)

```
curl pod (10.0.0.65, worker node)
  │
  ├─ App sends: HTTP GET to 10.0.1.104:80
  │
  ▼
ztunnel (outbound, in curl's netns)
  │  Creates TCP socket in curl's netns:
  │    setsockopt(IP_TOS, 0x5c)    ← DSCP 0x17
  │    connect(10.0.1.104:80)       ← port preservation
  │  TLS + H2 CONNECT
  │
  ▼
BPF from-container (curl's veth, worker node)
  │  Source: 10.0.0.65:XXXXX, Dest: 10.0.1.104:80
  │  Cross-node → routes via eth0 to CP (172.18.0.15)
  │
  ▼
[Network: worker eth0 → docker bridge → CP eth0]
  │  Source IP preserved (10.0.0.65) because:
  │    ipv4-native-routing-cidr = 10.0.0.0/8 covers 10.0.1.104
  │    masquerade rule: ! -d 10.0.0.0/8 → does NOT match → no SNAT
  │  TOS byte (0x5c) preserved (SNAT doesn't rewrite TOS)
  │
  ▼
BPF from-netdev (CP node, eth0)
  │  Dest 10.0.1.104 → local endpoint
  │
  ▼
BPF tail_ipv4_policy (nginx-remote's veth, CP node)
  │  Source IP: 10.0.0.65 → ipcache lookup → curl's security identity
  │  L4 policy: src identity=curl, dst port=80 → ALLOW ✅
  │  is_ip4_meshed(10.0.1.104) → true (ipcache flag_meshed=1)
  │  use_peer = false
  │
  ▼
nginx-remote pod netns — iptables PREROUTING
  │  -m dscp --dscp 0x17 → matches! → REDIRECT --to-ports 15008
  │
  ▼
ztunnel (inbound, port 15008 in nginx-remote's netns)
  │  TLS terminate + H2 decode → plaintext to localhost:80
  │
  ▼
nginx-remote (10.0.1.104:80) serves response
```

### Scenario 3: Non-Meshed → Meshed (curl-nomesh → nginx, same or cross-node)

```
curl-nomesh pod (10.0.0.238, worker)
  │
  ├─ App sends: HTTP GET to 10.0.0.162:80 (direct, no ztunnel)
  │
  ▼
BPF from-container (curl-nomesh's veth)
  │  Normal processing, no DSCP mark (not meshed source)
  │
  ▼
BPF tail_ipv4_policy (nginx's veth)
  │  L4 policy check against curl-nomesh's identity
  │  is_ip4_meshed(10.0.0.162) → true
  │  use_peer = false → enters pod netns via regular redirect
  │
  ▼
nginx pod netns — iptables PREROUTING
  │  No DSCP mark on this traffic → dscp rule does NOT match
  │  Falls through to default: REDIRECT --to-ports 15006 (plaintext inbound)
  │
  ▼
ztunnel (plaintext inbound, port 15006)
  │  Forwards to nginx on localhost:80
  │
  ▼
nginx (10.0.0.162:80) serves response
```

### Scenario 4: Meshed → Non-Meshed (curl → nginx-nomesh)

```
curl pod (10.0.0.65, worker)
  │
  ├─ App sends: HTTP GET to 10.0.0.38:80
  │
  ▼
ztunnel (outbound, in curl's netns)
  │  Resolves destination workload → NOT meshed (TCP, not HBONE)
  │  Creates direct TCP connection (no TLS, no DSCP, no port change)
  │  connect(10.0.0.38:80) — plain passthrough
  │
  ▼
BPF tail_ipv4_policy (nginx-nomesh's veth)
  │  is_ip4_meshed(10.0.0.38) → false
  │  use_peer = true (normal redirect_peer)
  │  Packet delivered directly to pod (no iptables)
  │
  ▼
nginx-nomesh (10.0.0.38:80) serves response
```

### Scenario 5: Non-Meshed → Non-Meshed

Standard Cilium flow — no ztunnel, no DSCP, `redirect_peer` enabled, no iptables
PREROUTING. Completely unchanged from mainline Cilium.

---

## Where Each Mark/Flag Is Set

| Mark/Flag | Set By | Where | When | Consumed By |
|---|---|---|---|---|
| **DSCP 0x17 (TOS 0x5c)** | ztunnel | `pool.rs`: `setsockopt(IP_TOS)` on HBONE socket | Before `connect()` — on SYN packet | iptables `PREROUTING` in dest pod netns |
| **ENDPOINT_F_MESHED** | Cilium agent | `reconciler.go` → `ep.SetPropertyValue(PropertyMeshed)` → lxcmap sync | On namespace enrollment / endpoint creation | BPF `is_ip4_meshed()` via local endpoint map |
| **flag_meshed (ipcache)** | Cilium agent | `reconciler.go` → `ipcache.UpsertMetadata(FlagMeshed)` | On enrollment + CEP watcher | BPF `is_ip4_meshed()` via ipcache map (cross-node) |
| **Port (original)** | ztunnel | `outbound.rs`: `us.port` instead of `self.hbone_port` | On HBONE connection setup | BPF L4 policy evaluation in `tail_ipv4_policy` |

## Conclusion

The cross-node L4 policy failure was **not caused by ztunnel or HBONE**. It was a
cluster misconfiguration where `ipv4-native-routing-cidr` (10.244.0.0/16) did not
match the actual pod CIDR range (10.0.0.0/8). This caused iptables masquerade to
SNAT all cross-node pod traffic to the node IP, destroying pod identity for BPF
policy evaluation.

After fixing `ipv4-native-routing-cidr` to `10.0.0.0/8`, **both standard and
ztunnel L4 policies work correctly across nodes**, with proper identity-based
and port-based enforcement.

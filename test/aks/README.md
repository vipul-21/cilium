# AKS Conformance Tests in CI

This document describes the AKS conformance tests that run in Cilium CI, when
they run, and how to reproduce them locally.

## CI Workflows

### 1. `Conformance AKS (ci-aks)`

**File:** `.github/workflows/conformance-aks.yaml`

This is the core AKS conformance workflow. It creates an AKS cluster with
`--network-plugin none` (BYOCNI), installs Cilium, and runs the full
`cilium connectivity test` suite.

**Triggers:**

| Trigger | When |
|---|---|
| `schedule` | Every 12 hours (`0 0/12 * * *`) |
| `workflow_call` | Called by parent workflows (see below) |
| `workflow_dispatch` | Manual trigger via GitHub UI |

> **Note:** This workflow does NOT run on pull requests directly. It is
> triggered by parent workflows or on schedule.

**Cilium Configuration (base):**

```
--datapath-mode=aks-byocni
--helm-set=cluster.name=cilium
--helm-set=loadBalancer.l7.backend=envoy
--helm-set=ipv4.enabled=true
--helm-set=ipv6.enabled=true
--helm-set=ipam.operator.clusterPoolIPv4PodCIDRList=192.168.0.0/16
--helm-set=ipam.operator.clusterPoolIPv6PodCIDRList=fd00::/104
```

Pod CIDRs are explicitly set to avoid clashing with AKS default Service CIDRs
(`10.0.0.0/16` and `fd12:3456:789a:1::/108`).

**Optional features (via `extra-args`):**

| Feature | Helm values |
|---|---|
| KPR | `kubeProxyReplacement=true` |
| IPsec | `encryption.enabled=true`, `encryption.type=ipsec` |
| WireGuard | `encryption.enabled=true`, `encryption.type=wireguard` |
| Advanced features | `bpf.masquerade=true`, `enableIPv4Masquerade=true`, `localRedirectPolicy=true`, `egressGateway.enabled=true` |

**Tests executed:**

1. **Sequential tests:** `cilium connectivity test --test "seq-.*"` — tests that
   must run serially.
2. **Concurrent tests:** `cilium connectivity test --test-concurrency=5 --test "!seq-.*"`
   — all remaining tests run with concurrency of 5.

Both use flags from `.github/actions/cli-test-config`:
- `--collect-sysdump-on-failure`
- `--external-target=nginx.external.svc.cluster.local`
- `--external-cidr=<VNet CIDR>`
- `--external-ip=<node1 IP>` / `--external-other-ip=<node2 IP>`
- `--external-target-ca-namespace=external-target-secrets`
- `--external-target-ca-name=custom-ca`
- `--external-target-fake-dns`
- `--hubble=false`
- `--flow-validation=disabled`

**Images waited for:** `cilium-ci`, `operator-azure-ci`, `hubble-relay-ci`,
`cilium-cli-ci`

---

### 2. `Conformance KPR AKS (ci-kpr-aks)`

**File:** `.github/workflows/conformance-kpr-aks.yaml`

Parent workflow that calls `conformance-aks.yaml` three times with different
feature combinations.

**Triggers:**

| Trigger | When |
|---|---|
| `schedule` | Every 12 hours, offset by 4h (`0 4/12 * * *`) |
| `workflow_dispatch` | Manual trigger |

**Sub-jobs:**

| Job | Features | UID |
|---|---|---|
| `conformance-aks-kpr` | KPR + advanced features | 1 |
| `conformance-aks-kpr-ipsec` | KPR + advanced features + IPsec | 2 |
| `conformance-aks-kpr-wireguard` | KPR + advanced features + WireGuard | 3 |

**Images waited for:** `cilium-ci`, `operator-generic-ci`, `hubble-relay-ci`

---

### 3. `Conformance IPsec (ci-ipsec)`

**File:** `.github/workflows/conformance-ipsec.yaml`

Parent workflow that tests IPsec across cloud providers (AKS, EKS, GKE). The
AKS job calls `conformance-aks.yaml` with `extra-args: '{"ipsec": true}'`.

---

## Kubernetes Version Matrix

Defined in `.github/actions/azure/k8s-versions.yaml`:

| Version | Location | Index | Default | Notes |
|---|---|---|---|---|
| 1.31 | westus3 | 1 | | |
| 1.32 | westus2 | 2 | | |
| 1.33 | westus | 3 | | |
| 1.34 | eastus2 | 4 | | |
| 1.35 | eastus | 5 | ✅ | preview |

**Matrix selection:**

- **Scheduled runs / stable branch releases:** Full matrix (all non-disabled
  versions).
- **PR-triggered runs:** Only the `default: true` entry (currently k8s 1.35 in
  eastus).

The matrix is further filtered at runtime: `az aks get-versions` validates each
version is actually available (non-LTS, non-premium) in its target location.
Unavailable versions are silently dropped.

## Cluster Setup

1. **Resource group** created in the matrix-specified Azure location.
2. **AKS cluster** created with:
   - `--network-plugin none` (BYOCNI — Cilium is the only CNI)
   - `--node-count <N+2>` (N workload nodes + 2 external target nodes)
   - `--ip-families ipv4,ipv6` (dual-stack)
   - `--node-vm-size Standard_B2s --node-osdisk-size 30` (cost reduction)
3. **2 nodes labeled** `cilium.io/no-schedule=true` — these host nginx external
   targets and do not run Cilium.
4. **Cilium installed** via `cilium install` with AKS-specific helm values.
5. **Hubble enabled** and Cilium readiness waited for (10m timeout).

## External Targets

Two nginx DaemonSets are deployed on the no-Cilium nodes to serve as external
(non-mesh) endpoints for connectivity tests:

- **Namespace `external`:** nginx on node 1 (hostNetwork, ports 80/443)
- **Namespace `external-other`:** nginx on node 2

A self-signed CA is generated and stored as a Secret (`external-target-secrets/custom-ca`)
for L7 TLS tests. Server certificates include SANs for both target domain names
and node IPs.

## Running Locally

Use the script at `test/aks/run-conformance.sh`:

```bash
# Basic run
./test/aks/run-conformance.sh

# With KPR (matches ci-kpr-aks job 1)
./test/aks/run-conformance.sh --kpr --advanced-features

# With KPR + IPsec (matches ci-kpr-aks job 2)
./test/aks/run-conformance.sh --kpr --ipsec --advanced-features

# With KPR + WireGuard (matches ci-kpr-aks job 3)
./test/aks/run-conformance.sh --kpr --wireguard --advanced-features

# Re-run tests on existing cluster
./test/aks/run-conformance.sh --skip-create --skip-install --cluster-name <name>

# Cleanup
./test/aks/run-conformance.sh --cleanup-only --cluster-name <name>
```

The script:
- Uses a **dedicated kubeconfig** (`~/.kube/aks-conformance-<name>`) to avoid
  touching your default context.
- Auto-detects the latest supported Kubernetes version.
- Creates `node_count + 2` AKS nodes (2 reserved for external targets).
- Runs the same sequential + concurrent connectivity test split as CI.

See `./test/aks/run-conformance.sh --help` for all options.

## Related

- [`COMPARISON-ACN-NIGHTLY.md`](./COMPARISON-ACN-NIGHTLY.md) — how this
  upstream conformance suite compares to the Azure Container Networking
  (ACN) `cilium nightly` pipeline (cluster shape, ConfigMap, and
  test-coverage differences).

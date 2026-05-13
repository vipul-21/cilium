#!/usr/bin/env bash
# Run Cilium AKS conformance tests locally.
# Replicates .github/workflows/conformance-aks.yaml for local developer use.
#
# Usage:
#   ./test/aks/run-conformance.sh [flags]
#
# Examples:
#   # Basic run with defaults
#   ./test/aks/run-conformance.sh
#
#   # With KPR and IPsec
#   ./test/aks/run-conformance.sh --kpr --ipsec
#
#   # Re-run tests on an existing cluster
#   ./test/aks/run-conformance.sh --skip-create --cluster-name my-cluster
#
#   # Just cleanup
#   ./test/aks/run-conformance.sh --cleanup-only --cluster-name my-cluster

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve repo root from script location
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
CLUSTER_NAME="${USER}-aks-conformance"
LOCATION="eastus2euap"
K8S_VERSION=""            # auto-detect if empty
CILIUM_NODE_COUNT=2       # nodes for Cilium workloads; 2 extra added for external targets
VM_SIZE="Standard_D2s_v3"  # override with --vm-size
OS_DISK_SIZE=30
TEST_CONCURRENCY=5

# Feature flags (match CI extra-args)
KPR=false
IPSEC=false
WIREGUARD=false
ADVANCED_FEATURES=false

# Workflow control
SKIP_CREATE=false
SKIP_INSTALL=false
SKIP_EXTERNAL_TARGETS=false
CLEANUP_ONLY=false
CLEANUP_ON_FAILURE=false

# Cilium install overrides
CILIUM_IMAGE_TAG=""       # e.g. "v1.16.0" or a SHA; empty = cilium install default
CILIUM_CHART_DIR=""       # path to local chart; empty = use released chart

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
usage() {
  cat <<EOF
Usage: $(basename "$0") [flags]

Cluster:
  --cluster-name NAME    AKS cluster & resource group name (default: \$USER-aks-conformance)
  --location LOC         Azure region (default: eastus)
  --k8s-version VER      Kubernetes version (default: auto-detect latest)
  --node-count N         Cilium workload nodes; 2 extra are added for external targets (default: 2)
  --vm-size SIZE         VM SKU (default: Standard_D2s_v6)

Features:
  --kpr                  Enable KubeProxyReplacement
  --ipsec                Enable IPsec encryption
  --wireguard            Enable WireGuard encryption
  --advanced-features    Enable masquerade, LRP, egress gateway

Cilium install:
  --image-tag TAG        Cilium image tag (default: CLI default)
  --chart-dir DIR        Path to local Cilium Helm chart

Workflow control:
  --skip-create          Skip cluster creation (reuse existing cluster)
  --skip-install         Skip Cilium installation (reuse existing install)
  --skip-external-targets Skip external target deployment
  --cleanup-only         Only delete the resource group, then exit
  --cleanup-on-failure   Delete resource group if tests fail

  -h, --help             Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cluster-name)       CLUSTER_NAME="$2"; shift 2 ;;
    --location)           LOCATION="$2"; shift 2 ;;
    --k8s-version)        K8S_VERSION="$2"; shift 2 ;;
    --node-count)         CILIUM_NODE_COUNT="$2"; shift 2 ;;
    --vm-size)            VM_SIZE="$2"; shift 2 ;;
    --kpr)                KPR=true; shift ;;
    --ipsec)              IPSEC=true; shift ;;
    --wireguard)          WIREGUARD=true; shift ;;
    --advanced-features)  ADVANCED_FEATURES=true; shift ;;
    --image-tag)          CILIUM_IMAGE_TAG="$2"; shift 2 ;;
    --chart-dir)          CILIUM_CHART_DIR="$2"; shift 2 ;;
    --skip-create)        SKIP_CREATE=true; shift ;;
    --skip-install)       SKIP_INSTALL=true; shift ;;
    --skip-external-targets) SKIP_EXTERNAL_TARGETS=true; shift ;;
    --cleanup-only)       CLEANUP_ONLY=true; shift ;;
    --cleanup-on-failure) CLEANUP_ON_FAILURE=true; shift ;;
    -h|--help)            usage; exit 0 ;;
    *) echo "Unknown flag: $1"; usage; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
check_dep() {
  if ! command -v "$1" &>/dev/null; then
    echo "ERROR: required tool '$1' not found in PATH" >&2
    exit 1
  fi
}

for tool in az kubectl cilium jq openssl envsubst base64; do
  check_dep "$tool"
done

if [[ "$IPSEC" == "true" && "$WIREGUARD" == "true" ]]; then
  echo "ERROR: --ipsec and --wireguard are mutually exclusive" >&2
  exit 1
fi

# Ensure az is logged in
if ! az account show &>/dev/null; then
  echo "ERROR: not logged in to Azure. Run 'az login' first." >&2
  exit 1
fi

TOTAL_NODE_COUNT=$(( CILIUM_NODE_COUNT + 2 ))

# ---------------------------------------------------------------------------
# Isolated kubeconfig — never touch the user's default context
# ---------------------------------------------------------------------------
AKS_KUBECONFIG="${HOME}/.kube/aks-conformance-${CLUSTER_NAME}"
export KUBECONFIG="$AKS_KUBECONFIG"
echo "==> Using dedicated kubeconfig: ${AKS_KUBECONFIG}"

# ---------------------------------------------------------------------------
# Cleanup helper
# ---------------------------------------------------------------------------
do_cleanup() {
  echo "==> Deleting resource group '${CLUSTER_NAME}'..."
  az group delete --name "${CLUSTER_NAME}" --yes --no-wait || true
  echo "    Resource group deletion initiated (async)."
  rm -f "$AKS_KUBECONFIG"
}

if [[ "$CLEANUP_ONLY" == "true" ]]; then
  do_cleanup
  exit 0
fi

cleanup_hint() {
  echo ""
  echo "================================================================"
  echo "To delete the cluster and all resources:"
  echo "  az group delete --name ${CLUSTER_NAME} --yes"
  echo "  rm -f ${AKS_KUBECONFIG}"
  echo ""
  echo "To interact with the cluster:"
  echo "  export KUBECONFIG=${AKS_KUBECONFIG}"
  echo "================================================================"
}

on_failure() {
  echo ""
  echo "!!! Script failed. Cluster '${CLUSTER_NAME}' is still running."
  if [[ "$CLEANUP_ON_FAILURE" == "true" ]]; then
    do_cleanup
  else
    cleanup_hint
  fi
}
trap on_failure ERR

# ---------------------------------------------------------------------------
# Step 1: Determine Kubernetes version
# ---------------------------------------------------------------------------
if [[ -z "$K8S_VERSION" ]]; then
  echo "==> Auto-detecting latest supported Kubernetes version in ${LOCATION}..."
  K8S_VERSION=$(az aks get-versions --location "$LOCATION" \
    --query "max(values[?contains(capabilities.supportPlan,'KubernetesOfficial')].version)" \
    -o tsv)
  if [[ -z "$K8S_VERSION" ]]; then
    echo "ERROR: could not determine a valid Kubernetes version for location ${LOCATION}" >&2
    exit 1
  fi
  echo "    Using Kubernetes ${K8S_VERSION}"
else
  echo "==> Validating Kubernetes version ${K8S_VERSION} in ${LOCATION}..."

  if ! az aks get-versions --location "$LOCATION" \
    --query "values[?contains(capabilities.supportPlan,'KubernetesOfficial')].version" \
    -o tsv | grep -qF "$K8S_VERSION"; then
    echo "ERROR: Kubernetes ${K8S_VERSION} is not available (non-LTS) in ${LOCATION}" >&2
    echo "Available versions:"
    az aks get-versions --location "$LOCATION" \
      --query "values[?contains(capabilities.supportPlan,'KubernetesOfficial')].version" -o tsv
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# Step 2: Create AKS cluster
# ---------------------------------------------------------------------------
if [[ "$SKIP_CREATE" == "false" ]]; then
  echo "==> Creating resource group '${CLUSTER_NAME}' in ${LOCATION}..."
  az group create \
    --name "$CLUSTER_NAME" \
    --location "$LOCATION" \
    --tags "usage=local-conformance owner=${USER}"

  echo "==> Creating AKS cluster (${TOTAL_NODE_COUNT} nodes, k8s ${K8S_VERSION}, ${VM_SIZE})..."
  az aks create \
    --resource-group "$CLUSTER_NAME" \
    --name "$CLUSTER_NAME" \
    --location "$LOCATION" \
    --kubernetes-version "$K8S_VERSION" \
    --network-plugin none \
    --node-count "$TOTAL_NODE_COUNT" \
    --ip-families ipv4,ipv6 \
    --node-vm-size "$VM_SIZE" \
    --node-osdisk-size "$OS_DISK_SIZE" \
    --generate-ssh-keys

  echo "==> Fetching cluster credentials..."
  az aks get-credentials \
    --resource-group "$CLUSTER_NAME" \
    --name "$CLUSTER_NAME" \
    --file "$AKS_KUBECONFIG" \
    --overwrite-existing
else
  echo "==> Skipping cluster creation (--skip-create)"
  # Ensure we have credentials
  if ! kubectl cluster-info &>/dev/null; then
    echo "    Fetching credentials for existing cluster..."
    az aks get-credentials \
      --resource-group "$CLUSTER_NAME" \
      --name "$CLUSTER_NAME" \
      --file "$AKS_KUBECONFIG" \
      --overwrite-existing
  fi
fi

# ---------------------------------------------------------------------------
# Step 3: Label nodes without Cilium
# ---------------------------------------------------------------------------
echo "==> Labeling 2 nodes as cilium.io/no-schedule=true (external targets)..."
mapfile -t ALL_NODES < <(kubectl get nodes -o name)
if [[ ${#ALL_NODES[@]} -lt 3 ]]; then
  echo "ERROR: need at least 3 nodes (got ${#ALL_NODES[@]}). 2 are reserved for external targets." >&2
  exit 1
fi

NO_CILIUM_NODES=("${ALL_NODES[0]}" "${ALL_NODES[1]}")
kubectl label "${NO_CILIUM_NODES[@]}" cilium.io/no-schedule=true --overwrite

echo "    External target nodes: ${NO_CILIUM_NODES[*]}"
echo "    Cilium workload nodes: ${ALL_NODES[*]:2}"

# ---------------------------------------------------------------------------
# Step 4: Install Cilium
# ---------------------------------------------------------------------------
if [[ "$SKIP_INSTALL" == "false" ]]; then
  CILIUM_ARGS=(
    "--datapath-mode=aks-byocni"
    "--helm-set=cluster.name=cilium"
    "--helm-set=loadBalancer.l7.backend=envoy"
    "--helm-set=azure.resourceGroup=${CLUSTER_NAME}"
    "--helm-set=ipv4.enabled=true"
    "--helm-set=ipv6.enabled=true"
    "--helm-set=ipam.operator.clusterPoolIPv4PodCIDRList=192.168.0.0/16"
    "--helm-set=ipam.operator.clusterPoolIPv6PodCIDRList=fd00::/104"
    "--nodes-without-cilium"
  )

  if [[ -n "$CILIUM_IMAGE_TAG" ]]; then
    CILIUM_ARGS+=("--image-tag=${CILIUM_IMAGE_TAG}")
  fi

  if [[ -n "$CILIUM_CHART_DIR" ]]; then
    CILIUM_ARGS+=("--chart-directory=${CILIUM_CHART_DIR}")
  fi

  if [[ "$KPR" == "true" ]]; then
    echo "    KubeProxyReplacement: enabled"
    CILIUM_ARGS+=("--helm-set=kubeProxyReplacement=true")
  fi

  if [[ "$IPSEC" == "true" ]]; then
    echo "    IPsec: enabled"
    cilium encrypt create-key --auth-algo rfc4106-gcm-aes
    CILIUM_ARGS+=("--helm-set=encryption.enabled=true" "--helm-set=encryption.type=ipsec")
  fi

  if [[ "$WIREGUARD" == "true" ]]; then
    echo "    WireGuard: enabled"
    CILIUM_ARGS+=("--helm-set=encryption.enabled=true" "--helm-set=encryption.type=wireguard")
  fi

  if [[ "$ADVANCED_FEATURES" == "true" ]]; then
    echo "    Advanced features: masquerade, LRP, egress gateway"
    CILIUM_ARGS+=(
      "--helm-set=bpf.masquerade=true"
      "--helm-set=enableIPv4Masquerade=true"
      "--helm-set=localRedirectPolicy=true"
      "--helm-set=egressGateway.enabled=true"
    )
  fi

  echo "==> Installing Cilium..."
  cilium install "${CILIUM_ARGS[@]}"

  echo "==> Enabling Hubble..."
  cilium hubble enable

  echo "==> Waiting for Cilium to be ready..."
  cilium status --wait --interactive=false --wait-duration=10m
else
  echo "==> Skipping Cilium installation (--skip-install)"
fi

# ---------------------------------------------------------------------------
# Step 5: Deploy external targets
# ---------------------------------------------------------------------------
if [[ "$SKIP_EXTERNAL_TARGETS" == "false" ]]; then
  echo "==> Deploying external targets (nginx on no-Cilium nodes)..."

  NGINX_TEMPLATE="${REPO_ROOT}/.github/actions/generic-external-targets/nginx-external.yaml"
  if [[ ! -f "$NGINX_TEMPLATE" ]]; then
    echo "ERROR: nginx template not found at ${NGINX_TEMPLATE}" >&2
    exit 1
  fi

  TARGETNAME="nginx.external.svc.cluster.local"
  OTHERTARGETNAME="nginx.external-other.svc.cluster.local"

  # Get the labeled node names (strip "node/" prefix)
  mapfile -t LABELED_NODES < <(kubectl get nodes -l cilium.io/no-schedule=true -o name | sed 's@^node/@@')
  if [[ ${#LABELED_NODES[@]} -lt 2 ]]; then
    echo "ERROR: need at least 2 nodes labeled cilium.io/no-schedule=true (got ${#LABELED_NODES[@]})" >&2
    exit 1
  fi

  # Get IPs from the labeled nodes
  NODE1_IPV4=$(kubectl get node "${LABELED_NODES[0]}" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | tr ' ' '\n' | grep -v ':' | head -1)
  NODE2_IPV4=$(kubectl get node "${LABELED_NODES[1]}" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | tr ' ' '\n' | grep -v ':' | head -1)
  NODE1_IPV6=$(kubectl get node "${LABELED_NODES[0]}" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | tr ' ' '\n' | grep ':' | head -1 || true)
  NODE2_IPV6=$(kubectl get node "${LABELED_NODES[1]}" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | tr ' ' '\n' | grep ':' | head -1 || true)

  WORKDIR=$(mktemp -d)
  trap "rm -rf ${WORKDIR}" EXIT

  # Generate self-signed CA
  openssl genrsa 2048 > "${WORKDIR}/ca-key.pem" 2>/dev/null
  openssl req -new -x509 -nodes -days 365 \
    -key "${WORKDIR}/ca-key.pem" \
    -subj "/O=Cilium/CN=Cilium CA" \
    -out "${WORKDIR}/ca-cert.pem" 2>/dev/null

  # Build SAN entries for the certificate
  SAN="DNS:${OTHERTARGETNAME}, DNS:${TARGETNAME}, DNS:fake.external.first.target, DNS:fake.external.second.target, IP:${NODE1_IPV4}, IP:${NODE2_IPV4}"
  if [[ -n "$NODE1_IPV6" ]]; then SAN+=", IP:${NODE1_IPV6}"; fi
  if [[ -n "$NODE2_IPV6" ]]; then SAN+=", IP:${NODE2_IPV6}"; fi

  # Generate server cert
  openssl req -newkey rsa:2048 -nodes \
    -keyout "${WORKDIR}/external-service.cilium.key" \
    -subj "/CN=${TARGETNAME}" \
    -out "${WORKDIR}/external-service.cilium.req.pem" 2>/dev/null

  cat > "${WORKDIR}/v3.ext" <<EOF
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
keyUsage               = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign
subjectAltName         = ${SAN}
EOF

  openssl x509 -req -days 365 -set_serial 01 \
    -in "${WORKDIR}/external-service.cilium.req.pem" \
    -out "${WORKDIR}/external-service.cilium.crt" \
    -extfile "${WORKDIR}/v3.ext" \
    -CA "${WORKDIR}/ca-cert.pem" \
    -CAkey "${WORKDIR}/ca-key.pem" 2>/dev/null

  # CA secret for L7 tests
  kubectl create ns external-target-secrets --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n external-target-secrets create secret generic custom-ca \
    --from-file=ca.crt="${WORKDIR}/ca-cert.pem" --dry-run=client -o yaml | kubectl apply -f -

  NGINX_CERT_BASE64=$(base64 -w0 "${WORKDIR}/external-service.cilium.crt")
  NGINX_KEY_BASE64=$(base64 -w0 "${WORKDIR}/external-service.cilium.key")

  # Deploy external target 1
  kubectl create ns external --dry-run=client -o yaml | kubectl apply -f -
  NGINX_CERT_BASE64="$NGINX_CERT_BASE64" \
  NGINX_KEY_BASE64="$NGINX_KEY_BASE64" \
  EXTERNAL_NODE="${LABELED_NODES[0]}" \
  envsubst '$NGINX_CERT_BASE64 $NGINX_KEY_BASE64 $EXTERNAL_NODE' < "$NGINX_TEMPLATE" \
    | kubectl -n external apply -f -

  # Deploy external target 2
  kubectl create ns external-other --dry-run=client -o yaml | kubectl apply -f -
  NGINX_CERT_BASE64="$NGINX_CERT_BASE64" \
  NGINX_KEY_BASE64="$NGINX_KEY_BASE64" \
  EXTERNAL_NODE="${LABELED_NODES[1]}" \
  envsubst '$NGINX_CERT_BASE64 $NGINX_KEY_BASE64 $EXTERNAL_NODE' < "$NGINX_TEMPLATE" \
    | kubectl -n external-other apply -f -

  echo "    Waiting for external targets to be ready..."
  kubectl -n external rollout status daemonset nginx --timeout 120s
  kubectl -n external-other rollout status daemonset nginx --timeout 120s
  kubectl -n external wait --for=jsonpath='{.status.numberReady}=1' daemonset/nginx --timeout=60s
  kubectl -n external-other wait --for=jsonpath='{.status.numberReady}=1' daemonset/nginx --timeout=60s

  echo "    External target 1: ${NODE1_IPV4} (${LABELED_NODES[0]})"
  echo "    External target 2: ${NODE2_IPV4} (${LABELED_NODES[1]})"
else
  echo "==> Skipping external target deployment (--skip-external-targets)"
  # Still need the IPs for connectivity tests
  mapfile -t LABELED_NODES < <(kubectl get nodes -l cilium.io/no-schedule=true -o name | sed 's@^node/@@')
  NODE1_IPV4=$(kubectl get node "${LABELED_NODES[0]}" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | tr ' ' '\n' | grep -v ':' | head -1)
  NODE2_IPV4=$(kubectl get node "${LABELED_NODES[1]}" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | tr ' ' '\n' | grep -v ':' | head -1)
  NODE1_IPV6=$(kubectl get node "${LABELED_NODES[0]}" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | tr ' ' '\n' | grep ':' | head -1 || true)
  NODE2_IPV6=$(kubectl get node "${LABELED_NODES[1]}" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | tr ' ' '\n' | grep ':' | head -1 || true)
fi

# ---------------------------------------------------------------------------
# Step 6: Determine VNet CIDR
# ---------------------------------------------------------------------------
echo "==> Determining VNet CIDR for external-cidr flags..."
NODE_RG=$(az aks show \
  --resource-group "$CLUSTER_NAME" \
  --name "$CLUSTER_NAME" \
  --query 'nodeResourceGroup' -o tsv)

ALL_PREFIXES=$(az network vnet list \
  --resource-group "$NODE_RG" \
  --query '[].addressSpace.addressPrefixes[]' -o tsv)

IPV4_CIDR=$(echo "$ALL_PREFIXES" | grep -v ':' | head -1)
IPV6_CIDR=$(echo "$ALL_PREFIXES" | grep ':' | head -1 || true)

if [[ -z "$IPV4_CIDR" ]]; then
  echo "ERROR: could not determine IPv4 VNet CIDR" >&2
  exit 1
fi
echo "    IPv4 CIDR: ${IPV4_CIDR}"
[[ -n "$IPV6_CIDR" ]] && echo "    IPv6 CIDR: ${IPV6_CIDR}"

# ---------------------------------------------------------------------------
# Step 7: Run connectivity tests
# ---------------------------------------------------------------------------
echo ""
echo "================================================================"
echo "  Running Cilium Connectivity Tests"
echo "================================================================"

CONN_ARGS=(
  "--collect-sysdump-on-failure"
  "--external-target=nginx.external.svc.cluster.local"
  "--external-cidr=${IPV4_CIDR}"
  "--external-ip=${NODE1_IPV4}"
  "--external-other-ip=${NODE2_IPV4}"
  "--external-target-ca-namespace=external-target-secrets"
  "--external-target-ca-name=custom-ca"
  "--external-target-fake-dns"
  "--hubble=false"
  "--flow-validation=disabled"
)

if [[ -n "$IPV6_CIDR" ]]; then
  CONN_ARGS+=("--external-cidrv6=${IPV6_CIDR}")
fi
if [[ -n "${NODE1_IPV6:-}" ]]; then
  CONN_ARGS+=("--external-ipv6=${NODE1_IPV6}")
fi
if [[ -n "${NODE2_IPV6:-}" ]]; then
  CONN_ARGS+=("--external-other-ipv6=${NODE2_IPV6}")
fi

echo ""
echo "--- Sequential tests ---"
cilium connectivity test "${CONN_ARGS[@]}" \
  --test "seq-.*"

echo ""
echo "--- Concurrent tests (concurrency=${TEST_CONCURRENCY}) ---"
cilium connectivity test "${CONN_ARGS[@]}" \
  --test-concurrency="$TEST_CONCURRENCY" \
  --test '!seq-.*'

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "================================================================"
echo "  All connectivity tests passed!"
echo "================================================================"
cleanup_hint

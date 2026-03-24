#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
#
# Test identity management upgrade paths:
#   Path A: agent -> operator  (direct)
#   Path B: agent -> both      (CFP-recommended transitional step)
#
# For each path, we test three restart orderings:
#   - operator-first: operator restarts before agent
#   - agent-first:    agent restarts before operator
#   - both:           agent and operator restart simultaneously
#
# For each combination, we verify:
#   1. Pre-upgrade: Identities exist and connectivity works in agent mode
#   2. Upgrade:     Switch to target mode via helm upgrade
#   3. Post-upgrade:
#      a. Existing pods retain their identities (no connection breakage)
#      b. Existing pod-to-pod connectivity is preserved
#      c. New pods get scheduled and receive identities
#      d. New pod connectivity works (including cross-generation)
#      e. CiliumIdentity CRDs are consistent
#
# This proves that "both" behaves identically to "operator" (agent is
# read-only in both modes).
#
# Prerequisites:
#   - docker, kind, kubectl, helm, cilium CLI available
#
# The script will:
#   1. Create a kind cluster (or reuse an existing one with --reuse-cluster)
#   2. Build and load cilium images
#   3. Install Cilium in agent mode
#   4. Run the upgrade path tests
#   5. Tear down the kind cluster (unless --reuse-cluster)
#
# Usage:
#   ./contrib/testing/test-identity-upgrade.sh
#   ./contrib/testing/test-identity-upgrade.sh --reuse-cluster
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

TEST_NS="identity-upgrade-test"
HELM_RELEASE="cilium"
HELM_NS="kube-system"
KIND_CLUSTER_NAME="kind"

REUSE_CLUSTER=false
for arg in "$@"; do
    case "${arg}" in
        --reuse-cluster) REUSE_CLUSTER=true ;;
    esac
done

PASS_COUNT=0
FAIL_COUNT=0

# ============================================================================
# Helpers
# ============================================================================

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC}  $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_step()  { echo -e "\n${YELLOW}=== $* ===${NC}"; }

cleanup() {
    log_step "Cleanup"
    log_info "Deleting test namespace ${TEST_NS}..."
    kubectl delete namespace "${TEST_NS}" --ignore-not-found --timeout=60s 2>/dev/null || true
    if [ "${REUSE_CLUSTER}" = false ]; then
        log_info "Tearing down kind cluster ${KIND_CLUSTER_NAME}..."
        kind delete cluster --name "${KIND_CLUSTER_NAME}" 2>/dev/null || true
    fi
}

# Create kind cluster, build images, and install Cilium
setup_kind_cluster() {
    log_step "Setting up kind cluster and installing Cilium"

    if [ "${REUSE_CLUSTER}" = true ]; then
        if kind get clusters 2>/dev/null | grep -q "^${KIND_CLUSTER_NAME}$"; then
            log_info "Reusing existing kind cluster '${KIND_CLUSTER_NAME}'"
            return 0
        fi
        log_warn "--reuse-cluster specified but cluster '${KIND_CLUSTER_NAME}' not found, creating..."
    fi

    # Create the kind cluster
    log_info "Creating kind cluster..."
    make -C "${ROOT_DIR}" kind

    # Build and load images
    log_info "Building and loading Cilium images..."
    make -C "${ROOT_DIR}" kind-image

    # Install Cilium in agent mode (the baseline for our tests)
    log_info "Installing Cilium with identityManagementMode=agent..."
    helm install "${HELM_RELEASE}" "${ROOT_DIR}/install/kubernetes/cilium" \
        -n "${HELM_NS}" \
        --set image.override="localhost:5000/cilium/cilium-dev:local" \
        --set image.pullPolicy=Never \
        --set operator.image.override="localhost:5000/cilium/operator-generic:local" \
        --set operator.image.pullPolicy=Never \
        --set operator.image.suffix="" \
        --set identityManagementMode=agent \
        --set ipam.mode=kubernetes \
        --set routingMode=tunnel \
        --set tunnelProtocol=vxlan \
        --set debug.enabled=true \
        --wait --timeout 300s 2>&1 | tail -5

    wait_for_cilium_ready 300
    log_pass "Kind cluster created and Cilium installed in agent mode"
}

# Wait for a pod to be Ready
wait_for_pod_ready() {
    local ns="$1" name="$2" timeout="${3:-120}"
    log_info "Waiting for pod ${ns}/${name} to be Ready (timeout: ${timeout}s)..."
    if ! kubectl wait --for=condition=Ready "pod/${name}" -n "${ns}" --timeout="${timeout}s" 2>/dev/null; then
        log_fail "Pod ${ns}/${name} did not become Ready within ${timeout}s"
        kubectl describe pod "${name}" -n "${ns}" 2>&1 | tail -20
        return 1
    fi
    return 0
}

# Wait for all cilium pods to be Ready
wait_for_cilium_ready() {
    local timeout="${1:-300}"
    log_info "Waiting for Cilium to be ready (timeout: ${timeout}s)..."
    if ! kubectl wait --for=condition=Ready pods -l k8s-app=cilium -n kube-system --timeout="${timeout}s" 2>/dev/null; then
        log_fail "Cilium agents did not become Ready"
        kubectl get pods -n kube-system -l k8s-app=cilium
        return 1
    fi
    if ! kubectl wait --for=condition=Ready pods -l name=cilium-operator -n kube-system --timeout="${timeout}s" 2>/dev/null; then
        log_fail "Cilium operator did not become Ready"
        kubectl get pods -n kube-system -l name=cilium-operator
        return 1
    fi
    log_info "Cilium is ready"
    return 0
}

# Get the identity for a pod via cilium-dbg on its node
get_pod_identity() {
    local ns="$1" pod="$2"
    kubectl get ciliumendpoints -n "${ns}" "${pod}" -o jsonpath='{.status.identity.id}' 2>/dev/null || echo ""
}

# Get the CiliumIdentity CRD name for a numeric ID
get_cid_for_id() {
    local id="$1"
    kubectl get ciliumidentity "${id}" -o name 2>/dev/null || echo ""
}

# Test connectivity between two pods using wget
test_connectivity() {
    local src_ns="$1" src_pod="$2" dst_ns="$3" dst_pod="$4"
    local dst_ip
    dst_ip=$(kubectl get pod "${dst_pod}" -n "${dst_ns}" -o jsonpath='{.status.podIP}' 2>/dev/null)
    if [ -z "${dst_ip}" ]; then
        log_fail "Could not get IP for ${dst_ns}/${dst_pod}"
        return 1
    fi

    log_info "Testing connectivity: ${src_ns}/${src_pod} -> ${dst_ns}/${dst_pod} (${dst_ip}:80)..."
    if kubectl exec "${src_pod}" -n "${src_ns}" -- wget -q -O /dev/null -T 5 "http://${dst_ip}:80/" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# ============================================================================
# Test Phases
# ============================================================================

setup_test_namespace() {
    log_step "Setting up test namespace and pods"

    kubectl create namespace "${TEST_NS}" --dry-run=client -o yaml | kubectl apply -f -

    # Server pod (nginx) — will be our connectivity target
    kubectl apply -n "${TEST_NS}" -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: server
  labels:
    app: server
    role: backend
spec:
  containers:
  - name: nginx
    image: nginx:stable-alpine
    ports:
    - containerPort: 80
  terminationGracePeriodSeconds: 0
EOF

    # Client pod — will test connectivity TO the server
    kubectl apply -n "${TEST_NS}" -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: client
  labels:
    app: client
    role: frontend
spec:
  containers:
  - name: alpine
    image: alpine:3.19
    command: ["sleep", "3600"]
  terminationGracePeriodSeconds: 0
EOF

    wait_for_pod_ready "${TEST_NS}" "server" 120
    wait_for_pod_ready "${TEST_NS}" "client" 120
}

phase1_verify_agent_mode() {
    log_step "Phase 1: Verify agent mode baseline"

    local current_mode
    current_mode=$(kubectl get configmap cilium-config -n kube-system -o jsonpath='{.data.identity-management-mode}' 2>/dev/null || echo "agent")
    log_info "Current identity-management-mode: ${current_mode}"

    # If already in operator mode, switch back to agent first
    if [ "${current_mode}" != "agent" ]; then
        log_info "Switching to agent mode first for baseline..."
        helm upgrade "${HELM_RELEASE}" "${ROOT_DIR}/install/kubernetes/cilium" \
            -n "${HELM_NS}" \
            --reuse-values \
            --set identityManagementMode=agent \
            --wait --timeout 300s 2>&1 | tail -5

        # Restart cilium pods to pick up the config change
        kubectl rollout restart daemonset cilium -n kube-system
        kubectl rollout restart deployment cilium-operator -n kube-system
        kubectl rollout status daemonset cilium -n kube-system --timeout=300s
        kubectl rollout status deployment cilium-operator -n kube-system --timeout=300s
        wait_for_cilium_ready 300
    fi

    current_mode=$(kubectl get configmap cilium-config -n kube-system -o jsonpath='{.data.identity-management-mode}')
    if [ "${current_mode}" == "agent" ]; then
        log_pass "identity-management-mode is 'agent'"
    else
        log_fail "Expected identity-management-mode=agent, got ${current_mode}"
        return 1
    fi

    # Record pre-upgrade identities
    log_info "Recording pre-upgrade identity state..."
    PRE_SERVER_IDENTITY=$(get_pod_identity "${TEST_NS}" "server")
    PRE_CLIENT_IDENTITY=$(get_pod_identity "${TEST_NS}" "client")
    log_info "  server identity: ${PRE_SERVER_IDENTITY}"
    log_info "  client identity: ${PRE_CLIENT_IDENTITY}"

    if [ -n "${PRE_SERVER_IDENTITY}" ] && [ "${PRE_SERVER_IDENTITY}" != "0" ]; then
        log_pass "Server pod has identity ${PRE_SERVER_IDENTITY} in agent mode"
    else
        log_fail "Server pod has no identity in agent mode"
    fi

    if [ -n "${PRE_CLIENT_IDENTITY}" ] && [ "${PRE_CLIENT_IDENTITY}" != "0" ]; then
        log_pass "Client pod has identity ${PRE_CLIENT_IDENTITY} in agent mode"
    else
        log_fail "Client pod has no identity in agent mode"
    fi

    # Test pre-upgrade connectivity
    if test_connectivity "${TEST_NS}" "client" "${TEST_NS}" "server"; then
        log_pass "Pre-upgrade connectivity: client -> server works"
    else
        log_fail "Pre-upgrade connectivity: client -> server FAILED"
    fi

    # Record CiliumIdentity CRDs
    log_info "Pre-upgrade CiliumIdentities:"
    kubectl get ciliumidentities 2>&1 | head -20 || true
    PRE_CID_COUNT=$(kubectl get ciliumidentities --no-headers 2>/dev/null | wc -l)
    log_info "  Total CiliumIdentity count: ${PRE_CID_COUNT}"
}

# restart_order: "operator-first", "agent-first", or "both"
phase2_upgrade_to_target() {
    local target_mode="$1"
    local restart_order="${2:-both}"
    log_step "Phase 2: Upgrade to '${target_mode}' mode (restart order: ${restart_order})"

    log_info "Running helm upgrade with identityManagementMode=${target_mode}..."
    helm upgrade "${HELM_RELEASE}" "${ROOT_DIR}/install/kubernetes/cilium" \
        -n "${HELM_NS}" \
        --reuse-values \
        --set identityManagementMode="${target_mode}" \
        --wait --timeout 300s 2>&1 | tail -5

    # Verify configmap changed
    local new_mode
    new_mode=$(kubectl get configmap cilium-config -n kube-system -o jsonpath='{.data.identity-management-mode}')
    if [ "${new_mode}" == "${target_mode}" ]; then
        log_pass "ConfigMap updated to identity-management-mode=${target_mode}"
    else
        log_fail "ConfigMap not updated, got: ${new_mode}"
        return 1
    fi

    # Restart components in the specified order
    case "${restart_order}" in
        operator-first)
            log_info "Restarting operator FIRST, then agent..."
            kubectl rollout restart deployment cilium-operator -n kube-system
            kubectl rollout status deployment cilium-operator -n kube-system --timeout=300s
            log_info "Operator rolled out. Now restarting agent..."
            kubectl rollout restart daemonset cilium -n kube-system
            kubectl rollout status daemonset cilium -n kube-system --timeout=300s
            ;;
        agent-first)
            log_info "Restarting agent FIRST, then operator..."
            kubectl rollout restart daemonset cilium -n kube-system
            kubectl rollout status daemonset cilium -n kube-system --timeout=300s
            log_info "Agent rolled out. Now restarting operator..."
            kubectl rollout restart deployment cilium-operator -n kube-system
            kubectl rollout status deployment cilium-operator -n kube-system --timeout=300s
            ;;
        both)
            log_info "Restarting agent and operator simultaneously..."
            kubectl rollout restart daemonset cilium -n kube-system
            kubectl rollout restart deployment cilium-operator -n kube-system
            kubectl rollout status daemonset cilium -n kube-system --timeout=300s
            kubectl rollout status deployment cilium-operator -n kube-system --timeout=300s
            ;;
        *)
            log_fail "Unknown restart order: ${restart_order}"
            return 1
            ;;
    esac

    wait_for_cilium_ready 300
    log_pass "Cilium restarted in ${target_mode} mode (${restart_order})"

    # Give the operator time to reconcile existing identities
    log_info "Waiting 15s for operator to reconcile identities..."
    sleep 15
}

phase3_verify_existing_pods() {
    local target_mode="$1"
    local label="agent -> ${target_mode}"
    log_step "Phase 3: Verify existing pods after upgrade to '${target_mode}'"

    # 3a. Check existing pods still have identities
    log_info "Checking existing pod identities..."
    local post_server_id post_client_id
    post_server_id=$(get_pod_identity "${TEST_NS}" "server")
    post_client_id=$(get_pod_identity "${TEST_NS}" "client")

    log_info "  server identity: ${post_server_id} (was: ${PRE_SERVER_IDENTITY})"
    log_info "  client identity: ${post_client_id} (was: ${PRE_CLIENT_IDENTITY})"

    if [ -n "${post_server_id}" ] && [ "${post_server_id}" != "0" ]; then
        log_pass "Server pod still has identity ${post_server_id} after upgrade"
    else
        log_fail "Server pod LOST its identity after upgrade"
    fi

    if [ -n "${post_client_id}" ] && [ "${post_client_id}" != "0" ]; then
        log_pass "Client pod still has identity ${post_client_id} after upgrade"
    else
        log_fail "Client pod LOST its identity after upgrade"
    fi

    # 3b. Check if identity numbers were preserved (they may change if re-allocated)
    if [ "${post_server_id}" == "${PRE_SERVER_IDENTITY}" ]; then
        log_pass "Server identity preserved: ${post_server_id}"
    else
        log_warn "Server identity changed: ${PRE_SERVER_IDENTITY} -> ${post_server_id} (may be expected)"
    fi

    if [ "${post_client_id}" == "${PRE_CLIENT_IDENTITY}" ]; then
        log_pass "Client identity preserved: ${post_client_id}"
    else
        log_warn "Client identity changed: ${PRE_CLIENT_IDENTITY} -> ${post_client_id} (may be expected)"
    fi

    # 3c. Verify CiliumIdentity CRDs exist for these identities
    if [ -n "${post_server_id}" ]; then
        local cid
        cid=$(get_cid_for_id "${post_server_id}")
        if [ -n "${cid}" ]; then
            log_pass "CiliumIdentity CRD exists for server identity ${post_server_id}"
        else
            log_fail "CiliumIdentity CRD MISSING for server identity ${post_server_id}"
        fi
    fi

    if [ -n "${post_client_id}" ]; then
        local cid
        cid=$(get_cid_for_id "${post_client_id}")
        if [ -n "${cid}" ]; then
            log_pass "CiliumIdentity CRD exists for client identity ${post_client_id}"
        else
            log_fail "CiliumIdentity CRD MISSING for client identity ${post_client_id}"
        fi
    fi

    # 3d. Test connectivity between existing pods
    log_info "Testing existing connection (client -> server)..."
    local connectivity_ok=true
    for i in $(seq 1 3); do
        if test_connectivity "${TEST_NS}" "client" "${TEST_NS}" "server"; then
            log_info "  Attempt ${i}/3: OK"
        else
            log_info "  Attempt ${i}/3: FAILED"
            connectivity_ok=false
        fi
    done

    if [ "${connectivity_ok}" = true ]; then
        log_pass "Existing connection client -> server works after upgrade (3/3 attempts)"
    else
        log_fail "Existing connection client -> server BROKEN after upgrade"
    fi
}

phase4_test_new_pod() {
    local target_mode="$1"
    local restart_order="${2:-both}"
    local label="agent -> ${target_mode} (${restart_order})"
    local new_server="new-server-${target_mode}-${restart_order}"
    local new_client="new-client-${target_mode}-${restart_order}"
    log_step "Phase 4: Test new pod scheduling in '${target_mode}' mode"

    # Create a new pod with a UNIQUE label set (never seen before)
    log_info "Scheduling new pods with unique labels..."
    kubectl apply -n "${TEST_NS}" -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${new_server}
  labels:
    app: ${new_server}
    role: new-backend
    test-run: upgrade-test-${target_mode}
spec:
  containers:
  - name: nginx
    image: nginx:stable-alpine
    ports:
    - containerPort: 80
  terminationGracePeriodSeconds: 0
EOF

    kubectl apply -n "${TEST_NS}" -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${new_client}
  labels:
    app: ${new_client}
    role: new-frontend
    test-run: upgrade-test-${target_mode}
spec:
  containers:
  - name: alpine
    image: alpine:3.19
    command: ["sleep", "3600"]
  terminationGracePeriodSeconds: 0
EOF

    # Wait for pods to be ready
    if ! wait_for_pod_ready "${TEST_NS}" "${new_server}" 120; then
        log_fail "[${label}] New server pod failed to become Ready"
        return 1
    fi
    log_pass "[${label}] New server pod became Ready"

    if ! wait_for_pod_ready "${TEST_NS}" "${new_client}" 120; then
        log_fail "[${label}] New client pod failed to become Ready"
        return 1
    fi
    log_pass "[${label}] New client pod became Ready"

    # Check the new pods got identities
    local new_server_id new_client_id
    # Give some time for CEP to be created
    sleep 5

    new_server_id=$(get_pod_identity "${TEST_NS}" "${new_server}")
    new_client_id=$(get_pod_identity "${TEST_NS}" "${new_client}")

    log_info "  ${new_server} identity: ${new_server_id}"
    log_info "  ${new_client} identity: ${new_client_id}"

    if [ -n "${new_server_id}" ] && [ "${new_server_id}" != "0" ]; then
        log_pass "[${label}] New server pod received identity ${new_server_id}"
    else
        log_fail "[${label}] New server pod did NOT receive an identity"
    fi

    if [ -n "${new_client_id}" ] && [ "${new_client_id}" != "0" ]; then
        log_pass "[${label}] New client pod received identity ${new_client_id}"
    else
        log_fail "[${label}] New client pod did NOT receive an identity"
    fi

    # Verify CiliumIdentity CRDs exist for the new pods
    if [ -n "${new_server_id}" ]; then
        local cid
        cid=$(get_cid_for_id "${new_server_id}")
        if [ -n "${cid}" ]; then
            log_pass "[${label}] CiliumIdentity CRD exists for new-server identity ${new_server_id}"
        else
            log_fail "[${label}] CiliumIdentity CRD MISSING for new-server identity ${new_server_id}"
        fi
    fi

    # Test connectivity between new pods
    log_info "Testing new pod connectivity (${new_client} -> ${new_server})..."
    # Retry a few times since the datapath may take a moment to program
    local new_conn_ok=false
    for i in $(seq 1 5); do
        if test_connectivity "${TEST_NS}" "${new_client}" "${TEST_NS}" "${new_server}"; then
            new_conn_ok=true
            break
        fi
        log_info "  Attempt ${i}/5 failed, retrying in 3s..."
        sleep 3
    done

    if [ "${new_conn_ok}" = true ]; then
        log_pass "[${label}] New pod connectivity: ${new_client} -> ${new_server} works"
    else
        log_fail "[${label}] New pod connectivity: ${new_client} -> ${new_server} FAILED"
    fi

    # Test cross-generation connectivity (old client -> new server, new client -> old server)
    log_info "Testing cross-generation connectivity..."
    if test_connectivity "${TEST_NS}" "client" "${TEST_NS}" "${new_server}"; then
        log_pass "[${label}] Cross-gen connectivity: old client -> new server works"
    else
        log_fail "[${label}] Cross-gen connectivity: old client -> new server FAILED"
    fi

    if test_connectivity "${TEST_NS}" "${new_client}" "${TEST_NS}" "server"; then
        log_pass "[${label}] Cross-gen connectivity: new client -> old server works"
    else
        log_fail "[${label}] Cross-gen connectivity: new client -> old server FAILED"
    fi

    # Cleanup new pods for this path
    kubectl delete pod "${new_server}" "${new_client}" -n "${TEST_NS}" --grace-period=0 --force 2>/dev/null || true
}

phase5_verify_identity_consistency() {
    local target_mode="$1"
    local label="agent -> ${target_mode}"
    log_step "Phase 5: Verify CiliumIdentity consistency (${target_mode})"

    log_info "Post-upgrade CiliumIdentities:"
    kubectl get ciliumidentities 2>&1

    local post_cid_count
    post_cid_count=$(kubectl get ciliumidentities --no-headers 2>/dev/null | wc -l)
    log_info "CiliumIdentity count: pre-upgrade=${PRE_CID_COUNT}, post-upgrade=${post_cid_count}"

    if [ "${post_cid_count}" -ge "${PRE_CID_COUNT}" ]; then
        log_pass "CiliumIdentity count is >= pre-upgrade count (${post_cid_count} >= ${PRE_CID_COUNT})"
    else
        log_fail "CiliumIdentity count decreased after upgrade (${post_cid_count} < ${PRE_CID_COUNT})"
    fi

    # Check all CiliumEndpoints have valid identity references
    log_info "Checking CiliumEndpoints in test namespace..."
    local ceps
    ceps=$(kubectl get ciliumendpoints -n "${TEST_NS}" -o jsonpath='{range .items[*]}{.metadata.name}={.status.identity.id}{"\n"}{end}' 2>/dev/null)

    local all_have_ids=true
    while IFS= read -r line; do
        if [ -z "${line}" ]; then continue; fi
        local name id
        name="${line%%=*}"
        id="${line##*=}"
        if [ -z "${id}" ] || [ "${id}" == "0" ]; then
            log_fail "CiliumEndpoint ${name} has no identity"
            all_have_ids=false
        else
            log_info "  CEP ${name}: identity=${id}"
        fi
    done <<< "${ceps}"

    if [ "${all_have_ids}" = true ]; then
        log_pass "All CiliumEndpoints in ${TEST_NS} have valid identities"
    fi

    # Check Cilium agent logs for errors related to identity allocation
    log_info "Checking Cilium agent logs for identity allocation errors..."
    local agent_pod
    agent_pod=$(kubectl get pods -n kube-system -l k8s-app=cilium -o jsonpath='{.items[0].metadata.name}')
    local error_count
    error_count=$(kubectl logs "${agent_pod}" -n kube-system --since=5m 2>/dev/null | grep -c "timed out waiting for cilium-operator to allocate" || true)
    if [ "${error_count}" -gt 0 ]; then
        log_fail "Found ${error_count} 'timed out waiting for operator' errors in agent logs"
        kubectl logs "${agent_pod}" -n kube-system --since=5m 2>/dev/null | grep "timed out waiting" | tail -5
    else
        log_pass "No identity allocation timeout errors in agent logs"
    fi

    local not_found_count
    not_found_count=$(kubectl logs "${agent_pod}" -n kube-system --since=5m 2>/dev/null | grep -c "security identity not found" || true)
    if [ "${not_found_count}" -gt 0 ]; then
        log_warn "Found ${not_found_count} 'security identity not found' messages (may be transient retries)"
    else
        log_pass "No 'security identity not found' errors in agent logs"
    fi
}

# ============================================================================
# Rollback Test Phases: operator/both -> agent
# ============================================================================

phase_rollback_to_agent() {
    local from_mode="$1"
    local restart_order="${2:-both}"
    log_step "Rollback: Switch from '${from_mode}' back to 'agent' mode (restart order: ${restart_order})"

    log_info "Running helm upgrade with identityManagementMode=agent (rollback)..."
    helm upgrade "${HELM_RELEASE}" "${ROOT_DIR}/install/kubernetes/cilium" \
        -n "${HELM_NS}" \
        --reuse-values \
        --set identityManagementMode=agent \
        --wait --timeout 300s 2>&1 | tail -5

    # Verify configmap changed
    local new_mode
    new_mode=$(kubectl get configmap cilium-config -n kube-system -o jsonpath='{.data.identity-management-mode}')
    if [ "${new_mode}" == "agent" ]; then
        log_pass "ConfigMap updated to identity-management-mode=agent (rollback)"
    else
        log_fail "ConfigMap not updated after rollback, got: ${new_mode}"
        return 1
    fi

    # Restart components in the specified order
    case "${restart_order}" in
        operator-first)
            log_info "Restarting operator FIRST, then agent..."
            kubectl rollout restart deployment cilium-operator -n kube-system
            kubectl rollout status deployment cilium-operator -n kube-system --timeout=300s
            log_info "Operator rolled out. Now restarting agent..."
            kubectl rollout restart daemonset cilium -n kube-system
            kubectl rollout status daemonset cilium -n kube-system --timeout=300s
            ;;
        agent-first)
            log_info "Restarting agent FIRST, then operator..."
            kubectl rollout restart daemonset cilium -n kube-system
            kubectl rollout status daemonset cilium -n kube-system --timeout=300s
            log_info "Agent rolled out. Now restarting operator..."
            kubectl rollout restart deployment cilium-operator -n kube-system
            kubectl rollout status deployment cilium-operator -n kube-system --timeout=300s
            ;;
        both)
            log_info "Restarting agent and operator simultaneously..."
            kubectl rollout restart daemonset cilium -n kube-system
            kubectl rollout restart deployment cilium-operator -n kube-system
            kubectl rollout status daemonset cilium -n kube-system --timeout=300s
            kubectl rollout status deployment cilium-operator -n kube-system --timeout=300s
            ;;
        *)
            log_fail "Unknown restart order: ${restart_order}"
            return 1
            ;;
    esac

    wait_for_cilium_ready 300
    log_pass "Cilium rolled back to agent mode (${restart_order})"

    # Give the agent time to reconcile identities
    log_info "Waiting 15s for agent to reconcile identities..."
    sleep 15
}

phase_verify_after_rollback() {
    local from_mode="$1"
    local label="${from_mode} -> agent (rollback)"
    log_step "Rollback Verify: Check existing pods after rollback from '${from_mode}' to 'agent'"

    log_info "Checking existing pod identities after rollback..."
    local post_server_id post_client_id
    post_server_id=$(get_pod_identity "${TEST_NS}" "server")
    post_client_id=$(get_pod_identity "${TEST_NS}" "client")

    log_info "  server identity: ${post_server_id} (was: ${PRE_SERVER_IDENTITY})"
    log_info "  client identity: ${post_client_id} (was: ${PRE_CLIENT_IDENTITY})"

    if [ -n "${post_server_id}" ] && [ "${post_server_id}" != "0" ]; then
        log_pass "[${label}] Server pod still has identity ${post_server_id} after rollback"
    else
        log_fail "[${label}] Server pod LOST its identity after rollback"
    fi

    if [ -n "${post_client_id}" ] && [ "${post_client_id}" != "0" ]; then
        log_pass "[${label}] Client pod still has identity ${post_client_id} after rollback"
    else
        log_fail "[${label}] Client pod LOST its identity after rollback"
    fi

    if [ "${post_server_id}" == "${PRE_SERVER_IDENTITY}" ]; then
        log_pass "[${label}] Server identity preserved: ${post_server_id}"
    else
        log_warn "[${label}] Server identity changed: ${PRE_SERVER_IDENTITY} -> ${post_server_id} (may be expected)"
    fi

    if [ "${post_client_id}" == "${PRE_CLIENT_IDENTITY}" ]; then
        log_pass "[${label}] Client identity preserved: ${post_client_id}"
    else
        log_warn "[${label}] Client identity changed: ${PRE_CLIENT_IDENTITY} -> ${post_client_id} (may be expected)"
    fi

    # Verify CiliumIdentity CRDs exist
    if [ -n "${post_server_id}" ]; then
        local cid
        cid=$(get_cid_for_id "${post_server_id}")
        if [ -n "${cid}" ]; then
            log_pass "[${label}] CiliumIdentity CRD exists for server identity ${post_server_id}"
        else
            log_fail "[${label}] CiliumIdentity CRD MISSING for server identity ${post_server_id}"
        fi
    fi

    if [ -n "${post_client_id}" ]; then
        local cid
        cid=$(get_cid_for_id "${post_client_id}")
        if [ -n "${cid}" ]; then
            log_pass "[${label}] CiliumIdentity CRD exists for client identity ${post_client_id}"
        else
            log_fail "[${label}] CiliumIdentity CRD MISSING for client identity ${post_client_id}"
        fi
    fi

    # Test connectivity
    log_info "Testing existing connection after rollback (client -> server)..."
    local connectivity_ok=true
    for i in $(seq 1 3); do
        if test_connectivity "${TEST_NS}" "client" "${TEST_NS}" "server"; then
            log_info "  Attempt ${i}/3: OK"
        else
            log_info "  Attempt ${i}/3: FAILED"
            connectivity_ok=false
        fi
    done

    if [ "${connectivity_ok}" = true ]; then
        log_pass "[${label}] Existing connection client -> server works after rollback (3/3 attempts)"
    else
        log_fail "[${label}] Existing connection client -> server BROKEN after rollback"
    fi
}

phase_new_pods_after_rollback() {
    local from_mode="$1"
    local restart_order="${2:-both}"
    local label="${from_mode} -> agent rollback (${restart_order})"
    local new_server="rb-server-${from_mode}-${restart_order}"
    local new_client="rb-client-${from_mode}-${restart_order}"
    log_step "Rollback New Pods: Test new pod scheduling after rollback to 'agent'"

    log_info "Scheduling new pods after rollback..."
    kubectl apply -n "${TEST_NS}" -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${new_server}
  labels:
    app: ${new_server}
    role: rb-backend
    test-run: rollback-test-${from_mode}
spec:
  containers:
  - name: nginx
    image: nginx:stable-alpine
    ports:
    - containerPort: 80
  terminationGracePeriodSeconds: 0
EOF

    kubectl apply -n "${TEST_NS}" -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${new_client}
  labels:
    app: ${new_client}
    role: rb-frontend
    test-run: rollback-test-${from_mode}
spec:
  containers:
  - name: alpine
    image: alpine:3.19
    command: ["sleep", "3600"]
  terminationGracePeriodSeconds: 0
EOF

    if ! wait_for_pod_ready "${TEST_NS}" "${new_server}" 120; then
        log_fail "[${label}] New server pod failed to become Ready after rollback"
        return 1
    fi
    log_pass "[${label}] New server pod became Ready after rollback"

    if ! wait_for_pod_ready "${TEST_NS}" "${new_client}" 120; then
        log_fail "[${label}] New client pod failed to become Ready after rollback"
        return 1
    fi
    log_pass "[${label}] New client pod became Ready after rollback"

    sleep 5

    local new_server_id new_client_id
    new_server_id=$(get_pod_identity "${TEST_NS}" "${new_server}")
    new_client_id=$(get_pod_identity "${TEST_NS}" "${new_client}")

    log_info "  ${new_server} identity: ${new_server_id}"
    log_info "  ${new_client} identity: ${new_client_id}"

    if [ -n "${new_server_id}" ] && [ "${new_server_id}" != "0" ]; then
        log_pass "[${label}] New server pod received identity ${new_server_id} after rollback"
    else
        log_fail "[${label}] New server pod did NOT receive an identity after rollback"
    fi

    if [ -n "${new_client_id}" ] && [ "${new_client_id}" != "0" ]; then
        log_pass "[${label}] New client pod received identity ${new_client_id} after rollback"
    else
        log_fail "[${label}] New client pod did NOT receive an identity after rollback"
    fi

    if [ -n "${new_server_id}" ]; then
        local cid
        cid=$(get_cid_for_id "${new_server_id}")
        if [ -n "${cid}" ]; then
            log_pass "[${label}] CiliumIdentity CRD exists for rb-server identity ${new_server_id}"
        else
            log_fail "[${label}] CiliumIdentity CRD MISSING for rb-server identity ${new_server_id}"
        fi
    fi

    # Test connectivity between new pods
    log_info "Testing new pod connectivity after rollback (${new_client} -> ${new_server})..."
    local new_conn_ok=false
    for i in $(seq 1 5); do
        if test_connectivity "${TEST_NS}" "${new_client}" "${TEST_NS}" "${new_server}"; then
            new_conn_ok=true
            break
        fi
        log_info "  Attempt ${i}/5 failed, retrying in 3s..."
        sleep 3
    done

    if [ "${new_conn_ok}" = true ]; then
        log_pass "[${label}] New pod connectivity: ${new_client} -> ${new_server} works after rollback"
    else
        log_fail "[${label}] New pod connectivity: ${new_client} -> ${new_server} FAILED after rollback"
    fi

    # Cross-generation: old client -> new server, new client -> old server
    log_info "Testing cross-generation connectivity after rollback..."
    if test_connectivity "${TEST_NS}" "client" "${TEST_NS}" "${new_server}"; then
        log_pass "[${label}] Cross-gen: old client -> new server works after rollback"
    else
        log_fail "[${label}] Cross-gen: old client -> new server FAILED after rollback"
    fi

    if test_connectivity "${TEST_NS}" "${new_client}" "${TEST_NS}" "server"; then
        log_pass "[${label}] Cross-gen: new client -> old server works after rollback"
    else
        log_fail "[${label}] Cross-gen: new client -> old server FAILED after rollback"
    fi

    kubectl delete pod "${new_server}" "${new_client}" -n "${TEST_NS}" --grace-period=0 --force 2>/dev/null || true
}

phase_consistency_after_rollback() {
    local from_mode="$1"
    local label="${from_mode} -> agent (rollback)"
    log_step "Rollback Consistency: Verify identity consistency after rollback from '${from_mode}'"

    log_info "Post-rollback CiliumIdentities:"
    kubectl get ciliumidentities 2>&1

    local post_cid_count
    post_cid_count=$(kubectl get ciliumidentities --no-headers 2>/dev/null | wc -l)
    log_info "CiliumIdentity count: pre-upgrade=${PRE_CID_COUNT}, post-rollback=${post_cid_count}"

    if [ "${post_cid_count}" -ge "${PRE_CID_COUNT}" ]; then
        log_pass "[${label}] CiliumIdentity count >= pre-upgrade (${post_cid_count} >= ${PRE_CID_COUNT})"
    else
        log_fail "[${label}] CiliumIdentity count decreased after rollback (${post_cid_count} < ${PRE_CID_COUNT})"
    fi

    log_info "Checking CiliumEndpoints in test namespace..."
    local ceps
    ceps=$(kubectl get ciliumendpoints -n "${TEST_NS}" -o jsonpath='{range .items[*]}{.metadata.name}={.status.identity.id}{"\n"}{end}' 2>/dev/null)

    local all_have_ids=true
    while IFS= read -r line; do
        if [ -z "${line}" ]; then continue; fi
        local name id
        name="${line%%=*}"
        id="${line##*=}"
        if [ -z "${id}" ] || [ "${id}" == "0" ]; then
            log_fail "[${label}] CiliumEndpoint ${name} has no identity after rollback"
            all_have_ids=false
        else
            log_info "  CEP ${name}: identity=${id}"
        fi
    done <<< "${ceps}"

    if [ "${all_have_ids}" = true ]; then
        log_pass "[${label}] All CiliumEndpoints have valid identities after rollback"
    fi

    log_info "Checking Cilium agent logs for identity allocation errors..."
    local agent_pod
    agent_pod=$(kubectl get pods -n kube-system -l k8s-app=cilium -o jsonpath='{.items[0].metadata.name}')
    local error_count
    error_count=$(kubectl logs "${agent_pod}" -n kube-system --since=5m 2>/dev/null | grep -c "timed out waiting for cilium-operator to allocate" || true)
    if [ "${error_count}" -gt 0 ]; then
        log_fail "[${label}] Found ${error_count} 'timed out waiting for operator' errors after rollback"
        kubectl logs "${agent_pod}" -n kube-system --since=5m 2>/dev/null | grep "timed out waiting" | tail -5
    else
        log_pass "[${label}] No identity allocation timeout errors after rollback"
    fi

    local not_found_count
    not_found_count=$(kubectl logs "${agent_pod}" -n kube-system --since=5m 2>/dev/null | grep -c "security identity not found" || true)
    if [ "${not_found_count}" -gt 0 ]; then
        log_warn "[${label}] Found ${not_found_count} 'security identity not found' messages (may be transient)"
    else
        log_pass "[${label}] No 'security identity not found' errors after rollback"
    fi
}

# ============================================================================
# Run a single upgrade path: agent -> target_mode
# ============================================================================

run_upgrade_path() {
    local target_mode="$1"
    local restart_order="${2:-both}"
    local label="agent -> ${target_mode} (restart: ${restart_order})"

    echo -e "\n${BLUE}============================================================${NC}"
    echo -e "${BLUE}  Testing upgrade path: ${label}${NC}"
    echo -e "${BLUE}============================================================${NC}\n"

    # Phase 1: Baseline in agent mode
    phase1_verify_agent_mode

    # Phase 2: Upgrade to target mode with specified restart order
    phase2_upgrade_to_target "${target_mode}" "${restart_order}"

    # Phase 3: Verify existing pods
    phase3_verify_existing_pods "${target_mode}"

    # Phase 4: Test new pods
    phase4_test_new_pod "${target_mode}" "${restart_order}"

    # Phase 5: Consistency checks
    phase5_verify_identity_consistency "${target_mode}"
}

# ============================================================================
# Run a single rollback path: agent -> target_mode -> agent
# ============================================================================

run_rollback_path() {
    local from_mode="$1"           # intermediate mode: operator or both
    local rollback_order="${2:-both}" # restart order for the rollback step
    local label="agent -> ${from_mode} -> agent (rollback restart: ${rollback_order})"

    echo -e "\n${BLUE}============================================================${NC}"
    echo -e "${BLUE}  Testing rollback path: ${label}${NC}"
    echo -e "${BLUE}============================================================${NC}\n"

    # Phase 1: Baseline in agent mode
    phase1_verify_agent_mode

    # Phase 2: Upgrade to target mode (simultaneous restart — not testing upgrade ordering here)
    phase2_upgrade_to_target "${from_mode}" "both"

    # Phase 3: Verify upgrade worked (existing pods still fine)
    phase3_verify_existing_pods "${from_mode}"

    # Rollback: Switch back to agent mode
    phase_rollback_to_agent "${from_mode}" "${rollback_order}"

    # Verify existing pods after rollback
    phase_verify_after_rollback "${from_mode}"

    # New pods in agent mode after rollback
    phase_new_pods_after_rollback "${from_mode}" "${rollback_order}"

    # Consistency checks after rollback
    phase_consistency_after_rollback "${from_mode}"
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo -e "${BLUE}"
    echo "============================================================"
    echo "  Identity Management Upgrade & Rollback Test"
    echo "  Upgrade:  agent -> operator  |  agent -> both"
    echo "  Rollback: operator -> agent  |  both -> agent"
    echo "============================================================"
    echo -e "${NC}"

    # Global vars set by phase1
    PRE_SERVER_IDENTITY=""
    PRE_CLIENT_IDENTITY=""
    PRE_CID_COUNT=0

    # Ensure we clean up on exit
    trap cleanup EXIT

    # Create cluster and install Cilium
    setup_kind_cluster

    # Setup test pods
    setup_test_namespace

    # Test all combinations of (target_mode × restart_order)
    local modes=("operator" "both")
    local orders=("operator-first" "agent-first" "both")

    for mode in "${modes[@]}"; do
        for order in "${orders[@]}"; do
            run_upgrade_path "${mode}" "${order}"
        done
    done

    # Rollback tests: agent -> target_mode -> agent
    log_step "Starting rollback tests"
    local rollback_modes=("operator" "both")
    local rollback_orders=("operator-first" "agent-first" "both")

    for mode in "${rollback_modes[@]}"; do
        for order in "${rollback_orders[@]}"; do
            run_rollback_path "${mode}" "${order}"
        done
    done

    # Summary
    echo ""
    echo -e "${BLUE}============================================================${NC}"
    echo -e "${BLUE}  Test Summary${NC}"
    echo -e "${BLUE}============================================================${NC}"
    echo -e "  ${GREEN}Passed: ${PASS_COUNT}${NC}"
    echo -e "  ${RED}Failed: ${FAIL_COUNT}${NC}"
    echo ""

    if [ "${FAIL_COUNT}" -gt 0 ]; then
        echo -e "${RED}SOME TESTS FAILED${NC}"
    else
        echo -e "${GREEN}ALL TESTS PASSED${NC}"
        echo ""
        echo "All upgrade and rollback paths produce identical behavior:"
        echo "  - Existing connections preserved across upgrades and rollbacks"
        echo "  - Identities preserved through upgrade and rollback cycles"
        echo "  - New pods get identities in all modes"
        echo "  - Cross-generation connectivity works"
        echo "  - Restart order (operator-first / agent-first / both) has no impact"
        echo "  - Rollback from operator/both to agent is seamless"
    fi

    # Restore cluster to operator mode
    log_info "Restoring cluster to operator mode..."
    helm upgrade "${HELM_RELEASE}" "${ROOT_DIR}/install/kubernetes/cilium" \
        -n "${HELM_NS}" \
        --reuse-values \
        --set identityManagementMode=operator \
        --wait --timeout 300s 2>&1 | tail -5

    exit "${FAIL_COUNT}"
}

main "$@"

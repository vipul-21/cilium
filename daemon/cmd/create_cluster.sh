#!/bin/bash
# Requirements:
# - clusters: Number of clusters to create (default: 1)
# - clusterPrefix: Cluster name prefix (e.g., "test")
# - clusterType: AKS cluster type (e.g., swift-byocni-nokubeproxy-up)
# - SUB: Azure subscription GUID
# - CILIUM_IMAGE_TAG: Cilium image tag with centralized CP changes (default: cp-testing)
# - CILIUM_IMAGE_REPO: Cilium image repository (default: acnpublic.azurecr.io/vipul/cilium)
# - CILIUM_PRIVATE_WS: Path to cilium-private workspace (default: ~/ws/cilium-private)
# - AZURE_CNS_WS: Path to azure-container-networking workspace (default: ~/ws/azure-container-networking)
# - START_STEP: Optional - Start from specific step (default: 1)
#
# Example usage:
#   clusterPrefix=mytest SUB=<GUID> clusterType=swift-byocni-nokubeproxy-up \
#   CILIUM_IMAGE_TAG=cp-testing clusters=1 ./create_cluster.sh
#
#   # To start from step 4 (if cluster already exists with Cilium):
#   START_STEP=4 clusterPrefix=mytest SUB=<GUID> clusterType=swift-byocni-nokubeproxy-up \
#   CILIUM_IMAGE_TAG=cp-testing clusters=1 ./create_cluster.sh
#
#############################################################################

set -euo pipefail

: "${clusters:=1}" >/dev/null
: "${clusterPrefix:?Environment variable 'clusterPrefix' must be set}" >/dev/null
: "${clusterType:?Environment variable 'clusterType' must be set}" >/dev/null
: "${SUB:?Environment variable 'SUB' must be set}" >/dev/null
: "${CILIUM_IMAGE_TAG:=cp-testing}" >/dev/null
: "${CILIUM_IMAGE_REPO:=acnpublic.azurecr.io/vipul/cilium}" >/dev/null
: "${CLUSTERMESH_IMAGE_TAG:=test-1}" >/dev/null
: "${CLUSTERMESH_IMAGE_REPO:=acnpublic.azurecr.io/vipul/clustermesh-apiserver}" >/dev/null
: "${START_STEP:=1}" >/dev/null
: "${CILIUM_PRIVATE_WS:=${HOME}/ws/cilium-private}" >/dev/null
: "${AZURE_CNS_WS:=${HOME}/ws/azure-container-networking}" >/dev/null

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CILIUM_CHART_DIR="${REPO_ROOT}/install/kubernetes/cilium"

if [[ ! -d "${CILIUM_CHART_DIR}" ]]; then
    echo "[ERROR] Local Cilium chart not found at ${CILIUM_CHART_DIR}" >&2
    exit 1
fi

echo ""
echo "=========================================================================="
echo "Variables Used"
echo "=========================================================================="
echo "Clusters:           ${clusters}"
echo "Cluster Prefix:     ${clusterPrefix}"
echo "Cluster Type:       ${clusterType}"
echo "Subscription:       ${SUB}"
echo "Cilium Image:       ${CILIUM_IMAGE_REPO}:${CILIUM_IMAGE_TAG}"
echo "ClusterMesh Image:  ${CLUSTERMESH_IMAGE_REPO}:${CLUSTERMESH_IMAGE_TAG}"
echo "Chart Directory:    ${CILIUM_CHART_DIR}"
echo "Starting from Step: ${START_STEP}"
echo "=========================================================================="
echo ""

suffixes=$(seq 1 "${clusters}")

for unique in $suffixes; do    
    # Subnet ranges
    VNET_PREFIX="10.${unique}.0.0/16"
    NODE_SUBNET_PREFIX="10.${unique}.0.0/24"
    POD_SUBNET_PREFIX="10.${unique}.1.0/24"
    NODE_SUBNET_NAME_VAL="${clusterPrefix}-${unique}-node"
    POD_SUBNET_NAME_VAL="${clusterPrefix}-${unique}-pod"
    CLUSTER="${clusterPrefix}-${unique}"
    CLUSTER_CONTEXT="${clusterPrefix}-${unique}"
    VNET="${clusterPrefix}-${unique}-vnet"

    if [[ ${START_STEP} -le 1 ]]; then
        echo "[STEP 1/${clusters}] Creating AKS cluster: ${CLUSTER}"
        make -C "${CILIUM_PRIVATE_WS}/clustermesh" "$clusterType" \
            AZCLI=az REGION=westus2 SUB="$SUB" \
            CLUSTER="$CLUSTER" \
            VNET_PREFIX="$VNET_PREFIX" SUBNET_PREFIX="$VNET_PREFIX" \
            NODE_SUBNET_PREFIX="$NODE_SUBNET_PREFIX" \
            POD_SUBNET_PREFIX="$POD_SUBNET_PREFIX" \
            NODE_COUNT=2 \
            NODE_SUBNET_NAME="$NODE_SUBNET_NAME_VAL" \
            POD_SUBNET_NAME="$POD_SUBNET_NAME_VAL" \
            VM_SIZE=Standard_D4s_v5 \
            VNET="$VNET"
    else
        echo "[SKIPPING STEP 1/${clusters}] Creating AKS cluster (START_STEP=${START_STEP})"
    fi

    if [[ ${START_STEP} -le 2 ]]; then
        echo ""
        echo "[STEP 2/${clusters}] Installing Cilium"
        echo "  Image: ${CILIUM_IMAGE_REPO}:${CILIUM_IMAGE_TAG}"
        cilium install --context "${CLUSTER_CONTEXT}" \
        --namespace kube-system \
        --chart-directory "${CILIUM_CHART_DIR}" \
        --set image.repository="${CILIUM_IMAGE_REPO}" \
        --set image.tag="${CILIUM_IMAGE_TAG}" \
        --set image.pullPolicy=Always \
        --set azure.resourceGroup="${clusterPrefix}-${unique}-rg" \
        --set aksbyocni.enabled=false \
        --set nodeinit.enabled=false \
        --set hubble.enabled=false \
        --set envoy.enabled=false \
        --set cluster.id="${unique}" \
        --set cluster.name="${CLUSTER}" \
        --set ipam.mode=delegated-plugin \
        --set routingMode=native \
        --set endpointRoutes.enabled=true \
        --set enable-cilium-endpoint-slice=true \
        --set enable-ipv4=true \
        --set enableIPv4Masquerade=false \
        --set kubeProxyReplacement=true \
        --set kubeProxyReplacementHealthzBindAddr='0.0.0.0:10256' \
        --set extraArgs="{--local-router-ipv4=169.254.23.0} {--install-iptables-rules=true}" \
        --set endpointHealthChecking.enabled=false \
        --set cni.exclusive=false \
        --set bpf.enableTCX=false \
        --set bpf.hostLegacyRouting=true \
        --set l7Proxy=true \
        --set sessionAffinity=true
    else
        echo "[SKIPPING STEP 2/${clusters}] Installing Cilium (START_STEP=${START_STEP})"
    fi

    if [[ ${START_STEP} -le 3 ]]; then
        echo ""
        echo "[STEP 3/${clusters}] Installing Azure CNS (Container Network Service)"
        make -C "${AZURE_CNS_WS}" test-load CNS_ONLY=true \
            AZURE_IPAM_VERSION=v0.4.0 CNS_VERSION=v1.7.9-0 \
            INSTALL_CNS=true INSTALL_OVERLAY=true \
            CNS_IMAGE_REPO=MCR IPAM_IMAGE_REPO=MCR \
            CLUSTER="${CLUSTER}" RESOURCE_GROUP="${clusterPrefix}-${unique}-rg"
    else
        echo "[SKIPPING STEP 3/${clusters}] Installing Azure CNS (START_STEP=${START_STEP})"
    fi

    if [[ ${START_STEP} -le 4 ]]; then
        echo ""
        echo "[STEP 4/${clusters}] Pre-creating clustermesh-remote-users configmap"
        if ! kubectl --context "${CLUSTER_CONTEXT}" -n kube-system get configmap clustermesh-remote-users &>/dev/null; then
            kubectl --context "${CLUSTER_CONTEXT}" -n kube-system create configmap clustermesh-remote-users \
                --from-literal=.keep=""
        fi
        
        kubectl --context "${CLUSTER_CONTEXT}" -n kube-system label configmap clustermesh-remote-users \
            app.kubernetes.io/managed-by=Helm \
            app.kubernetes.io/part-of=cilium \
            --overwrite
        
        kubectl --context "${CLUSTER_CONTEXT}" -n kube-system annotate configmap clustermesh-remote-users \
            meta.helm.sh/release-name=cilium \
            meta.helm.sh/release-namespace=kube-system \
            --overwrite
        
        echo ""
        echo "[STEP 4.5/${clusters}] Enabling ClusterMesh with kvstoremesh"
        cilium clustermesh enable --context "${CLUSTER_CONTEXT}" --enable-kvstoremesh
        
        echo ""
        echo "[STEP 5/${clusters}] Updating clustermesh-apiserver image"
        kubectl --context "${CLUSTER_CONTEXT}" set image deployment/clustermesh-apiserver \
            -n kube-system \
            apiserver="${CLUSTERMESH_IMAGE_REPO}:${CLUSTERMESH_IMAGE_TAG}"
        
        kubectl --context "${CLUSTER_CONTEXT}" rollout restart deployment/clustermesh-apiserver -n kube-system
        
        echo ""
        echo "[STEP 6/${clusters}] Waiting for clustermesh-apiserver..."
        kubectl --context "${CLUSTER_CONTEXT}" -n kube-system rollout status deployment/clustermesh-apiserver --timeout=300s

        echo ""
        echo "[STEP 7/${clusters}] Discovering service endpoint"
        CLUSTERMESH_SVC_IP=$(kubectl --context "${CLUSTER_CONTEXT}" -n kube-system \
            get svc clustermesh-apiserver -o jsonpath='{.spec.clusterIP}')

        echo ""
        echo "[STEP 8/${clusters}] Regenerating etcd certificates"
        
        # Get pod IP
        CLUSTERMESH_POD_IP=$(kubectl --context "${CLUSTER_CONTEXT}" -n kube-system \
            get pod -l k8s-app=clustermesh-apiserver -o jsonpath='{.items[0].status.podIP}')
        
        # Create temporary directory for certificate generation
        TEMP_CERT_DIR=$(mktemp -d)
        
        # Get CA certificate and key
        kubectl --context "${CLUSTER_CONTEXT}" -n kube-system get secret cilium-ca \
            -o jsonpath='{.data.ca\.crt}' | base64 -d > "${TEMP_CERT_DIR}/ca.crt"
        kubectl --context "${CLUSTER_CONTEXT}" -n kube-system get secret cilium-ca \
            -o jsonpath='{.data.ca\.key}' | base64 -d > "${TEMP_CERT_DIR}/ca.key"
        
        # Create OpenSSL config with cluster IP and pod IP
        cat > "${TEMP_CERT_DIR}/openssl.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = clustermesh-apiserver.kube-system.svc.cluster.local

[v3_req]
keyUsage = keyEncipherment, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = clustermesh-apiserver.kube-system.svc.cluster.local
DNS.2 = clustermesh-apiserver.kube-system.svc
DNS.3 = clustermesh-apiserver.kube-system
DNS.4 = clustermesh-apiserver
DNS.5 = localhost
DNS.6 = *.mesh.cilium.io
IP.1 = 127.0.0.1
IP.2 = ::1
IP.3 = ${CLUSTERMESH_SVC_IP}
IP.4 = ${CLUSTERMESH_POD_IP}
EOF
        
        # Generate new server key and certificate
        openssl genrsa -out "${TEMP_CERT_DIR}/tls.key" 2048
        openssl req -new -key "${TEMP_CERT_DIR}/tls.key" \
            -out "${TEMP_CERT_DIR}/tls.csr" -config "${TEMP_CERT_DIR}/openssl.cnf"
        openssl x509 -req -in "${TEMP_CERT_DIR}/tls.csr" \
            -CA "${TEMP_CERT_DIR}/ca.crt" \
            -CAkey "${TEMP_CERT_DIR}/ca.key" \
            -CAcreateserial \
            -out "${TEMP_CERT_DIR}/tls.crt" \
            -days 3650 \
            -extensions v3_req \
            -extfile "${TEMP_CERT_DIR}/openssl.cnf"
        
        # Delete existing secret and recreate
        kubectl --context "${CLUSTER_CONTEXT}" -n kube-system delete secret clustermesh-apiserver-server-cert --ignore-not-found=true
        
        # Update the secret
        kubectl --context "${CLUSTER_CONTEXT}" -n kube-system create secret generic clustermesh-apiserver-server-cert \
            --from-file=tls.crt="${TEMP_CERT_DIR}/tls.crt" \
            --from-file=tls.key="${TEMP_CERT_DIR}/tls.key" \
            --from-file=ca.crt="${TEMP_CERT_DIR}/ca.crt"
        
        kubectl --context "${CLUSTER_CONTEXT}" -n kube-system rollout restart deployment/clustermesh-apiserver
        kubectl --context "${CLUSTER_CONTEXT}" -n kube-system rollout status deployment/clustermesh-apiserver --timeout=5m
        rm -rf "${TEMP_CERT_DIR}"

        echo ""
        echo "[STEP 9/${clusters}] Extracting admin certificates"
        LOCAL_CA_CRT=$(kubectl --context "${CLUSTER_CONTEXT}" -n kube-system get secret cilium-ca -o jsonpath='{.data.ca\.crt}')
        LOCAL_CLIENT_KEY=$(kubectl --context "${CLUSTER_CONTEXT}" -n kube-system get secret clustermesh-apiserver-admin-cert -o jsonpath='{.data.tls\.key}')
        LOCAL_CLIENT_CRT=$(kubectl --context "${CLUSTER_CONTEXT}" -n kube-system get secret clustermesh-apiserver-admin-cert -o jsonpath='{.data.tls\.crt}')
        
        kubectl --context "${CLUSTER_CONTEXT}" -n kube-system create secret generic clustermesh-apiserver-local-cert \
            --from-literal=tls.key="$(echo ${LOCAL_CLIENT_KEY} | base64 -d)" \
            --from-literal=tls.crt="$(echo ${LOCAL_CLIENT_CRT} | base64 -d)" \
            --from-literal=ca.crt="$(echo ${LOCAL_CA_CRT} | base64 -d)" \
            --dry-run=client -o yaml | kubectl --context "${CLUSTER_CONTEXT}" apply -f -
        
        echo ""
        echo "[STEP 10/${clusters}] Enabling centralized control plane"
        cilium upgrade --context "${CLUSTER_CONTEXT}" \
            --namespace kube-system \
            --chart-directory "${CILIUM_CHART_DIR}" \
            --reuse-values \
            --set azure.resourceGroup="${clusterPrefix}-${unique}-rg" \
            --set clustermesh.config.enabled=true \
            --set clustermesh.config.localCluster.ips[0]="${CLUSTERMESH_SVC_IP}" \
            --set clustermesh.config.localCluster.tls.caCert="${LOCAL_CA_CRT}" \
            --set clustermesh.config.localCluster.tls.key="${LOCAL_CLIENT_KEY}" \
            --set clustermesh.config.localCluster.tls.cert="${LOCAL_CLIENT_CRT}" \
            --set clustermesh.readCiliumEndpointsFromEtcd=true

        echo ""
        echo "[STEP 11/${clusters}] Restarting Cilium agents"
        kubectl --context "${CLUSTER_CONTEXT}" -n kube-system rollout restart daemonset/cilium
        kubectl --context "${CLUSTER_CONTEXT}" -n kube-system rollout status daemonset/cilium --timeout=5m
        
        sleep 1m
        kubectl --context "${CLUSTER_CONTEXT}" -n kube-system rollout restart daemonset/azure-cns
        kubectl --context "${CLUSTER_CONTEXT}" -n kube-system rollout status daemonset/azure-cns --timeout=5m

        echo ""
        echo "[STEP 12/${clusters}] Verifying setup"
        if kubectl --context "${CLUSTER_CONTEXT}" logs -n kube-system daemonset/cilium -c cilium-agent --since=2m 2>/dev/null | \
           grep -q "Starting IP identity watcher"; then
            echo "  IPIdentityWatcher started"
            
            SYNC_COUNT=$(kubectl --context "${CLUSTER_CONTEXT}" logs -n kube-system daemonset/cilium -c cilium-agent --since=2m 2>/dev/null | \
                grep "IPIdentityWatcher synchronized" | tail -1 | grep -oP 'num_entries=\K[0-9]+' || echo "0")
            
            if [[ "${SYNC_COUNT}" -gt 0 ]]; then
                echo "  Synchronized ${SYNC_COUNT} entries from etcd"
            fi
        fi
        
        if kubectl --context "${CLUSTER_CONTEXT}" logs -n kube-system daemonset/cilium -c cilium-agent --since=2m 2>/dev/null | \
           grep -q "Initialized clustermesh CEP client"; then
            echo "  Connected to clustermesh etcd"
        fi
        
        echo ""
        echo "Cluster ${unique}/${clusters} setup complete: ${CLUSTER}"
    else
        echo "[SKIPPING STEPS 4-12/${clusters}] ClusterMesh and centralized CP setup (START_STEP=${START_STEP})"
    fi  # End of START_STEP -le 4
done
echo ""
echo "All ${clusters} cluster setup complete!"
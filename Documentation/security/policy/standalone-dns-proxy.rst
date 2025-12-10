.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _standalone_dns_proxy:

***************************************
Standalone DNS Proxy (alpha)
***************************************

.. include:: ../../alpha.rst

The Standalone DNS Proxy is an independent component that runs as a separate
DaemonSet in the cluster, providing DNS proxying capabilities independent of
the Cilium agent. The in agent proxy runs alongside the Standalone DNS Proxy.
The load of DNS request is shared between both proxies.

.. note::

   The Standalone DNS Proxy is currently in alpha stage. It is recommended to test
   thoroughly before using in production environments.

Overview
========

The Standalone DNS Proxy communicates with the Cilium agent via gRPC to:

1. Receive DNS policy configuration
2. Report DNS query results for policy enforcement
3. Coordinate IP address to FQDN mappings

Configuration
=============

To enable the Standalone DNS Proxy, set the following Helm values:

.. code-block:: yaml

   standaloneDnsProxy:
     enabled: true
     proxyPort: 10094
     serverPort: 10095

.. important::

   The ``standaloneDnsProxy.proxyPort`` must match the ``dnsProxy.proxyPort`` 
   configuration in the Cilium agent. Both the agent and standalone DNS proxy 
   expect these ports to be the same for proper communication and DNS traffic 
   interception.

Testing the Standalone DNS Proxy
=================================

This section provides steps to test the Standalone DNS Proxy in a development environment.

Building and Deploying
-----------------------

1. **Build the Standalone DNS Proxy Image**

   Build the standalone DNS proxy container image:

   .. code-block:: shell-session

      $ make docker-standalone-dns-proxy-image

2. **Set Up kind Cluster with Cilium**

   Create a kind cluster and install Cilium:

   .. code-block:: shell-session

      $ make kind && make kind-image && make kind-install-cilium

3. **Load the Image into kind**

   Load the standalone DNS proxy image into the kind cluster:

   .. code-block:: shell-session

      $ kind load docker-image quay.io/cilium/standalone-dns-proxy:latest

4. **Upgrade Cilium to Enable Standalone DNS Proxy**

   Enable the standalone DNS proxy and configure it to work with the Cilium agent:

   .. code-block:: shell-session

      $ cilium upgrade \
          --chart-directory='./install/kubernetes/cilium' \
          --set='l7Proxy=true' \
          --set='dnsProxy.proxyPort=10094' \
          --helm-set='standaloneDnsProxy.enabled=true' \
          --helm-set='standaloneDnsProxy.proxyPort=10094' \
          --helm-set='standaloneDnsProxy.l7Proxy=true' \
          --helm-set='standaloneDnsProxy.image.repository=quay.io/cilium/standalone-dns-proxy' \
          --helm-set='standaloneDnsProxy.image.tag=latest' \
          --helm-set='standaloneDnsProxy.image.useDigest=false' \
          --helm-set='standaloneDnsProxy.image.pullPolicy=Never'

   .. note::

      * Both ``dnsProxy.proxyPort`` and ``standaloneDnsProxy.proxyPort`` are set to ``10094`` to ensure proper communication
      * ``l7Proxy=true`` enables L7 proxy support required for DNS policy enforcement
      * ``image.pullPolicy=Never`` is used for local testing with kind

5. **Restart Cilium Agent**

   Restart the Cilium agent to apply the configuration changes:

   .. code-block:: shell-session

      $ kubectl rollout restart ds -n kube-system cilium

6. **Verify Deployment**

   Check that the standalone DNS proxy pods are running:

   .. code-block:: shell-session

      $ kubectl -n kube-system get pods -l k8s-app=standalone-dns-proxy
      NAME                          READY   STATUS    RESTARTS   AGE
      standalone-dns-proxy-xxxxx    1/1     Running   0          1m

Usage with DNS Policies
========================

The Standalone DNS Proxy integrates with Cilium's DNS-based network policies (toFQDNs rules). 
When enabled, DNS queries from pods are intercepted by the Standalone DNS Proxy or the in-agent 
DNS proxy, which communicates with the Cilium agent to enforce the configured DNS policies.

Example DNS Policy
------------------

The following example demonstrates DNS policy enforcement with the standalone DNS proxy. 
This policy allows pods with the label ``org: alliance`` to:

* Query DNS for any domain (for visibility)
* Access ``cilium.io`` and its subdomains

.. literalinclude:: ../../../../examples/policies/l7/dns/dns.yaml
   :language: yaml

Apply the policy:

.. code-block:: shell-session

   $ kubectl apply -f examples/policies/l7/dns/dns-visibility.yaml

Testing the Policy
~~~~~~~~~~~~~~~~~~

Deploy a test pod to verify DNS policy enforcement:

.. code-block:: shell-session

   $ kubectl run test-pod --image=nicolaka/netshoot --labels="org=alliance" -- sleep 3600

Test allowed domains:

.. code-block:: shell-session

   $ kubectl exec test-pod -- nslookup cilium.io
   $ kubectl exec test-pod -- nslookup api.cilium.io
   $ kubectl exec test-pod -- nslookup docs.sub.cilium.io

The DNS queries should be intercepted by the DNS proxy, and connections 
to the resolved IPs should be allowed based on the policy.

Make the cilium agent go down and verify that the standalone DNS proxy
continues to intercept DNS requests.
.. code-block:: shell-session

   $ kubectl set image -n kube-system ds/cilium cilium-agent=quay.io/cilium/cilium:non-existent-image
   $ kubectl exec test-pod -- nslookup cilium.io

Verify DNS Proxy Interception
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Check the standalone DNS proxy logs to confirm it's processing DNS requests:

.. code-block:: shell-session

   $ kubectl -n kube-system logs -l k8s-app=standalone-dns-proxy --tail=50 | grep -i dns

You should see log entries showing DNS queries being processed by the standalone proxy.

For more information on DNS policies, see :ref:`DNS based`.

Limitations
===========

The Standalone DNS Proxy alpha release has the following known limitations:

* Metrics related to DNS are not supported yet. The metrics are currently
  only available from the in-agent DNS proxy.
* Standalone DNS proxy depends on cilium agent to read DNS policies, enforce them and 
  communicate via gRPC. If there are connectivity issues between the proxy and agent,
  DNS policy enforcement may be affected.

Troubleshooting
===============

Port Configuration Mismatch
----------------------------

If DNS queries are not being properly proxied, verify that the proxy ports match:

.. code-block:: shell-session

   $ kubectl -n kube-system get configmap cilium-config -o yaml | grep -E 'tofqdns-proxy-port'
   $ kubectl -n kube-system get configmap standalone-dns-proxy-config -o yaml | grep -E 'tofqdns-proxy-port'

Both ``dnsProxy.proxyPort`` and ``standaloneDnsProxy.proxyPort`` must be set to the 
same value (default: ``10094``). A mismatch will prevent proper DNS traffic interception.

gRPC Communication Issues
-------------------------

If there are communication issues between the proxy and agent:

1. Check network connectivity between proxy pods and agent pods
2. Verify gRPC port configuration
3. Review agent logs for connection errors

.. code-block:: shell-session

   $ kubectl -n kube-system logs -l k8s-app=cilium --tail=100 | grep -i "grpc"

API Reference
=============

For detailed API documentation, see :ref:`sdpapi_ref`.

Further Reading
===============

* :ref:`DNS based`
* :ref:`DNS Proxy`

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"net/netip"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/table"
	"github.com/cilium/cilium/pkg/ztunnel/xds"
	"github.com/cilium/cilium/pkg/ztunnel/zds"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
)

type params struct {
	cell.In

	Config                      config.Config
	DB                          *statedb.DB
	EnrolledNamespaceTable      statedb.RWTable[*table.EnrolledNamespace]
	Logger                      *slog.Logger
	Lifecycle                   cell.Lifecycle
	EndpointManager             endpointmanager.EndpointManager
	EndpointEnroller            zds.EndpointEnroller
	RestorerPromise             promise.Promise[endpointstate.Restorer]
	EndpointEventChannel        chan *xds.EndpointEvent
	CiliumEndpointResource      resource.Resource[*types.CiliumEndpoint]
	CiliumEndpointSliceResource resource.Resource[*v2alpha1.CiliumEndpointSlice]
	IPCache                     *ipcache.IPCache
}

type EnrollmentReconciler struct {
	db                          *statedb.DB
	logger                      *slog.Logger
	enrolledNamespaceTable      statedb.RWTable[*table.EnrolledNamespace]
	endpointManager             endpointmanager.EndpointManager
	endpointEnroller            zds.EndpointEnroller
	restorerPromise             promise.Promise[endpointstate.Restorer]
	endpointEventCh             chan *xds.EndpointEvent
	ciliumEndpointResource      resource.Resource[*types.CiliumEndpoint]
	ciliumEndpointSliceResource resource.Resource[*v2alpha1.CiliumEndpointSlice]
	ipcache                     *ipcache.IPCache
}

func NewEnrollmentReconciler(cfg params) reconciler.Operations[*table.EnrolledNamespace] {
	if !cfg.Config.EnableZTunnel {
		return nil
	}

	ops := &EnrollmentReconciler{
		logger:                      cfg.Logger,
		db:                          cfg.DB,
		enrolledNamespaceTable:      cfg.EnrolledNamespaceTable,
		endpointManager:             cfg.EndpointManager,
		endpointEnroller:            cfg.EndpointEnroller,
		restorerPromise:             cfg.RestorerPromise,
		endpointEventCh:             cfg.EndpointEventChannel,
		ciliumEndpointResource:      cfg.CiliumEndpointResource,
		ciliumEndpointSliceResource: cfg.CiliumEndpointSliceResource,
		ipcache:                     cfg.IPCache,
	}
	cfg.Lifecycle.Append(ops)
	return ops
}

// emitEndpointEvents sends endpoint events for all CiliumEndpoints/CiliumEndpointSlices
// in the given namespace to the xDS server with the specified event type.
func (ops *EnrollmentReconciler) emitEndpointEvents(ctx context.Context, namespace string, eventType xds.EndpointEventType) error {
	if option.Config.EnableCiliumEndpointSlice {
		cesStore, err := ops.ciliumEndpointSliceResource.Store(ctx)
		if err != nil {
			return fmt.Errorf("failed to get CiliumEndpointSlice store: %w", err)
		}
		slices, err := cesStore.ByIndex(k8s.NamespaceIndex, namespace)
		if err != nil {
			return fmt.Errorf("failed to get CiliumEndpointSlices by namespace index: %w", err)
		}

		for _, ces := range slices {
			for _, coreCep := range ces.Endpoints {
				cep := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(&coreCep, ces.Namespace)
				select {
				case ops.endpointEventCh <- &xds.EndpointEvent{
					Type:           eventType,
					CiliumEndpoint: cep,
				}:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
		return nil
	}

	cepStore, err := ops.ciliumEndpointResource.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to get CiliumEndpoint store from K8sCiliumEndpointsWatcher: %w", err)
	}
	ceps, err := cepStore.ByIndex(k8s.NamespaceIndex, namespace)
	if err != nil {
		return fmt.Errorf("failed to get CiliumEndpoints by namespace index: %w", err)
	}
	for _, cep := range ceps {
		select {
		case ops.endpointEventCh <- &xds.EndpointEvent{
			Type:           eventType,
			CiliumEndpoint: cep,
		}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (ops *EnrollmentReconciler) Update(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision, ns *table.EnrolledNamespace) error {
	if err := ops.emitEndpointEvents(ctx, ns.Name, xds.CREATE); err != nil {
		return err
	}

	// Enroll all endpoints in this namespace
	endpoints := ops.endpointManager.GetEndpointsByNamespace(ns.Name)
	for _, ep := range endpoints {
		if ep.GetContainerNetnsPath() == "" || isZtunnelPod(ep) {
			continue
		}
		err := ops.endpointEnroller.EnrollEndpoint(ep)
		if err != nil {
			ops.logger.Error("Failed to enroll endpoint to ztunnel",
				logfields.K8sNamespace, ns.Name,
				logfields.Pod, ep.K8sPodName,
				logfields.Error, err,
			)
			return err
		}
		ops.setMeshedMetadata(ep, true)
	}
	// Set meshed ipcache metadata for all IPs in this namespace
	// (both local and remote endpoints) so every node's BPF map
	// knows these endpoints are meshed.
	ops.setMeshedMetadataForNamespace(ctx, ns.Name, true)

	ops.logger.Info("Enrolled all endpoints in namespace", logfields.K8sNamespace, ns.Name)
	return nil
}

func (ops *EnrollmentReconciler) Delete(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision, ns *table.EnrolledNamespace) error {
	endpoints := ops.endpointManager.GetEndpointsByNamespace(ns.Name)
	for _, ep := range endpoints {
		if ep.GetContainerNetnsPath() == "" || isZtunnelPod(ep) {
			continue
		}
		err := ops.endpointEnroller.DisenrollEndpoint(ep)
		if err != nil {
			ops.logger.Error("Failed to disenroll endpoint from ztunnel",
				logfields.K8sNamespace, ns.Name,
				logfields.Pod, ep.K8sPodName,
				logfields.Error, err,
			)
			return err
		}
		ops.setMeshedMetadata(ep, false)
	}

	// Clear meshed ipcache metadata for all IPs in this namespace.
	ops.setMeshedMetadataForNamespace(ctx, ns.Name, false)

	if err := ops.emitEndpointEvents(ctx, ns.Name, xds.REMOVED); err != nil {
		return err
	}

	ops.logger.Info("Disenrolled all endpoints in namespace",
		logfields.K8sNamespace, ns.Name,
	)
	return nil
}

// Prune unexpected entries.
func (ops *EnrollmentReconciler) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[*table.EnrolledNamespace, statedb.Revision]) error {
	return nil
}

var _ reconciler.Operations[*table.EnrolledNamespace] = &EnrollmentReconciler{}

const meshedResourceID ipcacheTypes.ResourceID = "ztunnel-mesh"

// setMeshedMetadata updates the ipcache and endpoint property to reflect
// the meshed enrollment state for a local endpoint.
func (ops *EnrollmentReconciler) setMeshedMetadata(ep *endpoint.Endpoint, meshed bool) {
	ep.SetPropertyValue(endpoint.PropertyMeshed, meshed)
	ops.setMeshedMetadataForIP(ep.IPv4Address(), meshed)
}

// setMeshedMetadataForIP updates the ipcache meshed flag for a single IP.
// This works for both local and remote pod IPs.
func (ops *EnrollmentReconciler) setMeshedMetadataForIP(ip netip.Addr, meshed bool) {
	if !ip.IsValid() {
		return
	}
	prefix := cmtypes.NewLocalPrefixCluster(netip.PrefixFrom(ip, ip.BitLen()))
	flags := ipcacheTypes.EndpointFlags{}
	flags.SetMeshed(meshed)
	if meshed {
		ops.ipcache.UpsertMetadata(prefix, source.CustomResource, meshedResourceID, flags)
	} else {
		ops.ipcache.RemoveMetadata(prefix, meshedResourceID, flags)
	}
}

// setMeshedMetadataForNamespace sets the meshed ipcache flag for all
// endpoint IPs in the given namespace by iterating the CES/CEP store.
// This covers both local and remote endpoints.
func (ops *EnrollmentReconciler) setMeshedMetadataForNamespace(ctx context.Context, namespace string, meshed bool) {
	if option.Config.EnableCiliumEndpointSlice {
		cesStore, err := ops.ciliumEndpointSliceResource.Store(ctx)
		if err != nil {
			ops.logger.Error("Failed to get CES store for meshed metadata",
				logfields.Error, err)
			return
		}
		slices, err := cesStore.ByIndex(k8s.NamespaceIndex, namespace)
		if err != nil {
			ops.logger.Error("Failed to get CES by namespace for meshed metadata",
				logfields.Error, err)
			return
		}
		for _, ces := range slices {
			for _, coreCep := range ces.Endpoints {
				if coreCep.Networking == nil {
					continue
				}
				for _, pair := range coreCep.Networking.Addressing {
					if pair.IPV4 != "" {
						if ip, err := netip.ParseAddr(pair.IPV4); err == nil {
							ops.setMeshedMetadataForIP(ip, meshed)
						}
					}
					if pair.IPV6 != "" {
						if ip, err := netip.ParseAddr(pair.IPV6); err == nil {
							ops.setMeshedMetadataForIP(ip, meshed)
						}
					}
				}
			}
		}
		return
	}

	cepStore, err := ops.ciliumEndpointResource.Store(ctx)
	if err != nil {
		ops.logger.Error("Failed to get CEP store for meshed metadata",
			logfields.Error, err)
		return
	}
	ceps, err := cepStore.ByIndex(k8s.NamespaceIndex, namespace)
	if err != nil {
		ops.logger.Error("Failed to get CEPs by namespace for meshed metadata",
			logfields.Error, err)
		return
	}
	for _, cep := range ceps {
		if cep.Networking == nil {
			continue
		}
		for _, pair := range cep.Networking.Addressing {
			if pair.IPV4 != "" {
				if ip, err := netip.ParseAddr(pair.IPV4); err == nil {
					ops.setMeshedMetadataForIP(ip, meshed)
				}
			}
			if pair.IPV6 != "" {
				if ip, err := netip.ParseAddr(pair.IPV6); err == nil {
					ops.setMeshedMetadataForIP(ip, meshed)
				}
			}
		}
	}
}

// isZtunnelPod returns true if the endpoint is a ztunnel pod.
// This checks for the "app=ztunnel-cilium" label that is set on ztunnel pods.
func isZtunnelPod(ep *endpoint.Endpoint) bool {
	labels := ep.GetLabels()
	if label, ok := labels["k8s:app"]; ok {
		return label.Value == "ztunnel-cilium"
	}
	return false
}

func (ops *EnrollmentReconciler) Start(ctx cell.HookContext) error {
	_, initialized := ops.enrolledNamespaceTable.Initialized(ops.db.ReadTxn())
	select {
	case <-ctx.Done():
		ops.logger.Info("Stopping reconciler")
		return nil
	case <-initialized:
	}
	ops.logger.Info("EnrolledNamespace table initialized")

	restorer, err := ops.restorerPromise.Await(ctx)
	if err != nil {
		return fmt.Errorf("failed to await restorer: %w", err)
	}
	// Wait for endpoint restore to complete before getting endpoints.
	// This is to ensure that we don't miss any endpoints that are restored from disk.
	if err := restorer.WaitForEndpointRestore(ctx); err != nil {
		return fmt.Errorf("failed to wait for endpoint restore: %w", err)
	}

	ops.endpointManager.Subscribe(ops)
	// Get endpoints for initial snapshot
	endpoints := ops.endpointManager.GetEndpoints()
	endpointsToEnroll := make([]*endpoint.Endpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		epNamespace := ep.GetK8sNamespace()
		// If namespace is not enrolled or endpoint has no netns path or is ztunnel itself, skip
		if epNamespace == "" || ep.GetContainerNetnsPath() == "" || isZtunnelPod(ep) {
			continue
		}
		// Check if namespace is enrolled
		txn := ops.db.ReadTxn()
		_, _, found := ops.enrolledNamespaceTable.Get(txn, table.EnrolledNamespacesNameIndex.Query(epNamespace))
		if !found {
			ops.logger.Info("Skipping enrollment of endpoint in unenrolled namespace",
				logfields.K8sNamespace, epNamespace,
				logfields.Pod, ep.K8sPodName,
			)
			continue
		}
		endpointsToEnroll = append(endpointsToEnroll, ep)
	}
	ops.endpointEnroller.SeedInitialSnapshot(endpointsToEnroll...)
	ops.logger.Info("Enrollment reconciler initialized")
	return nil
}

func (ops *EnrollmentReconciler) Stop(cell.HookContext) error {
	ops.endpointManager.Unsubscribe(ops)
	ops.logger.Info("Stopping reconciler")
	return nil
}

func (ops *EnrollmentReconciler) EndpointCreated(ep *endpoint.Endpoint) {
	epNamespace := ep.GetK8sNamespace()
	// If namespace is not enrolled or endpoint has no netns path or is ztunnel itself, skip
	if epNamespace == "" || ep.GetContainerNetnsPath() == "" || isZtunnelPod(ep) {
		return
	}
	// Check if namespace is enrolled
	txn := ops.db.ReadTxn()
	_, _, found := ops.enrolledNamespaceTable.Get(txn, table.EnrolledNamespacesNameIndex.Query(epNamespace))
	if !found {
		ops.logger.Debug("Skipping enrollment of endpoint in unenrolled namespace",
			logfields.K8sNamespace, epNamespace,
			logfields.Pod, ep.K8sPodName,
		)
		return
	}
	err := ops.endpointEnroller.EnrollEndpoint(ep)
	if err != nil {
		ops.logger.Error("Failed to enroll endpoint to ztunnel",
			logfields.K8sNamespace, epNamespace,
			logfields.Pod, ep.K8sPodName,
			logfields.Error, err,
		)
		return
	}
	ops.setMeshedMetadata(ep, true)
}

func (ops *EnrollmentReconciler) EndpointDeleted(ep *endpoint.Endpoint, _ endpoint.DeleteConfig) {
	epNamespace := ep.GetK8sNamespace()
	// If namespace is not enrolled or endpoint has no netns path or is ztunnel itself, skip
	if epNamespace == "" || ep.GetContainerNetnsPath() == "" || isZtunnelPod(ep) {
		return
	}
	// Check if namespace is enrolled
	txn := ops.db.ReadTxn()
	_, _, found := ops.enrolledNamespaceTable.Get(txn, table.EnrolledNamespacesNameIndex.Query(epNamespace))
	if !found {
		ops.logger.Debug("Skipping disenrollment of endpoint in unenrolled namespace",
			logfields.K8sNamespace, epNamespace,
			logfields.Pod, ep.K8sPodName,
		)
		return
	}
	err := ops.endpointEnroller.DisenrollEndpoint(ep)
	if err != nil {
		ops.logger.Error("Failed to disenroll endpoint from ztunnel",
			logfields.K8sNamespace, epNamespace,
			logfields.Pod, ep.K8sPodName,
			logfields.Error, err,
		)
		return
	}
	ops.setMeshedMetadata(ep, false)
}

func (ops *EnrollmentReconciler) EndpointRestored(ep *endpoint.Endpoint) {}

var _ cell.HookInterface = &EnrollmentReconciler{}
var _ endpointmanager.Subscriber = &EnrollmentReconciler{}

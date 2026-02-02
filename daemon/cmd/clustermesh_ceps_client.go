// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/cilium/hive/cell"

	cmcommon "github.com/cilium/cilium/pkg/clustermesh/common"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

// Common client name for both CEP and CES modes - they read from the same etcd path
const cepClientName = "ipcache-clustermesh-ceps"

// Global channel to signal when clustermesh node watcher is ready
var clustermeshNodeWatcherReady chan struct{}

type cepKVStoreClientParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Logger    *slog.Logger

	Config      *option.DaemonConfig
	ClusterInfo cmtypes.ClusterInfo

	ClusterMeshConfig   cmcommon.Config
	RemoteClientFactory cmcommon.RemoteClientFactoryFn

	NodeManager    nodemanager.NodeManager
	LocalNodeStore *node.LocalNodeStore
}

type cepKVStoreClientOut struct {
	cell.Out

	Client           kvstore.Client `name:"ipcache-clustermesh-ceps"`
	NodeWatcherReady chan struct{}  `name:"clustermesh-node-watcher-ready" optional:"true"`
	LocalNodeReady   chan struct{}  `name:"clustermesh-local-node-ready" optional:"true"`
}

type staticKVClient struct {
	kvstore.BackendOperations
}

func (c *staticKVClient) IsEnabled() bool {
	return c.BackendOperations != nil
}

func newClusterMeshCEPClient(params cepKVStoreClientParams) (cepKVStoreClientOut, error) {
	if params.Config == nil {
		params.Logger.Info("Skipping clustermesh client: daemon config not provided", logfields.LogSubsys, cepClientName)
		return cepKVStoreClientOut{}, nil
	}

	// Support both CEP and CES modes - they read from the same etcd path (cilium/state/ip/v1/default/<IP>)
	if !params.Config.ReadCiliumEndpointFromClusterMesh && !params.Config.ReadCiliumEndpointSliceFromClusterMesh {
		params.Logger.Info("Skipping clustermesh client: both read-ceps-from-clustermesh and read-ces-from-clustermesh disabled", 
			logfields.LogSubsys, cepClientName,
			"read-ceps-from-clustermesh", params.Config.ReadCiliumEndpointFromClusterMesh,
			"read-ces-from-clustermesh", params.Config.ReadCiliumEndpointSliceFromClusterMesh)
		return cepKVStoreClientOut{}, nil
	}

	mode := "CEP"
	if params.Config.ReadCiliumEndpointSliceFromClusterMesh {
		mode = "CES"
	}

	cfgDir := params.ClusterMeshConfig.ClusterMeshConfig
	if cfgDir == "" {
		params.Logger.Error("Clustermesh client missing configuration directory", logfields.LogSubsys, cepClientName)
		return cepKVStoreClientOut{}, fmt.Errorf("--clustermesh-config must be set when reading endpoints from clustermesh")
	}

	clusterName := params.ClusterInfo.Name
	if clusterName == "" {
		clusterName = params.Config.ClusterName
	}

	cfgPath := filepath.Join(cfgDir, clusterName)
	if _, err := os.Stat(cfgPath); err != nil {
		params.Logger.Error("Unable to read clustermesh config", logfields.LogSubsys, cepClientName, logfields.ClusterName, clusterName, logfields.Path, cfgPath, logfields.Error, err)
		return cepKVStoreClientOut{}, fmt.Errorf("unable to read clustermesh config %q: %w", cfgPath, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := params.Logger.With(logfields.LogSubsys, cepClientName, logfields.ClusterName, clusterName)
	backend, errCh := params.RemoteClientFactory(ctx, logger, cfgPath, kvstore.ExtraOptions{
		// NoEndpointStatusChecks: true,
	})

	// Don't block agent startup waiting for connection - handle errors asynchronously
	go func() {
		var err error
		select {
		case err = <-errCh:
		case <-ctx.Done():
			err = ctx.Err()
		}
		if err != nil {
			params.Logger.Error("Failed connecting to clustermesh etcd", logfields.LogSubsys, cepClientName, logfields.ClusterName, clusterName, logfields.Path, cfgPath, logfields.Error, err)
			// Connection will retry automatically via etcd client
		}
	}()

	params.Logger.Info("Initialized clustermesh client", logfields.LogSubsys, cepClientName, "mode", mode, logfields.ClusterName, clusterName, logfields.Path, cfgPath)

	client := &staticKVClient{BackendOperations: backend}

	// Create channels to signal when the node watcher is ready and when local node is received
	watcherReady := make(chan struct{})
	localNodeReady := make(chan struct{})
	
	// If reading CES mode (which also includes CiliumNode), set up the node watcher
	if params.Config.ReadCiliumEndpointSliceFromClusterMesh {
		setupNodeWatcher(ctx, params, client, clusterName, logger, watcherReady, localNodeReady)
	} else {
		// If not using CES mode, close the channels immediately as we don't need to wait
		close(watcherReady)
		close(localNodeReady)
	}

	params.Lifecycle.Append(cell.Hook{
		OnStop: func(cell.HookContext) error {
			cancel()
			backend.Close()
			return nil
		},
	})

	return cepKVStoreClientOut{
		Client:           client,
		NodeWatcherReady: watcherReady,
		LocalNodeReady:   localNodeReady,
	}, nil
}

// localNodeObserver is a custom observer for clustermesh mode that handles both local and remote nodes.
// Unlike nodeStore.NodeObserver which skips local nodes, this observer processes local nodes
// to update PodCIDR configuration from clustermesh etcd.
type localNodeObserver struct {
	nodeManager      nodemanager.NodeManager
	localNodeStore   *node.LocalNodeStore
	source           source.Source
	logger           *slog.Logger
	localNodeReady   chan struct{}
	localNodeOnce    sync.Once
}

func (o *localNodeObserver) OnUpdate(k store.Key) {
	n, ok := k.(*nodeStore.ValidatingNode)
	if !ok {
		return
	}

	nodeCopy := n.DeepCopy()
	nodeCopy.Source = o.source

	// For local node, update the LocalNodeStore with PodCIDR from clustermesh
	if n.IsLocal() {
		o.logger.Info(
			"Received own node information from clustermesh etcd",
			logfields.NodeName, nodeCopy.Name,
			logfields.V4Prefix, nodeCopy.IPv4AllocCIDR,
			logfields.V6Prefix, nodeCopy.IPv6AllocCIDR,
		)
		
		// Update the local node store with PodCIDR information
		if nodeCopy.IPv4AllocCIDR != nil && option.Config.EnableIPv4 {
			o.localNodeStore.Update(func(ln *node.LocalNode) {
				ln.IPv4AllocCIDR = nodeCopy.IPv4AllocCIDR
			})
		}
		if nodeCopy.IPv6AllocCIDR != nil && option.Config.EnableIPv6 {
			o.localNodeStore.Update(func(ln *node.LocalNode) {
				ln.IPv6AllocCIDR = nodeCopy.IPv6AllocCIDR
			})
		}
		
		// Signal that the local node has been received (only once)
		o.localNodeOnce.Do(func() {
			o.logger.Info("Local node received from clustermesh etcd, signaling ready")
			close(o.localNodeReady)
		})
	} else {
		// For remote nodes, update the node manager as usual
		o.nodeManager.NodeUpdated(*nodeCopy)
	}
}

func (o *localNodeObserver) OnDelete(k store.NamedKey) {
	n, ok := k.(*nodeStore.ValidatingNode)
	if !ok || n.IsLocal() {
		return
	}

	nodeCopy := n.DeepCopy()
	nodeCopy.Source = o.source
	o.nodeManager.NodeDeleted(*nodeCopy)
}

// setupNodeWatcher configures watching of CiliumNode data from clustermesh etcd.
// The watcherReady channel will be closed once the watcher is set up and actively watching.
// The localNodeReady channel will be closed once the local node is received from clustermesh.
func setupNodeWatcher(ctx context.Context, params cepKVStoreClientParams, client kvstore.Client, clusterName string, logger *slog.Logger, watcherReady chan struct{}, localNodeReady chan struct{}) {
	// Create a custom observer that handles local nodes for PodCIDR configuration
	// Use source.KVStore to indicate these nodes come from kvstore (clustermesh etcd)
	observer := &localNodeObserver{
		nodeManager:    params.NodeManager,
		localNodeStore: params.LocalNodeStore,
		source:         source.KVStore,
		logger:         logger,
		localNodeReady: localNodeReady,
	}

	// Watch the nodes path in the clustermesh etcd
	// The path format is: cilium/state/nodes/v1/<cluster-name>/<node-name>
	nodePath := path.Join(nodeStore.NodeStorePrefix, clusterName)

	// Create validators to ensure we only accept nodes from our cluster
	// Note: We don't use ClusterIDValidator here because ClusterInfo.ID may not be
	// populated yet during bootstrap. ClusterNameValidator is sufficient for validation.
	keyCreator := nodeStore.ValidatingKeyCreator(
		nodeStore.ClusterNameValidator(clusterName),
		nodeStore.NameValidator(),
	)

	// Create a store factory
	storeFactory := store.NewFactory(logger, store.MetricsProvider())

	// Start watching the nodes in a goroutine
	go func() {
		// Create a watch store to observe node changes from clustermesh etcd
		nodeWatcher := storeFactory.NewWatchStore(
			clusterName,
			keyCreator,
			observer,
			store.RWSWithOnSyncCallback(func(ctx context.Context) {
				// Called when initial sync is complete
				logger.Info("Initial node sync from clustermesh completed")
				params.NodeManager.NodeSync()
			}),
		)

		logger.Info("Starting to watch nodes from clustermesh etcd", logfields.Path, nodePath)
		
		// Signal that the watcher is now set up and ready to receive updates
		close(watcherReady)

		// Watch will block and continuously synchronize nodes from clustermesh etcd
		// Log if it exits unexpectedly
		nodeWatcher.Watch(ctx, client, nodePath)
		logger.Warn("Node watcher exited", logfields.Path, nodePath)
	}()
}

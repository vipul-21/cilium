// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/hive/cell"

	cmcommon "github.com/cilium/cilium/pkg/clustermesh/common"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// Common client name for both CEP and CES modes - they read from the same etcd path
const cepClientName = "ipcache-clustermesh-ceps"

type cepKVStoreClientParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Logger    *slog.Logger

	Config      *option.DaemonConfig
	ClusterInfo cmtypes.ClusterInfo

	ClusterMeshConfig   cmcommon.Config
	RemoteClientFactory cmcommon.RemoteClientFactoryFn
}

type cepKVStoreClientOut struct {
	cell.Out

	Client kvstore.Client `name:"ipcache-clustermesh-ceps"`
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

	params.Lifecycle.Append(cell.Hook{
		OnStop: func(cell.HookContext) error {
			cancel()
			backend.Close()
			return nil
		},
	})

	return cepKVStoreClientOut{Client: client}, nil
}

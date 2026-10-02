// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/endpointmanager"
	fqdnconfig "github.com/cilium/cilium/pkg/fqdn/config"
	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// Cell provides the standalone DNS proxy gRPC server.
// It is responsible for sending the DNS rules and IP cache updates
// to the standalone DNS proxy. It also handles the DNS responses
// from the standalone DNS proxy and updates the DNS rules and IP cache
// accordingly. It receives the DNS rules during the endpoint regeneration
// event and listens for ip cache updates from the ipcache.
var Cell = cell.Module(
	"sdp-grpc-server",
	"Provides the standalone DNS proxy gRPC server",

	cell.Provide(newDefaultListener),
	cell.ProvidePrivate(newPolicyRulesTable),
	cell.ProvidePrivate(newIdentityToIPsTable),
	cell.Provide(newServer),
)

type serverParams struct {
	cell.In

	Logger             *slog.Logger
	EndpointsLookup    endpointmanager.EndpointsLookup
	DNSRequestHandler  messagehandler.DNSMessageHandler
	IPCache            *ipcache.IPCache
	JobGroup           job.Group
	Config             fqdnconfig.Config
	DaemonConfig       *option.DaemonConfig
	DefaultListener    listenConfig
	DB                 *statedb.DB
	PolicyRulesTable   statedb.RWTable[PolicyRules]
	IdentityToIPsTable statedb.RWTable[identityToIPs]
}

func newServer(params serverParams) *FQDNDataServer {

	if !params.Config.EnableStandaloneDNSProxy {
		return nil
	}

	if !params.DaemonConfig.EnableL7Proxy {
		params.Logger.Error("Standalone DNS proxy requires L7 proxy to be enabled")
		return nil
	}

	if params.Config.ToFQDNsProxyPort == 0 || params.Config.StandaloneDNSProxyServerPort == 0 {
		params.Logger.Error("Standalone DNS proxy requires a valid port number to be set")
		return nil
	}

	srv := NewServer(params)
	params.IPCache.AddListener(srv)

	params.JobGroup.Add(job.OneShot("sdp-grpc-server", srv.ListenAndServe,
		job.WithRetry(3, &job.ExponentialBackoff{Min: 1 * time.Second, Max: 5 * time.Second}),
		job.WithShutdown()))

	return srv
}

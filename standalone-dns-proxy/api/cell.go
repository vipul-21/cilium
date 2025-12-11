// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	sdpDefaults "github.com/cilium/cilium/standalone-dns-proxy/pkg/defaults"
)

const (
	// StandaloneDNSProxyAPISocketPath is the path to the Unix domain socket on which
	// to serve API requests from the standalone DNS proxy.
	StandaloneDNSProxyAPISocketPath = "standalone-dns-proxy-api-socket-path"
)

var Cell = cell.Module(
	"standalone-dns-proxy-api",
	"Standalone DNS Proxy API Server",

	cell.Config(defaultConfig),
	cell.Provide(newServer),
	cell.Invoke(func(*Server) {}),
)

type Config struct {
	// StandaloneDNSProxyAPISocketPath is the path to the Unix domain socket for the API server.
	// If empty, defaults to /var/run/cilium/standalone-dns-proxy-api.sock
	StandaloneDNSProxyAPISocketPath string
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String(StandaloneDNSProxyAPISocketPath, def.StandaloneDNSProxyAPISocketPath,
		"Path to Unix domain socket for API server")
}

var defaultConfig = Config{
	StandaloneDNSProxyAPISocketPath: sdpDefaults.APISockPath,
}

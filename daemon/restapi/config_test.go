// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restapi

import (
	"testing"

	"github.com/stretchr/testify/require"

	fqdnconfig "github.com/cilium/cilium/pkg/fqdn/config"
	"github.com/cilium/cilium/pkg/option"
)

func TestGetConfigMap(t *testing.T) {
	cfg := fqdnconfig.DefaultConfig
	cfg.StandaloneDNSProxyServerPort = 11095
	cfg.ToFQDNsEnableDNSCompression = false
	handler := getConfigHandler{
		daemonConfig: &option.DaemonConfig{EnableIPv4: true},
		fqdnConfig:   cfg,
	}

	got := handler.getConfigMap()
	require.Equal(t, true, got["EnableIPv4"])
	require.Equal(t, 11095, got["StandaloneDNSProxyServerPort"])
	require.Equal(t, false, got["ToFQDNsEnableDNSCompression"])
	require.Equal(t, true, got["ToFQDNsPreAllocate"])
	require.NotContains(t, got, "Opts")
	require.NotContains(t, got, "FQDNConfig")
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restapi

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/fqdn/config"
	"github.com/cilium/cilium/pkg/option"
	fakewireguard "github.com/cilium/cilium/pkg/wireguard/fake"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

func TestReservedPortsConfig(t *testing.T) {
	for _, tt := range []struct {
		transparent bool
		reserved    string
		want        string
	}{
		{false, defaults.ContainerIPLocalReservedPortsAuto, ""},
		{true, defaults.ContainerIPLocalReservedPortsAuto, strconv.Itoa(wgTypes.ListenPort)},
		{false, "12345", "12345"},
		{true, "12345", "12345"},
	} {
		t.Run(fmt.Sprintf("%t/%s", tt.transparent, tt.reserved), func(t *testing.T) {
			handler := getConfigHandler{
				logger:       hivetest.Logger(t),
				daemonConfig: &option.DaemonConfig{ContainerIPLocalReservedPorts: tt.reserved},
				fqdnConfig:   config.Config{DNSProxyEnableTransparentMode: tt.transparent},
				wgConfig:     fakewireguard.Config{EnableWireguard: true},
				tunnelConfig: tunnel.NewTestConfig(tunnel.Disabled),
			}
			require.Equal(t, tt.want, handler.getIPLocalReservedPorts())
		})
	}
}

func TestGetConfigMap(t *testing.T) {
	cfg := config.DefaultConfig
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

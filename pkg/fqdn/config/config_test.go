// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config_test

import (
	"strings"
	"testing"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/fqdn/config"
	"github.com/cilium/cilium/pkg/time"
)

func TestConfig(t *testing.T) {
	overridden := config.DefaultConfig
	overridden.EnableStandaloneDNSProxy = true
	overridden.StandaloneDNSProxyServerPort = 11095
	overridden.ToFQDNsEnableDNSCompression = false
	overridden.DNSMaxIPsPerRestoredRule = 23
	overridden.DNSProxyConcurrencyProcessingGracePeriod = 250 * time.Millisecond

	for _, tt := range []struct {
		name      string
		configure func(*testing.T, *hive.Hive)
		want      config.Config
	}{
		{
			name: "defaults",
			want: config.DefaultConfig,
		},
		{
			name: "flags",
			configure: func(t *testing.T, h *hive.Hive) {
				flags := pflag.NewFlagSet(t.Name(), pflag.ContinueOnError)
				h.RegisterFlags(flags)
				require.NoError(t, flags.Parse([]string{
					"--enable-standalone-dns-proxy",
					"--standalone-dns-proxy-server-port=11095",
					"--tofqdns-enable-dns-compression=false",
					"--dns-max-ips-per-restored-rule=23",
					"--dnsproxy-concurrency-processing-grace-period=250ms",
				}))
			},
			want: overridden,
		},
		{
			name: "environment",
			configure: func(t *testing.T, _ *hive.Hive) {
				t.Setenv("CILIUM_ENABLE_STANDALONE_DNS_PROXY", "true")
				t.Setenv("CILIUM_STANDALONE_DNS_PROXY_SERVER_PORT", "11095")
				t.Setenv("CILIUM_TOFQDNS_ENABLE_DNS_COMPRESSION", "false")
				t.Setenv("CILIUM_DNS_MAX_IPS_PER_RESTORED_RULE", "23")
				t.Setenv("CILIUM_DNSPROXY_CONCURRENCY_PROCESSING_GRACE_PERIOD", "250ms")
			},
			want: overridden,
		},
		{
			name: "config-file",
			configure: func(t *testing.T, h *hive.Hive) {
				h.Viper().SetConfigType("yaml")
				require.NoError(t, h.Viper().ReadConfig(strings.NewReader(`
enable-standalone-dns-proxy: true
standalone-dns-proxy-server-port: 11095
tofqdns-enable-dns-compression: false
dns-max-ips-per-restored-rule: 23
dnsproxy-concurrency-processing-grace-period: 250ms
`)))
			},
			want: overridden,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var got config.Config
			h := hive.NewWithOptions(
				hive.Options{EnvPrefix: "CILIUM_"},
				config.Cell,
				cell.Invoke(func(cfg config.Config) { got = cfg }),
			)
			if tt.configure != nil {
				tt.configure(t, h)
			}
			require.NoError(t, h.Populate(hivetest.Logger(t)))
			require.Equal(t, tt.want, got)
		})
	}
}

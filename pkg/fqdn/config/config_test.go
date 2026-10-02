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
	overridden.ToFQDNsPreAllocate = false
	overridden.DNSProxyLockCount = 17
	overridden.DNSProxyLockTimeout = time.Second
	overridden.FQDNProxyResponseMaxDelay = 2 * time.Second
	overridden.ToFQDNsPreCache = "/tmp/fqdn-cache.json"
	overridden.DNSPolicyUnloadOnShutdown = true
	overridden.ToFQDNsProxyPort = 10053
	overridden.FQDNRejectResponse = config.FQDNProxyDenyWithNameError
	overridden.FQDNRegexCompileLRUSize = 2048
	overridden.DNSProxyConcurrencyLimit = 7
	overridden.DNSProxyEnableTransparentMode = true
	overridden.DNSProxySocketLingerTimeout = -1

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
					"--tofqdns-preallocate-identities=false",
					"--dnsproxy-lock-count=17",
					"--dnsproxy-lock-timeout=1s",
					"--tofqdns-proxy-response-max-delay=2s",
					"--tofqdns-pre-cache=/tmp/fqdn-cache.json",
					"--dns-policy-unload-on-shutdown",
					"--tofqdns-proxy-port=10053",
					"--tofqdns-dns-reject-response-code=nameError",
					"--fqdn-regex-compile-lru-size=2048",
					"--dnsproxy-concurrency-limit=7",
					"--dnsproxy-enable-transparent-mode",
					"--dnsproxy-socket-linger-timeout=-1",
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
				t.Setenv("CILIUM_TOFQDNS_PREALLOCATE_IDENTITIES", "false")
				t.Setenv("CILIUM_DNSPROXY_LOCK_COUNT", "17")
				t.Setenv("CILIUM_DNSPROXY_LOCK_TIMEOUT", "1s")
				t.Setenv("CILIUM_TOFQDNS_PROXY_RESPONSE_MAX_DELAY", "2s")
				t.Setenv("CILIUM_TOFQDNS_PRE_CACHE", "/tmp/fqdn-cache.json")
				t.Setenv("CILIUM_DNS_POLICY_UNLOAD_ON_SHUTDOWN", "true")
				t.Setenv("CILIUM_TOFQDNS_PROXY_PORT", "10053")
				t.Setenv("CILIUM_TOFQDNS_DNS_REJECT_RESPONSE_CODE", "nameError")
				t.Setenv("CILIUM_FQDN_REGEX_COMPILE_LRU_SIZE", "2048")
				t.Setenv("CILIUM_DNSPROXY_CONCURRENCY_LIMIT", "7")
				t.Setenv("CILIUM_DNSPROXY_ENABLE_TRANSPARENT_MODE", "true")
				t.Setenv("CILIUM_DNSPROXY_SOCKET_LINGER_TIMEOUT", "-1")
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
tofqdns-preallocate-identities: false
dnsproxy-lock-count: 17
dnsproxy-lock-timeout: 1s
tofqdns-proxy-response-max-delay: 2s
tofqdns-pre-cache: /tmp/fqdn-cache.json
dns-policy-unload-on-shutdown: true
tofqdns-proxy-port: 10053
tofqdns-dns-reject-response-code: nameError
fqdn-regex-compile-lru-size: 2048
dnsproxy-concurrency-limit: 7
dnsproxy-enable-transparent-mode: true
dnsproxy-socket-linger-timeout: -1
`)))
			},
			want: overridden,
		},
	} {
		for _, profile := range []struct {
			name     string
			cell     cell.Cell
			defaults config.Config
		}{
			{"agent", config.Cell, config.DefaultConfig},
			{"standalone", config.StandaloneCell, config.DefaultStandaloneConfig},
		} {
			t.Run(profile.name+"/"+tt.name, func(t *testing.T) {
				var got config.Config
				h := hive.NewWithOptions(
					hive.Options{EnvPrefix: "CILIUM_"},
					profile.cell,
					cell.Invoke(func(cfg config.Config) { got = cfg }),
				)
				want := tt.want
				if tt.configure != nil {
					tt.configure(t, h)
				} else {
					want = profile.defaults
				}
				require.NoError(t, h.Populate(hivetest.Logger(t)))
				require.Equal(t, want, got)
			})
		}
	}
}

func TestStandaloneDefaults(t *testing.T) {
	want := config.DefaultConfig
	want.DNSProxyLockCount = 0
	want.DNSProxyLockTimeout = 0
	want.FQDNProxyResponseMaxDelay = 0
	want.FQDNRejectResponse = ""
	want.FQDNRegexCompileLRUSize = 0
	want.DNSProxySocketLingerTimeout = 0

	var got config.Config
	h := hive.New(
		config.StandaloneCell,
		cell.Invoke(func(cfg config.Config) { got = cfg }),
	)
	require.NoError(t, h.Populate(hivetest.Logger(t)))
	require.Equal(t, want, got)
}

func TestFlagMetadata(t *testing.T) {
	flags := pflag.NewFlagSet(t.Name(), pflag.ContinueOnError)
	config.DefaultConfig.Flags(flags)
	require.True(t, flags.Lookup(config.DNSProxyLockCount).Hidden)
	require.True(t, flags.Lookup(config.DNSProxyLockTimeout).Hidden)
	require.True(t, flags.Lookup(config.FQDNRegexCompileLRUSize).Hidden)
	require.Equal(t, "This option is obsolete and will be removed in v1.21", flags.Lookup(config.ToFQDNsPreCache).Deprecated)
}

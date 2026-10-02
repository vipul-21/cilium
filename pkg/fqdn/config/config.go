// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package config defines startup configuration shared by the FQDN components.
package config

import (
	"fmt"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/time"
)

const (
	EnableStandaloneDNSProxy                 = "enable-standalone-dns-proxy"
	StandaloneDNSProxyServerPort             = "standalone-dns-proxy-server-port"
	DNSMaxIPsPerRestoredRule                 = "dns-max-ips-per-restored-rule"
	ToFQDNsEnableDNSCompression              = "tofqdns-enable-dns-compression"
	DNSProxyConcurrencyProcessingGracePeriod = "dnsproxy-concurrency-processing-grace-period"
	ToFQDNsPreAllocate                       = "tofqdns-preallocate-identities"
	DNSProxyLockCount                        = "dnsproxy-lock-count"
	DNSProxyLockTimeout                      = "dnsproxy-lock-timeout"
	FQDNProxyResponseMaxDelay                = "tofqdns-proxy-response-max-delay"
	ToFQDNsPreCache                          = "tofqdns-pre-cache"
	DNSPolicyUnloadOnShutdown                = "dns-policy-unload-on-shutdown"
	ToFQDNsProxyPort                         = "tofqdns-proxy-port"
	FQDNRejectResponseCode                   = "tofqdns-dns-reject-response-code"
	FQDNRegexCompileLRUSize                  = "fqdn-regex-compile-lru-size"
	DNSProxyConcurrencyLimit                 = "dnsproxy-concurrency-limit"
	DNSProxyEnableTransparentMode            = "dnsproxy-enable-transparent-mode"
	DNSProxySocketLingerTimeout              = "dnsproxy-socket-linger-timeout"
	ToFQDNsMinTTL                            = "tofqdns-min-ttl"
	ToFQDNsMaxIPsPerHost                     = "tofqdns-endpoint-max-ip-per-hostname"
	ToFQDNsMaxDeferredConnectionDeletes      = "tofqdns-max-deferred-connection-deletes"
	ToFQDNsIdleConnectionGracePeriod         = "tofqdns-idle-connection-grace-period"

	FQDNProxyDenyWithNameError = "nameError"
	FQDNProxyDenyWithRefused   = "refused"
)

var FQDNRejectOptions = []string{FQDNProxyDenyWithNameError, FQDNProxyDenyWithRefused}

type Config struct {
	EnableStandaloneDNSProxy                 bool
	StandaloneDNSProxyServerPort             int
	ToFQDNsEnableDNSCompression              bool
	DNSMaxIPsPerRestoredRule                 int
	DNSProxyConcurrencyProcessingGracePeriod time.Duration
	ToFQDNsPreAllocate                       bool `mapstructure:"tofqdns-preallocate-identities"`
	DNSProxyLockCount                        int
	DNSProxyLockTimeout                      time.Duration
	FQDNProxyResponseMaxDelay                time.Duration `mapstructure:"tofqdns-proxy-response-max-delay"`
	ToFQDNsPreCache                          string
	DNSPolicyUnloadOnShutdown                bool
	ToFQDNsProxyPort                         int
	FQDNRejectResponse                       string `mapstructure:"tofqdns-dns-reject-response-code"`
	FQDNRegexCompileLRUSize                  uint
	DNSProxyConcurrencyLimit                 int
	DNSProxyEnableTransparentMode            bool
	DNSProxySocketLingerTimeout              int
	ToFQDNsMinTTL                            int
	ToFQDNsMaxIPsPerHost                     int `mapstructure:"tofqdns-endpoint-max-ip-per-hostname"`
	ToFQDNsMaxDeferredConnectionDeletes      int
	ToFQDNsIdleConnectionGracePeriod         time.Duration
}

var DefaultConfig = Config{
	EnableStandaloneDNSProxy:                 false,
	StandaloneDNSProxyServerPort:             10095,
	ToFQDNsEnableDNSCompression:              true,
	DNSMaxIPsPerRestoredRule:                 1000,
	DNSProxyConcurrencyProcessingGracePeriod: 0,
	ToFQDNsPreAllocate:                       true,
	DNSProxyLockCount:                        131,
	DNSProxyLockTimeout:                      500 * time.Millisecond,
	FQDNProxyResponseMaxDelay:                100 * time.Millisecond,
	FQDNRejectResponse:                       FQDNProxyDenyWithRefused,
	FQDNRegexCompileLRUSize:                  1024,
	DNSProxySocketLingerTimeout:              10,
	ToFQDNsMaxIPsPerHost:                     1000,
	ToFQDNsMaxDeferredConnectionDeletes:      10000,
}

// These legacy flags were not registered by standalone-dns-proxy, so absent
// settings used zero values rather than the agent's defaults.
var DefaultStandaloneConfig = func() Config {
	cfg := DefaultConfig
	cfg.DNSProxyLockCount = 0
	cfg.DNSProxyLockTimeout = 0
	cfg.FQDNProxyResponseMaxDelay = 0
	cfg.FQDNRejectResponse = ""
	cfg.FQDNRegexCompileLRUSize = 0
	cfg.DNSProxySocketLingerTimeout = 0
	cfg.ToFQDNsMaxIPsPerHost = 0
	cfg.ToFQDNsMaxDeferredConnectionDeletes = 0
	return cfg
}()

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableStandaloneDNSProxy, def.EnableStandaloneDNSProxy, "Enables standalone DNS proxy")
	flags.Int(StandaloneDNSProxyServerPort, def.StandaloneDNSProxyServerPort, "Global port on which the gRPC server for standalone DNS proxy should listen")
	flags.Bool(ToFQDNsEnableDNSCompression, def.ToFQDNsEnableDNSCompression, "Allow the DNS proxy to compress responses to endpoints that are larger than 512 Bytes or the EDNS0 option, if present")
	flags.Int(DNSMaxIPsPerRestoredRule, def.DNSMaxIPsPerRestoredRule, "Maximum number of IPs to maintain for each restored DNS rule")
	flags.Duration(DNSProxyConcurrencyProcessingGracePeriod, def.DNSProxyConcurrencyProcessingGracePeriod, "Grace time to wait when DNS proxy concurrent limit has been reached during DNS message processing")
	flags.Bool(ToFQDNsPreAllocate, def.ToFQDNsPreAllocate, "Preallocate identities for ToFQDN selectors. This reduces proxied DNS response latency. Disable if you have many ToFQDN selectors.")
	flags.Int(DNSProxyLockCount, def.DNSProxyLockCount, "Array size containing mutexes which protect against parallel handling of DNS response names. Preferably use prime numbers")
	flags.MarkHidden(DNSProxyLockCount)
	flags.Duration(DNSProxyLockTimeout, def.DNSProxyLockTimeout, fmt.Sprintf("Timeout when acquiring the locks controlled by --%s", DNSProxyLockCount))
	flags.MarkHidden(DNSProxyLockTimeout)
	flags.Duration(FQDNProxyResponseMaxDelay, def.FQDNProxyResponseMaxDelay, "The maximum time the DNS proxy holds an allowed DNS response before sending it along. Responses are sent as soon as the datapath is updated with the new IP information.")
	flags.String(ToFQDNsPreCache, def.ToFQDNsPreCache, "DNS cache data at this path is preloaded on agent startup")
	flags.MarkDeprecated(ToFQDNsPreCache, "This option is obsolete and will be removed in v1.21")
	flags.Bool(DNSPolicyUnloadOnShutdown, def.DNSPolicyUnloadOnShutdown, "Unload DNS policy rules on graceful shutdown")
	flags.Int(ToFQDNsProxyPort, def.ToFQDNsProxyPort, "Global port on which the in-agent DNS proxy should listen. Default 0 is a OS-assigned port.")
	flags.String(FQDNRejectResponseCode, def.FQDNRejectResponse, fmt.Sprintf("DNS response code for rejecting DNS requests, available options are '%v'", FQDNRejectOptions))
	flags.Uint(FQDNRegexCompileLRUSize, def.FQDNRegexCompileLRUSize, "Size of the FQDN regex compilation LRU. Useful for heavy but repeated DNS L7 rules with MatchName or MatchPattern")
	flags.MarkHidden(FQDNRegexCompileLRUSize)
	flags.Int(DNSProxyConcurrencyLimit, def.DNSProxyConcurrencyLimit, "Limit concurrency of DNS message processing")
	flags.Bool(DNSProxyEnableTransparentMode, def.DNSProxyEnableTransparentMode, "Enable DNS proxy transparent mode")
	flags.Int(DNSProxySocketLingerTimeout, def.DNSProxySocketLingerTimeout, "Timeout (in seconds) when closing the connection between the DNS proxy and the upstream server. "+
		"If set to 0, the connection is closed immediately (with TCP RST). If set to -1, the connection is closed asynchronously in the background")
	flags.Int(ToFQDNsMinTTL, def.ToFQDNsMinTTL, "The minimum time, in seconds, to use DNS data for toFQDNs policies")
	flags.Int(ToFQDNsMaxIPsPerHost, def.ToFQDNsMaxIPsPerHost, "Maximum number of IPs to maintain per FQDN name for each endpoint")
	flags.Int(ToFQDNsMaxDeferredConnectionDeletes, def.ToFQDNsMaxDeferredConnectionDeletes, "Maximum number of IPs to retain for expired DNS lookups with still-active connections")
	flags.Duration(ToFQDNsIdleConnectionGracePeriod, def.ToFQDNsIdleConnectionGracePeriod, "Time during which idle but previously active connections with expired DNS lookups are still considered alive (default 0s)")
}

func (cfg Config) Validate() error {
	if cfg.ToFQDNsMaxDeferredConnectionDeletes < 0 {
		return fmt.Errorf("%s must be positive, or 0 to disable deferred connection deletion", ToFQDNsMaxDeferredConnectionDeletes)
	}
	return nil
}

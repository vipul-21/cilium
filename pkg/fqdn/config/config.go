// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package config defines startup configuration shared by the FQDN components.
package config

import (
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
)

type Config struct {
	EnableStandaloneDNSProxy                 bool
	StandaloneDNSProxyServerPort             int
	ToFQDNsEnableDNSCompression              bool
	DNSMaxIPsPerRestoredRule                 int
	DNSProxyConcurrencyProcessingGracePeriod time.Duration
	ToFQDNsPreAllocate                       bool `mapstructure:"tofqdns-preallocate-identities"`
}

var DefaultConfig = Config{
	EnableStandaloneDNSProxy:                 false,
	StandaloneDNSProxyServerPort:             10095,
	ToFQDNsEnableDNSCompression:              true,
	DNSMaxIPsPerRestoredRule:                 1000,
	DNSProxyConcurrencyProcessingGracePeriod: 0,
	ToFQDNsPreAllocate:                       true,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableStandaloneDNSProxy, def.EnableStandaloneDNSProxy, "Enables standalone DNS proxy")
	flags.Int(StandaloneDNSProxyServerPort, def.StandaloneDNSProxyServerPort, "Global port on which the gRPC server for standalone DNS proxy should listen")
	flags.Bool(ToFQDNsEnableDNSCompression, def.ToFQDNsEnableDNSCompression, "Allow the DNS proxy to compress responses to endpoints that are larger than 512 Bytes or the EDNS0 option, if present")
	flags.Int(DNSMaxIPsPerRestoredRule, def.DNSMaxIPsPerRestoredRule, "Maximum number of IPs to maintain for each restored DNS rule")
	flags.Duration(DNSProxyConcurrencyProcessingGracePeriod, def.DNSProxyConcurrencyProcessingGracePeriod, "Grace time to wait when DNS proxy concurrent limit has been reached during DNS message processing")
	flags.Bool(ToFQDNsPreAllocate, def.ToFQDNsPreAllocate, "Preallocate identities for ToFQDN selectors. This reduces proxied DNS response latency. Disable if you have many ToFQDN selectors.")
}

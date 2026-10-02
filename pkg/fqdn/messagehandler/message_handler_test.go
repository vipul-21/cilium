// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package messagehandler

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"

	ciliumdns "github.com/cilium/dns"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn"
	fqdnconfig "github.com/cilium/cilium/pkg/fqdn/config"
	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/namemanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	mockipc "github.com/cilium/cilium/pkg/testutils/ipcache"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/time"
)

type deadlineNameManager struct {
	namemanager.NameManager
	deadline time.Time
}

func (*deadlineNameManager) LockName(string)   {}
func (*deadlineNameManager) UnlockName(string) {}

func (m *deadlineNameManager) UpdateGenerateDNS(ctx context.Context, _ time.Time, _ string, _ *fqdn.DNSIPRecords, _ ...*fqdn.DNSCache) <-chan error {
	m.deadline, _ = ctx.Deadline()
	done := make(chan error)
	close(done)
	return done
}

func TestResponseDeadlineConfig(t *testing.T) {
	for _, delay := range []time.Duration{100 * time.Millisecond, 2 * time.Second} {
		t.Run(delay.String(), func(t *testing.T) {
			cfg := fqdnconfig.DefaultConfig
			cfg.FQDNProxyResponseMaxDelay = delay
			manager := &deadlineNameManager{}
			handler := NewDNSMessageHandler(DNSMessageHandlerParams{
				Logger:      hivetest.Logger(t),
				Config:      cfg,
				NameManager: manager,
			})
			lookupTime := time.Now()
			ips := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
			ep := &endpoint.Endpoint{DNSHistory: fqdn.NewDNSCache(0)}
			ep.DNSHistory.Update(lookupTime, "cilium.io.", ips, 60)

			before := time.Now()
			handler.UpdateOnDNSMsg(lookupTime, ep, "cilium.io.", ips, 60, &dnsproxy.ProxyRequestContext{})
			after := time.Now()
			require.False(t, manager.deadline.Before(before.Add(delay)))
			require.False(t, manager.deadline.After(after.Add(delay)))
		})
	}
}

func BenchmarkNotifyOnDNSMsg(b *testing.B) {
	var (
		logger    = hivetest.Logger(b)
		ciliumMsg = &ciliumdns.Msg{
			MsgHdr: ciliumdns.MsgHdr{
				Response: true,
			},
			Question: []ciliumdns.Question{{
				Name: dns.FQDN("cilium.io"),
			}},
			Answer: []ciliumdns.RR{&ciliumdns.A{
				Hdr: ciliumdns.RR_Header{
					Name: dns.FQDN("cilium.io"),
					Ttl:  3600,
				},
				A: net.ParseIP("192.0.2.3"),
			}},
		}
		ebpfMsg = &ciliumdns.Msg{
			MsgHdr: ciliumdns.MsgHdr{
				Response: true,
			},
			Compress: false,
			Question: []ciliumdns.Question{{
				Name: dns.FQDN("ebpf.io"),
			}},
			Answer: []ciliumdns.RR{&ciliumdns.A{
				Hdr: ciliumdns.RR_Header{
					Name: dns.FQDN("ebpf.io"),
					Ttl:  3600,
				},
				A: net.ParseIP("192.0.2.4"),
			}},
		}
		srvAddr    = netip.MustParseAddrPort("10.96.64.1:53")
		emptyPRCtx = &dnsproxy.ProxyRequestContext{}
	)

	ciliumMsgDetails, err := dnsproxy.ExtractResponseMsgDetails(ciliumMsg)
	require.NoError(b, err)
	ebpfMsgDetails, err := dnsproxy.ExtractResponseMsgDetails(ebpfMsg)
	require.NoError(b, err)

	var (
		ciliumIOSel             = api.FQDNSelector{MatchName: "cilium.io"}
		ciliumIOSelMatchPattern = api.FQDNSelector{MatchPattern: "*cilium.io."}
		ebpfIOSel               = api.FQDNSelector{MatchName: "ebpf.io"}

		wg sync.WaitGroup
	)

	policyRepo := policy.NewPolicyRepository(logger, cmtypes.DefaultClusterInfo, nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop())
	ipc := &mockipc.MockIPCache{}
	nm := namemanager.New(namemanager.ManagerParams{
		Config: namemanager.NameManagerConfig{
			MinTTL:   1,
			StateDir: defaults.StateDir,
		},
		FQDNConfig: fqdnconfig.DefaultConfig,
		IPCache:    ipc,
		PolicyRepo: policyRepo,
		Logger:     logger,
	})
	policyRepo.GetSelectorCache().SetLocalIdentityNotifier(nm)

	handler := NewDNSMessageHandler(
		DNSMessageHandlerParams{
			Logger:            logger,
			Config:            fqdnconfig.DefaultConfig,
			NameManager:       nm,
			ProxyAccessLogger: accesslog.NewProxyAccessLogger(logger, accesslog.ProxyAccessLoggerConfig{}, &noopNotifier{}, &dummyInfoRegistry{}, node.NewTestLocalNodeStore(node.LocalNode{})),
		})

	// Register rules (simulates applied policies).
	dscu := &testpolicy.DummySelectorCacheUser{}
	selectorsToAdd := api.FQDNSelectorSlice{ciliumIOSel, ciliumIOSelMatchPattern, ebpfIOSel}
	policyRepo.GetSelectorCache().AddSelectors(dscu, types.ToSelectors(selectorsToAdd...)...)

	const nEndpoints int = 1024

	// Initialize the endpoints.
	endpoints := make([]*endpoint.Endpoint, nEndpoints)
	for i := range endpoints {
		endpoints[i] = &endpoint.Endpoint{
			ID:   uint16(i),
			IPv4: netip.MustParseAddr(fmt.Sprintf("10.96.%d.%d", i/256, i%256)),
			SecurityIdentity: &identity.Identity{
				ID: identity.NumericIdentity(i % int(cmtypes.DefaultClusterInfo.MaximumAllocationIdentity())),
			},
			DNSZombies: &fqdn.DNSZombieMappings{
				Mutex: lock.Mutex{},
			},
		}
		ep := endpoints[i]
		ep.UpdateLogger(nil)
		ep.DNSHistory = fqdn.NewDNSCache(0)
	}

	b.ReportAllocs()

	// Simulate parallel DNS responses from the upstream DNS for cilium.io and
	// ebpf.io, done by every endpoint.
	for b.Loop() {
		for _, ep := range endpoints {
			wg.Go(func() {
				// Using a hardcoded string representing endpoint IP:port as this
				// parameter is only used in logging. Not using the endpoint's IP
				// so we don't spend any time in the benchmark on converting from
				// net.IP to string.
				require.NoError(b, handler.NotifyOnDNSMsg(time.Now(), ep, "10.96.64.8:12345", 0, srvAddr, ciliumMsgDetails, "udp", true, emptyPRCtx))
				require.NoError(b, handler.NotifyOnDNSMsg(time.Now(), ep, "10.96.64.4:54321", 0, srvAddr, ebpfMsgDetails, "udp", true, emptyPRCtx))
			})
		}
		wg.Wait()
	}
}

type noopNotifier struct{}

func (*noopNotifier) NewProxyLogRecord(l *accesslog.LogRecord) error { return nil }

type dummyInfoRegistry struct{}

func (*dummyInfoRegistry) FillEndpointInfo(ctx context.Context, info *accesslog.EndpointInfo, addr netip.Addr) {
}

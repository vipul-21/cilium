// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/time"
)

// A name held by a still-alive zombie must remain resolvable in the global
// cache after a GC pass, because RegisterFQDNSelector backfills a newly
// registered selector from that cache. GC never re-introduces a mapping it has
// dropped (partialRestoreFromCache only restores entries present before the
// expiry), so a name pruned here would be lost for the life of the connection
// and any policy applied later would never select its IP.
func TestGCKeepsAliveZombieNamesResolvableForLaterSelectors(t *testing.T) {
	logger := hivetest.Logger(t)
	lookupTime := time.Now()
	sharedIP := netip.MustParseAddr("1.1.1.1")
	prefix := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("1.1.1.1/32"))

	epMgr := mgrMock{logger: logger, eps: make(sets.Set[*endpoint.Endpoint])}
	ep := &endpoint.Endpoint{
		ID:   uint16(1),
		IPv4: netip.MustParseAddr("10.96.0.1"),
		SecurityIdentity: &identity.Identity{
			ID: identity.NumericIdentity(int(identity.GetMaximumAllocationIdentity(cmtypes.DefaultClusterInfo.ID))),
		},
		DNSZombies: fqdn.NewDNSZombieMappings(logger, 10000, 10000),
		DNSHistory: fqdn.NewDNSCache(1),
	}
	ep.UpdateLogger(nil)
	epMgr.eps.Insert(ep)

	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context:           t.Context(),
		Logger:            logger,
		IdentityAllocator: testidentity.NewMockIdentityAllocator(nil),
		IdentityUpdater:   &dummyIdentityUpdater{},
	})
	ipc.TriggerLabelInjection()
	defer ipc.Shutdown()

	nameManager := New(ManagerParams{
		Logger: logger,
		Config: NameManagerConfig{
			MinTTL:            1,
			DNSProxyLockCount: defaults.DNSProxyLockCount,
			StateDir:          option.Config.StateDir,
		},
		EPMgr:   &epMgr,
		IPCache: ipc,
	})
	nameManager.bootstrapCompleted = true

	// One selector exists up front; github.com is deliberately not selected yet.
	require.NoError(t, ipc.WaitForRevision(t.Context(), nameManager.RegisterFQDNSelector(ciliumIOSel)))

	// Both names resolve to the same IP and are recorded through the DNS path.
	for _, name := range []string{dns.FQDN("cilium.io"), dns.FQDN("github.com")} {
		ep.DNSHistory.Update(lookupTime, name, []netip.Addr{sharedIP}, 1)
		<-nameManager.UpdateGenerateDNS(t.Context(), lookupTime, name,
			&fqdn.DNSIPRecords{TTL: 1, IPs: []netip.Addr{sharedIP}}, ep.DNSHistory)
	}
	require.Contains(t, nameManager.cache.LookupIP(sharedIP), dns.FQDN("github.com"))

	// Expire both names into zombies and mark the IP as carrying live traffic,
	// so the zombie is kept alive across GC.
	ep.DNSZombies.SetCTGCTime(lookupTime, lookupTime.Add(2*time.Minute))
	ep.DNSHistory.GC(lookupTime.Add(2*time.Second), ep.DNSZombies)
	ep.DNSZombies.MarkAlive(lookupTime.Add(time.Minute), sharedIP)

	require.NoError(t, nameManager.doGC(t.Context()))
	require.NoError(t, ipc.WaitForRevision(t.Context(), ipc.UpsertMetadataBatch()))

	// github.com matches no selector at this point, so nothing has asked for it.
	// It must still be resolvable, or the registration below cannot find it.
	require.Contains(t, nameManager.cache.LookupIP(sharedIP), dns.FQDN("github.com"),
		"an alive zombie's names must survive GC so a later selector can match them")

	// Apply the policy that selects github.com, after the GC pass.
	require.NoError(t, ipc.WaitForRevision(t.Context(), nameManager.RegisterFQDNSelector(githubSel)))

	id, found := ipc.LookupByPrefix(prefix.String())
	require.True(t, found, "the IP must still be in ipcache")
	ident := ipc.IdentityAllocator.LookupIdentityByID(t.Context(), id.ID)
	require.Contains(t, ident.Labels, githubSel.IdentityLabel().Key,
		"a selector registered after GC must still pick up the alive zombie's IP")
	require.Contains(t, ident.Labels, ciliumIOSel.IdentityLabel().Key)
}

// An alive zombie's names must not be re-cleaned on every GC pass. They are
// expired and immediately restored unchanged, which is pure churn proportional
// to the number of names held against a single connected IP, and that is the
// cost that makes GC overrun its interval once an IP accumulates many names.
//
// This is asserted on the cleaned-names counter rather than on cache contents,
// because the churn is invisible from the end state: the names are restored, so
// a pass that cleans all of them and one that cleans none look identical
// afterwards.
func TestGCDoesNotRecleanAliveZombieNamesEveryPass(t *testing.T) {
	logger := hivetest.Logger(t)
	lookupTime := time.Now()
	sharedIP := netip.MustParseAddr("1.1.1.1")

	cleaned := metric.NewCounter(metric.CounterOpts{Name: "test_fqdn_gc_cleaned"})
	oldCleaned := metrics.FQDNGarbageCollectorCleanedTotal
	metrics.FQDNGarbageCollectorCleanedTotal = cleaned
	defer func() { metrics.FQDNGarbageCollectorCleanedTotal = oldCleaned }()

	epMgr := mgrMock{logger: logger, eps: make(sets.Set[*endpoint.Endpoint])}
	ep := &endpoint.Endpoint{
		ID:   uint16(1),
		IPv4: netip.MustParseAddr("10.96.0.1"),
		SecurityIdentity: &identity.Identity{
			ID: identity.NumericIdentity(int(identity.GetMaximumAllocationIdentity(cmtypes.DefaultClusterInfo.ID))),
		},
		DNSZombies: fqdn.NewDNSZombieMappings(logger, 100000, 100000),
		DNSHistory: fqdn.NewDNSCache(1),
	}
	ep.UpdateLogger(nil)
	epMgr.eps.Insert(ep)

	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context:           t.Context(),
		Logger:            logger,
		IdentityAllocator: testidentity.NewMockIdentityAllocator(nil),
		IdentityUpdater:   &dummyIdentityUpdater{},
	})
	ipc.TriggerLabelInjection()
	defer ipc.Shutdown()

	nameManager := New(ManagerParams{
		Logger: logger,
		Config: NameManagerConfig{
			MinTTL:            1,
			DNSProxyLockCount: defaults.DNSProxyLockCount,
			StateDir:          option.Config.StateDir,
		},
		EPMgr:   &epMgr,
		IPCache: ipc,
	})
	nameManager.bootstrapCompleted = true
	require.NoError(t, ipc.WaitForRevision(t.Context(), nameManager.RegisterFQDNSelector(ciliumIOSel)))

	// Many names against one IP, the shape that makes this expensive.
	const nameCount = 50
	for i := range nameCount {
		name := dns.FQDN(fmt.Sprintf("n%d.cilium.io", i))
		ep.DNSHistory.Update(lookupTime, name, []netip.Addr{sharedIP}, 1)
		<-nameManager.UpdateGenerateDNS(t.Context(), lookupTime, name,
			&fqdn.DNSIPRecords{TTL: 1, IPs: []netip.Addr{sharedIP}}, ep.DNSHistory)
	}

	// Expire them into zombies kept alive by an ongoing connection.
	ep.DNSZombies.SetCTGCTime(lookupTime, lookupTime.Add(2*time.Minute))
	ep.DNSHistory.GC(lookupTime.Add(2*time.Second), ep.DNSZombies)
	ep.DNSZombies.MarkAlive(lookupTime.Add(time.Minute), sharedIP)

	// First pass absorbs the one-off expiry of the original lookups.
	require.NoError(t, nameManager.doGC(t.Context()))

	// Steady state: the connection is still alive and nothing new resolved, so
	// there is nothing left to clean.
	for range 3 {
		ep.DNSZombies.MarkAlive(time.Now().Add(time.Minute), sharedIP)
		before := cleaned.Get()
		require.NoError(t, nameManager.doGC(t.Context()))
		require.Equal(t, before, cleaned.Get(),
			"a GC pass over an unchanged alive zombie must not clean any name")
	}
}

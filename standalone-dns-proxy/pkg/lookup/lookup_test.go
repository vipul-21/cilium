// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lookup

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/fqdn/lookup"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/standalone-dns-proxy/pkg/client"
)

func newIPTable(db *statedb.DB) (statedb.RWTable[client.IPtoEndpointInfo], error) {
	table, err := client.NewIPtoEndpointTable(db)
	if err != nil {
		return nil, err
	}

	// Pre-insert an entry for testing
	insertIP(db, table, netip.MustParseAddr("10.0.0.1"), 123, identity.NumericIdentity(5))
	insertIP(db, table, netip.MustParseAddr("10.0.0.0"), 456, identity.NumericIdentity(5))
	return table, nil
}

func newPrefixToIdentityTable(db *statedb.DB) statedb.RWTable[client.PrefixToIdentity] {
	table, err := statedb.NewTable(
		db,
		client.PrefixToIdentityTableName,
		client.IdentityToPrefixIndex,
		client.PrefixToIdentityIndex,
	)
	if err != nil {
		return nil
	}

	// Pre-insert entries for testing: nested prefixes /8, /24, /16 and /32
	insertPrefixes(db, table, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, identity.NumericIdentity(444))
	insertPrefixes(db, table, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, identity.NumericIdentity(111))
	insertPrefixes(db, table, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")}, identity.NumericIdentity(222))
	// Add a more specific /32 entry so lookup prefers it over the /24 and /16
	insertPrefixes(db, table, []netip.Prefix{netip.MustParsePrefix("10.0.0.3/32"), netip.MustParsePrefix("10.0.0.4/32")}, identity.NumericIdentity(333))
	return table
}

func insertPrefixes(db *statedb.DB, table statedb.RWTable[client.PrefixToIdentity], prefix []netip.Prefix, ident identity.NumericIdentity) {
	w := db.WriteTxn(table)
	table.Insert(w, client.PrefixToIdentity{
		Prefix:   prefix,
		Identity: ident,
	})
	w.Commit()
}

func insertIP(db *statedb.DB, table statedb.RWTable[client.IPtoEndpointInfo], ip netip.Addr, id uint64, ident identity.NumericIdentity) {
	w := db.WriteTxn(table)
	table.Insert(w, client.IPtoEndpointInfo{
		IP:       []netip.Addr{ip},
		ID:       id,
		Identity: ident,
	})
	w.Commit()
}

func TestLookupRegisteredEndpoint(t *testing.T) {
	var rc lookup.ProxyLookupHandler
	h := hive.New(
		cell.Provide(newIPTable),
		cell.Provide(newRulesClient),
		cell.Provide(newPrefixToIdentityTable),
		cell.Invoke(func(_lh lookup.ProxyLookupHandler) {
			rc = _lh
		}),
	)
	if err := h.Start(hivetest.Logger(t), t.Context()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	ep, isHost, err := rc.LookupRegisteredEndpoint(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	require.NotNil(t, ep)
	require.Equal(t, uint16(123), ep.ID)
	require.Equal(t, identity.NumericIdentity(5), ep.SecurityIdentity.ID)
	require.False(t, isHost)

	ep, isHost, err = rc.LookupRegisteredEndpoint(netip.MustParseAddr("10.0.0.2"))
	require.Error(t, err)
	require.Nil(t, ep)
	require.False(t, isHost)

	h.Stop(hivetest.Logger(t), context.TODO())
}

func TestLookupDualStackEndpoints(t *testing.T) {
	db := statedb.New()
	table, err := client.NewIPtoEndpointTable(db)
	require.NoError(t, err)

	endpoints := []client.IPtoEndpointInfo{
		{
			IP:       []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fd00::1")},
			ID:       123,
			Identity: identity.NumericIdentity(5),
		},
		{
			IP:       []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("fd00::2")},
			ID:       456,
			Identity: identity.NumericIdentity(5),
		},
	}
	wtxn := db.WriteTxn(table)
	defer wtxn.Abort()
	for _, ep := range endpoints {
		_, _, err := table.Insert(wtxn, ep)
		require.NoError(t, err)
	}
	wtxn.Commit()
	require.Equal(t, len(endpoints), table.NumObjects(db.ReadTxn()))

	rc := &rulesClient{
		db:                db,
		ipToIdentityTable: table,
	}
	for _, expected := range endpoints {
		for _, ip := range expected.IP {
			t.Run(ip.String(), func(t *testing.T) {
				ep, isHost, err := rc.LookupRegisteredEndpoint(ip)
				require.NoError(t, err)
				require.NotNil(t, ep)
				require.Equal(t, uint16(expected.ID), ep.ID)
				require.Equal(t, expected.Identity, ep.SecurityIdentity.ID)
				require.False(t, isHost)

				ident, exists := rc.LookupSecIDByIP(ip)
				require.True(t, exists)
				require.Equal(t, expected.Identity, ident.ID)
			})
		}
	}
}

func TestLookupSecIDByIP(t *testing.T) {
	var rc lookup.ProxyLookupHandler
	h := hive.New(
		cell.Provide(newIPTable),
		cell.Provide(newRulesClient),
		cell.Provide(newPrefixToIdentityTable),
		cell.Invoke(func(_lh lookup.ProxyLookupHandler) {
			rc = _lh
		}),
	)
	if err := h.Start(hivetest.Logger(t), t.Context()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	err := testutils.WaitUntilWithSleep(func() bool {
		ipv6, ipv4 := rc.(*rulesClient).prefixLengths.ToBPFData()
		return len(ipv4) == 5 && len(ipv6) == 2
	}, 5*time.Second, 1*time.Second)
	require.NoError(t, err)

	ipv6, ipv4 := rc.(*rulesClient).prefixLengths.ToBPFData()
	require.Equal(t, []int{32, 24, 16, 8, 0}, ipv4)
	require.Equal(t, []int{128, 0}, ipv6)
	ident_, exists := rc.LookupSecIDByIP(netip.MustParseAddr("10.0.0.1"))
	require.True(t, exists)
	require.Equal(t, identity.NumericIdentity(5), ident_.ID)

	// An IP that is inside the /24 should match the /24
	ident_, exists = rc.LookupSecIDByIP(netip.MustParseAddr("10.0.0.2"))
	require.True(t, exists)
	require.Equal(t, identity.NumericIdentity(111), ident_.ID)

	// An IP that is inside the /16 but outside the /24 and /32 should match the /16
	ident_, exists = rc.LookupSecIDByIP(netip.MustParseAddr("10.0.1.1"))
	require.True(t, exists)
	require.Equal(t, identity.NumericIdentity(222), ident_.ID)

	// The /32 entry should take precedence over the /24 and /16
	ident_, exists = rc.LookupSecIDByIP(netip.MustParseAddr("10.0.0.3"))
	require.True(t, exists)
	require.Equal(t, identity.NumericIdentity(333), ident_.ID)

	ident_, exists = rc.LookupSecIDByIP(netip.MustParseAddr("10.0.0.4"))
	require.True(t, exists)
	require.Equal(t, identity.NumericIdentity(333), ident_.ID)

	// An IP that is inside the /8 but outside the /16 should match the /8
	ident_, exists = rc.LookupSecIDByIP(netip.MustParseAddr("10.255.1.1"))
	require.True(t, exists)
	require.Equal(t, identity.NumericIdentity(444), ident_.ID)

	ident_, exists = rc.LookupSecIDByIP(netip.MustParseAddr("11.0.0.0"))
	require.False(t, exists)
	require.Equal(t, identity.NumericIdentity(0), ident_.ID)

	h.Stop(hivetest.Logger(t), context.TODO())
}

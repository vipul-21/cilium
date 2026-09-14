// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// deleteDNSLookups collects its ipcache cleanup candidates from a snapshot taken
// before it expires anything. A DNS response that lands between the snapshot and
// the expiry is removed by that expiry, but is in no candidate set, so its
// ipcache metadata is never withdrawn.
func TestForceExpireReportsRemovedAssociations(t *testing.T) {
	c := NewDNSCache(0)
	ip := netip.MustParseAddr("10.0.0.9")
	cutoff := time.Now()

	// A lookup lands after any snapshot a caller may have taken. Its LookupTime
	// is older than the cutoff, so the expiry below removes it again.
	c.Update(cutoff.Add(-time.Second), "late.example.com", []netip.Addr{ip}, 3600)

	_, candidates := c.ForceExpire(cutoff, nil)

	require.Empty(t, c.Lookup("late.example.com"), "precondition: the association was removed")
	require.True(t, slices.Contains(candidates[ip], "late.example.com"),
		"a removed association must reach the ipcache cleanup candidates, "+
			"otherwise its FQDN labels stay on the prefix forever; candidates=%v", candidates)
}

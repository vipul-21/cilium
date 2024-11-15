package maps

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setup(tb testing.TB) *ipcache.Map {
	testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS("")

	err := rlimit.RemoveMemlock()
	require.NoError(tb, err)

	testMap := ipcache.NewMap(
		ipcache.Name,
	)

	err = testMap.OpenOrCreate()
	require.NoError(tb, err, "Failed to create map")

	tb.Cleanup(func() {
		require.NoError(tb, testMap.Close())
	})

	return testMap
}

func TestGetIdentity(t *testing.T) {
	_ = setup(t)
	tests := []struct {
		name          string
		ipAddr        netip.Addr
		expectedInfo  ipcache.RemoteEndpointInfo
		expectedError error
	}{
		{
			name:          "IPv4 address",
			ipAddr:        netip.MustParseAddr("192.168.1.1"),
			expectedInfo:  ipcache.RemoteEndpointInfo{SecurityIdentity: 1234},
			expectedError: nil,
		},
		{
			name:          "IPv6 address",
			ipAddr:        netip.MustParseAddr("2001:db8::1"),
			expectedInfo:  ipcache.RemoteEndpointInfo{SecurityIdentity: 5678},
			expectedError: nil,
		},
		{
			name:          "LoadMap error",
			ipAddr:        netip.MustParseAddr("192.168.1.1"),
			expectedInfo:  ipcache.RemoteEndpointInfo{},
			expectedError: errors.New("load map error"),
		},
		{
			name:          "Get error",
			ipAddr:        netip.MustParseAddr("192.168.1.1"),
			expectedInfo:  ipcache.RemoteEndpointInfo{},
			expectedError: errors.New("get error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := GetIdentity(tt.ipAddr)
			assert.Equal(t, tt.expectedInfo, info)
			assert.Equal(t, tt.expectedError, err)
		})
	}
}

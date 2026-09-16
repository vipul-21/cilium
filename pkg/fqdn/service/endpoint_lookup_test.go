// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

type endpointLookupManager struct {
	endpointmanager.EndpointsLookup
	endpoints map[netip.Addr]*endpoint.Endpoint
}

func (m *endpointLookupManager) LookupIP(ip netip.Addr) *endpoint.Endpoint {
	return m.endpoints[ip]
}

func TestLookupEndpoint(t *testing.T) {
	ipv4 := netip.MustParseAddr("10.0.0.1")
	ipv6 := netip.MustParseAddr("fd00::1")
	ep := &endpoint.Endpoint{
		ID:               123,
		SecurityIdentity: &identity.Identity{ID: 1001},
	}
	host := &endpoint.Endpoint{
		ID:               1,
		SecurityIdentity: &identity.Identity{ID: identity.ReservedIdentityHost},
	}
	host.SetIsHost(true)

	// No replicated tables are populated: the endpoint manager is authoritative.
	server := &FQDNDataServer{
		endpointsLookup: &endpointLookupManager{
			endpoints: map[netip.Addr]*endpoint.Endpoint{
				ipv4:                            ep,
				ipv6:                            ep,
				netip.MustParseAddr("10.0.0.2"): {ID: 124},
				netip.MustParseAddr("10.0.0.3"): {
					ID:               125,
					SecurityIdentity: &identity.Identity{ID: identity.InvalidIdentity},
				},
				netip.MustParseAddr("10.0.0.4"): host,
			},
		},
	}

	tests := []struct {
		name string
		req  *pb.LookupEndpointRequest
		code codes.Code
	}{
		{name: "IPv4 before replication", req: &pb.LookupEndpointRequest{Ip: ipv4.AsSlice()}},
		{name: "IPv6 before replication", req: &pb.LookupEndpointRequest{Ip: ipv6.AsSlice()}},
		{
			name: "IPv4 mapped IPv6",
			req:  &pb.LookupEndpointRequest{Ip: netip.MustParseAddr("::ffff:10.0.0.1").AsSlice()},
		},
		{
			name: "unknown endpoint",
			req:  &pb.LookupEndpointRequest{Ip: netip.MustParseAddr("10.0.0.99").AsSlice()},
			code: codes.NotFound,
		},
		{
			name: "identity not assigned",
			req:  &pb.LookupEndpointRequest{Ip: netip.MustParseAddr("10.0.0.2").AsSlice()},
			code: codes.FailedPrecondition,
		},
		{
			name: "invalid identity",
			req:  &pb.LookupEndpointRequest{Ip: netip.MustParseAddr("10.0.0.3").AsSlice()},
			code: codes.FailedPrecondition,
		},
		{
			name: "host endpoint",
			req:  &pb.LookupEndpointRequest{Ip: netip.MustParseAddr("10.0.0.4").AsSlice()},
			code: codes.FailedPrecondition,
		},
		{name: "nil request", code: codes.InvalidArgument},
		{name: "empty IP", req: &pb.LookupEndpointRequest{}, code: codes.InvalidArgument},
		{name: "malformed IP", req: &pb.LookupEndpointRequest{Ip: []byte{10, 0, 1}}, code: codes.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := server.LookupEndpoint(t.Context(), tt.req)
			require.Equal(t, tt.code, status.Code(err))
			if tt.code != codes.OK {
				require.Nil(t, response)
				return
			}
			require.Equal(t, uint64(123), response.GetEndpointId())
			require.Equal(t, uint32(1001), response.GetIdentity())
		})
	}
}

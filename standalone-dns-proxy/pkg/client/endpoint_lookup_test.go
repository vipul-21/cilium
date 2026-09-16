// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"math"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/time"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

type endpointLookupServer struct {
	pb.UnimplementedFQDNDataServer
	lookup func(context.Context, *pb.LookupEndpointRequest) (*pb.LookupEndpointResponse, error)
}

func (s *endpointLookupServer) LookupEndpoint(ctx context.Context, req *pb.LookupEndpointRequest) (*pb.LookupEndpointResponse, error) {
	return s.lookup(ctx, req)
}

func newEndpointLookupClient(t testing.TB, lookup func(context.Context, *pb.LookupEndpointRequest) (*pb.LookupEndpointResponse, error)) *GRPCClient {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	pb.RegisterFQDNDataServer(server, &endpointLookupServer{lookup: lookup})
	stopped := make(chan error, 1)
	go func() {
		stopped <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		require.NoError(t, <-stopped)
	})

	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn.Connect()
	for state := conn.GetState(); state != connectivity.Ready; state = conn.GetState() {
		require.True(t, conn.WaitForStateChange(ctx, state), "gRPC connection did not become ready")
	}

	db := statedb.New()
	table, err := NewIPtoEndpointTable(db)
	require.NoError(t, err)
	return &GRPCClient{client: conn, db: db, ipToEndpointTable: table}
}

func TestLookupEndpoint(t *testing.T) {
	valid := &pb.LookupEndpointResponse{EndpointId: 123, Identity: 1001}
	tests := []struct {
		name     string
		ip       netip.Addr
		response *pb.LookupEndpointResponse
		rpcError error
		wantErr  string
	}{
		{name: "IPv4", ip: netip.MustParseAddr("10.0.0.1"), response: valid},
		{name: "IPv6", ip: netip.MustParseAddr("fd00::1"), response: valid},
		{name: "IPv4 mapped IPv6", ip: netip.MustParseAddr("::ffff:10.0.0.1"), response: valid},
		{name: "invalid IP", wantErr: "invalid endpoint IP address"},
		{name: "not found", ip: netip.MustParseAddr("10.0.0.1"), rpcError: status.Error(codes.NotFound, "not found"), wantErr: "NotFound"},
		{name: "unavailable", ip: netip.MustParseAddr("10.0.0.1"), rpcError: status.Error(codes.Unavailable, "unavailable"), wantErr: "Unavailable"},
		{name: "older agent", ip: netip.MustParseAddr("10.0.0.1"), rpcError: status.Error(codes.Unimplemented, "unimplemented"), wantErr: "Unimplemented"},
		{name: "empty response", ip: netip.MustParseAddr("10.0.0.1"), response: &pb.LookupEndpointResponse{}, wantErr: "invalid endpoint information"},
		{name: "zero endpoint ID", ip: netip.MustParseAddr("10.0.0.1"), response: &pb.LookupEndpointResponse{Identity: 1001}, wantErr: "invalid endpoint information"},
		{name: "endpoint ID overflow", ip: netip.MustParseAddr("10.0.0.1"), response: &pb.LookupEndpointResponse{EndpointId: math.MaxUint16 + 1, Identity: 1001}, wantErr: "invalid endpoint information"},
		{name: "zero identity", ip: netip.MustParseAddr("10.0.0.1"), response: &pb.LookupEndpointResponse{EndpointId: 123}, wantErr: "invalid endpoint information"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			c := newEndpointLookupClient(t, func(_ context.Context, req *pb.LookupEndpointRequest) (*pb.LookupEndpointResponse, error) {
				calls.Add(1)
				ip, ok := netip.AddrFromSlice(req.GetIp())
				if !ok || ip != tt.ip.Unmap() {
					return nil, status.Error(codes.InvalidArgument, "unexpected request IP")
				}
				return tt.response, tt.rpcError
			})
			updateMapping(t, c, 456, 2001, "10.0.0.99")

			for range 2 {
				info, err := c.LookupEndpoint(t.Context(), tt.ip)
				if tt.wantErr != "" {
					require.ErrorContains(t, err, tt.wantErr)
					require.Empty(t, info)
					require.Equal(t, 1, c.ipToEndpointTable.NumObjects(c.db.ReadTxn()))
				} else {
					require.NoError(t, err)
					require.Equal(t, IPtoEndpointInfo{
						IP: []netip.Addr{tt.ip.Unmap()}, ID: 123, Identity: 1001,
					}, info)
					checkMapping(t, c, tt.ip.Unmap().String(), 123, 1001, true)
				}
			}
			checkMapping(t, c, "10.0.0.99", 456, 2001, true)
			switch {
			case !tt.ip.IsValid():
				require.Zero(t, calls.Load())
			case tt.wantErr != "":
				require.Equal(t, int32(2), calls.Load(), "errors must not be cached")
			default:
				require.Equal(t, int32(1), calls.Load(), "second lookup must use the cache")
				require.NoError(t, c.updateIPToEndpoint(nil))
				checkMapping(t, c, tt.ip.Unmap().String(), 0, 0, false)
				_, err := c.LookupEndpoint(t.Context(), tt.ip)
				require.NoError(t, err)
				require.Equal(t, int32(2), calls.Load(), "a new snapshot must replace the cached result")
			}
		})
	}
}

func TestLookupEndpointConcurrentSnapshot(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")
	for _, replace := range []bool{false, true} {
		name := "empty snapshot"
		if replace {
			name = "updated endpoint"
		}
		t.Run(name, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			c := newEndpointLookupClient(t, func(ctx context.Context, _ *pb.LookupEndpointRequest) (*pb.LookupEndpointResponse, error) {
				if calls.Add(1) > 1 {
					return nil, status.Error(codes.NotFound, "endpoint removed")
				}
				close(started)
				select {
				case <-release:
					return &pb.LookupEndpointResponse{EndpointId: 123, Identity: 1001}, nil
				case <-ctx.Done():
					return nil, status.FromContextError(ctx.Err()).Err()
				}
			})
			type result struct {
				info IPtoEndpointInfo
				err  error
			}
			done := make(chan result, 1)
			go func() {
				info, err := c.LookupEndpoint(t.Context(), ip)
				done <- result{info, err}
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("lookup did not reach the agent")
			}
			if replace {
				updateMapping(t, c, 456, 2001, ip.String())
			} else {
				require.NoError(t, c.updateIPToEndpoint(nil))
			}
			close(release)
			got := <-done
			if replace {
				require.NoError(t, got.err)
				require.Equal(t, uint64(456), got.info.ID)
				require.Equal(t, identity.NumericIdentity(2001), got.info.Identity)
				checkMapping(t, c, ip.String(), 456, 2001, true)
				require.Equal(t, int32(1), calls.Load())
			} else {
				require.Equal(t, codes.NotFound, status.Code(got.err))
				require.Empty(t, got.info)
				checkMapping(t, c, ip.String(), 0, 0, false)
				require.Equal(t, int32(2), calls.Load(), "resolve again after a newer empty snapshot")
			}
		})
	}
}

func TestLookupEndpointConcurrentMisses(t *testing.T) {
	c := newEndpointLookupClient(t, func(context.Context, *pb.LookupEndpointRequest) (*pb.LookupEndpointResponse, error) {
		return &pb.LookupEndpointResponse{EndpointId: 123, Identity: 1001}, nil
	})
	ip := netip.MustParseAddr("10.0.0.1")
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for range cap(results) {
		wg.Go(func() {
			_, err := c.LookupEndpoint(t.Context(), ip)
			results <- err
		})
	}
	wg.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	checkMapping(t, c, ip.String(), 123, 1001, true)
	require.Equal(t, 1, c.ipToEndpointTable.NumObjects(c.db.ReadTxn()))
}

func TestLookupEndpointDeadline(t *testing.T) {
	for _, callerTimeout := range []time.Duration{20 * time.Millisecond, 3 * time.Second} {
		t.Run(callerTimeout.String(), func(t *testing.T) {
			deadlines := make(chan time.Time, 1)
			c := newEndpointLookupClient(t, func(ctx context.Context, _ *pb.LookupEndpointRequest) (*pb.LookupEndpointResponse, error) {
				deadline, _ := ctx.Deadline()
				deadlines <- deadline
				<-ctx.Done()
				return nil, status.FromContextError(ctx.Err()).Err()
			})
			ctx, cancel := context.WithTimeout(t.Context(), callerTimeout)
			defer cancel()
			start := time.Now()
			_, err := c.LookupEndpoint(ctx, netip.MustParseAddr("10.0.0.1"))
			require.Equal(t, codes.DeadlineExceeded, status.Code(err))
			select {
			case deadline := <-deadlines:
				require.False(t, deadline.IsZero())
				require.LessOrEqual(t, deadline.Sub(start), min(callerTimeout, endpointLookupTimeout)+100*time.Millisecond)
			default:
				t.Fatal("lookup did not reach the agent")
			}
			require.Zero(t, c.ipToEndpointTable.NumObjects(c.db.ReadTxn()))
		})
	}
}

func BenchmarkLookupEndpointCacheMiss(b *testing.B) {
	c := newEndpointLookupClient(b, func(context.Context, *pb.LookupEndpointRequest) (*pb.LookupEndpointResponse, error) {
		return &pb.LookupEndpointResponse{EndpointId: 123, Identity: 1001}, nil
	})
	ip := netip.MustParseAddr("10.0.0.1")
	ctx := b.Context()
	_, err := c.LookupEndpoint(ctx, ip)
	require.NoError(b, err)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		require.NoError(b, c.updateIPToEndpoint(nil))
		b.StartTimer()
		if _, err := c.LookupEndpoint(ctx, ip); err != nil {
			b.Fatal(err)
		}
	}
}

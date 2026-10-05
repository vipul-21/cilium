// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/standalone-dns-proxy/pkg/client"
	"github.com/cilium/cilium/standalone-dns-proxy/pkg/metrics"
)

type readinessTestJobs struct {
	job.Group
	jobs []job.Job
}

func (g *readinessTestJobs) Add(jobs ...job.Job) {
	g.jobs = append(g.jobs, jobs...)
}

type readinessTestConnection struct {
	client.ConnectionHandler
	connected atomic.Bool
	checked   chan struct{}
}

func (c *readinessTestConnection) IsConnected() bool {
	connected := c.connected.Load()
	select {
	case c.checked <- struct{}{}:
	default:
	}
	return connected
}

func (c *readinessTestConnection) StopConnection() {
	c.connected.Store(false)
}

type readinessTestProxy struct {
	proxy.DNSProxier
	listen func(uint16) error
}

func (p *readinessTestProxy) Listen(port uint16) error {
	return p.listen(port)
}

func (p *readinessTestProxy) Cleanup() {}

func TestStandaloneDNSProxyReadiness(t *testing.T) {
	for _, tt := range []struct {
		name      string
		listenErr error
	}{
		{name: "ready after connecting and listening"},
		{name: "not ready after listener failure", listenErr: errors.New("listen failed")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn := &readinessTestConnection{checked: make(chan struct{}, 1)}
			jobs := &readinessTestJobs{}
			sdp := &StandaloneDNSProxy{
				logger:      hivetest.Logger(t),
				proxyPort:   10094,
				connHandler: conn,
				jobGroup:    jobs,
				metrics:     metrics.NewMetrics(),
			}
			var listens atomic.Int32
			sdp.dnsProxier = &readinessTestProxy{
				listen: func(port uint16) error {
					assert.Equal(t, uint16(10094), port)
					assert.False(t, sdp.IsReady(), "proxy must not be ready before Listen succeeds")
					listens.Add(1)
					return tt.listenErr
				},
			}

			require.NoError(t, sdp.StartStandaloneDNSProxy())
			require.Len(t, jobs.jobs, 2)
			require.False(t, sdp.IsReady(), "proxy must not be ready before its first connection")

			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			done := make(chan error, 1)
			go func() {
				defer close(done)
				done <- sdp.WatchConnection(ctx, nil)
			}()
			t.Cleanup(func() {
				cancel()
				<-done
			})

			select {
			case <-conn.checked:
			case <-ctx.Done():
				t.Fatal("connection watcher did not check the connection")
			}
			require.False(t, sdp.IsReady())
			require.Zero(t, listens.Load())

			conn.connected.Store(true)
			select {
			case err := <-done:
				require.ErrorIs(t, err, tt.listenErr)
			case <-ctx.Done():
				t.Fatal("connection watcher did not start the listener")
			}
			require.Equal(t, int32(1), listens.Load())
			require.Equal(t, tt.listenErr == nil, sdp.IsReady())

			conn.connected.Store(false)
			require.Equal(t, tt.listenErr == nil, sdp.IsReady(),
				"a started proxy must remain ready to serve cached state during agent outages")

			require.NoError(t, sdp.StopStandaloneDNSProxy())
			require.False(t, sdp.IsReady())
		})
	}
}

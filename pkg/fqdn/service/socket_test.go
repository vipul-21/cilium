// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

// TestListenUnixPermissions asserts the access control on the FQDNData control
// plane socket. The socket streams the node's DNS policy and is the sink that
// populates the toFQDNs cache, so a workload that merely shares the node's
// network namespace must not be able to reach it. Losing these modes silently
// would reintroduce that exposure, so they are pinned here.
func TestListenUnixPermissions(t *testing.T) {
	socketDir := filepath.Join(t.TempDir(), "standalone-dns-proxy", "sockets")
	socketPath := GetSocketPath(socketDir)

	d := &defaultListener{log: hivetest.Logger(t), proxyGID: uint(os.Getgid())}

	lis, err := d.Listen(context.Background(), "unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { lis.Close() })

	socketInfo, err := os.Stat(socketPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o660), socketInfo.Mode().Perm(),
		"socket must be accessible by owner and group only")

	dirInfo, err := os.Stat(socketDir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o750), dirInfo.Mode().Perm(),
		"socket directory must not be world-accessible")
}

// TestListenUnixReplacesStaleSocket ensures the agent can restart when a socket
// file was left behind by a previous run, which would otherwise fail with
// "address already in use" and leave the proxy without a control plane.
func TestListenUnixReplacesStaleSocket(t *testing.T) {
	socketDir := filepath.Join(t.TempDir(), "standalone-dns-proxy", "sockets")
	socketPath := GetSocketPath(socketDir)

	require.NoError(t, os.MkdirAll(socketDir, 0o750))
	require.NoError(t, os.WriteFile(socketPath, []byte("stale"), 0o660))

	d := &defaultListener{log: hivetest.Logger(t), proxyGID: uint(os.Getgid())}

	lis, err := d.Listen(context.Background(), "unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { lis.Close() })

	socketInfo, err := os.Stat(socketPath)
	require.NoError(t, err)
	require.NotZero(t, socketInfo.Mode()&os.ModeSocket, "stale file must be replaced by a socket")
}

// TestSocketPathLayout pins the on-disk layout, which the Helm chart mounts into
// the standalone DNS proxy by hostPath and must therefore agree with.
func TestSocketPathLayout(t *testing.T) {
	require.Equal(t, "/var/run/cilium/standalone-dns-proxy/sockets", GetSocketDir("/var/run/cilium"))
	require.Equal(t, "/var/run/cilium/standalone-dns-proxy/sockets/sdp.sock",
		GetSocketPath(GetSocketDir("/var/run/cilium")))
}

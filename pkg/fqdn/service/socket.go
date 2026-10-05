// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"path/filepath"
)

// GetSocketDir returns the directory holding the standalone DNS proxy control
// plane socket, given the Cilium runtime directory. The directory is shared
// with the standalone DNS proxy via a hostPath mount.
func GetSocketDir(runDir string) string {
	return filepath.Join(runDir, "standalone-dns-proxy", "sockets")
}

// GetSocketPath returns the path of the socket the standalone DNS proxy uses to
// reach the agent's FQDNData gRPC service.
func GetSocketPath(socketDir string) string {
	return filepath.Join(socketDir, "sdp.sock")
}

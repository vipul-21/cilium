// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defaults

import (
	"github.com/cilium/cilium/pkg/defaults"
)

const (
	// ShellSockPath is the path to the UNIX domain socket exposing the debug shell
	// for the standalone DNS proxy
	ShellSockPath = defaults.RuntimePath + "/standalone-dns-proxy-shell.sock"

	// APISockPath is the path to the UNIX domain socket exposing the API
	// for the standalone DNS proxy
	APISockPath = defaults.RuntimePath + "/standalone-dns-proxy-api.sock"
)

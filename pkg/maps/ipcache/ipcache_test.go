// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"testing"
)

var (
	ipaddr   = "10.0.0.1"
	ipaddr2  = "2.2.2.2"
	identity = 2
)

func TestRemoteEndpointInfoFlagsStringReturnsCorrectValue(t *testing.T) {
	type stringTest struct {
		name string
		in   RemoteEndpointInfoFlags
		out  string
	}

	tests := []stringTest{
		{
			name: "no flags",
			in:   0,
			out:  "<none>",
		},
		{
			name: "FlagSkipTunnel",
			in:   FlagSkipTunnel,
			out:  "skiptunnel",
		},
	}

	for _, test := range tests {
		if s := test.in.String(); s != test.out {
			t.Errorf(
				"Expected '%s' for string representation of %s, instead got '%s'",
				test.out, test.name, s,
			)
		}
	}
}

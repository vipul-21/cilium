// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

func TestFQDNConfigFlags(t *testing.T) {
	flags := pflag.NewFlagSet("fqdn", pflag.ContinueOnError)
	DefaultConfig.Flags(flags)

	require.Nil(t, flags.Lookup("standalone-dns-proxy-server-port"))
	require.NoError(t, flags.Parse([]string{"--enable-standalone-dns-proxy"}))
	require.ErrorContains(t, flags.Parse([]string{"--standalone-dns-proxy-server-port=10095"}), "unknown flag")
}

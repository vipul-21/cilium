// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"log/slog"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/fqdn/config"
	"github.com/cilium/cilium/pkg/policy/api"
)

func FuzzMapSelectorsToNamesLocked(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		fqdnSelector := api.FQDNSelector{}
		ff.GenerateStruct(&fqdnSelector)
		nameManager := New(ManagerParams{
			Logger: slog.New(slog.DiscardHandler),
			Config: NameManagerConfig{
				StateDir: defaults.StateDir,
			},
			FQDNConfig: config.Config{
				ToFQDNsMinTTL:     1,
				DNSProxyLockCount: config.DefaultConfig.DNSProxyLockCount,
			},
		})
		nameManager.mapSelectorsToNamesLocked(fqdnSelector)
	})
}

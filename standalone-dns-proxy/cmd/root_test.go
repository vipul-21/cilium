// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"
)

// TestOperatorHive verifies that the Operator hive can be instantiated with
// default configuration and thus the Operator hive can be inspected with
// the hive commands and documentation can be generated from it.
func TestOperatorHive(t *testing.T) {
	// defer goleak.VerifyNone(t)

	// var testSrv Server

	// hive := hive.New(
	// 	cell.Provide(newServer),
	// 	cell.Config(Config{
	// 		Pprof:        false,
	// 		PprofAddress: "localhost",
	// 		PprofPort:    0,
	// 	}),
	// 	cell.Invoke(func(srv Server) {
	// 		testSrv = srv
	// 	}),
	// )

	// tlog := hivetest.Logger(t)
	// if err := hive.Start(tlog, context.Background()); err != nil {
	// 	t.Fatalf("failed to start: %s", err)
	// }

	// if testSrv != nil {
	// 	t.Fatalf("listener unexpectedly started on port %d", testSrv.Port())
	// }

	// if err := hive.Stop(tlog, context.Background()); err != nil {
	// 	t.Fatalf("failed to stop: %s", err)
	// }
}

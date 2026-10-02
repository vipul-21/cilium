// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import "github.com/cilium/hive/cell"

// Cell provides the configuration shared by the FQDN components.
var Cell = newCell(DefaultConfig)

// StandaloneCell provides the same configuration with the standalone proxy's defaults.
var StandaloneCell = newCell(DefaultStandaloneConfig)

func newCell(defaults Config) cell.Cell {
	return cell.Group(
		cell.Config(defaults),
		cell.Invoke(Config.Validate),
	)
}

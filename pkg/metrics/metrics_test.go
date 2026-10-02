// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	fqdnconfig "github.com/cilium/cilium/pkg/fqdn/config"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

func TestDNSSemaphoreMetricConfig(t *testing.T) {
	for _, limit := range []int{-1, 0, 2} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			counter := metric.NewCounter(metric.CounterOpts{
				ConfigName: Namespace + "_" + SubsystemFQDN + "_semaphore_rejected_total",
				Namespace:  Namespace,
				Subsystem:  SubsystemFQDN,
				Name:       "semaphore_rejected_total",
				Help:       "Rejected DNS requests",
				Disabled:   true,
			})
			reg := &Registry{params: RegistryParams{
				Logger:      hivetest.Logger(t),
				AutoMetrics: []metric.WithMetadata{counter},
				FQDNConfig:  fqdnconfig.Config{DNSProxyConcurrencyLimit: limit},
			}}
			reg.registerMetrics()
			require.Equal(t, limit > 0, counter.IsEnabled())
			reg.registerMetrics()
			require.Equal(t, limit > 0, counter.IsEnabled())
		})
	}
}

func TestGaugeWithThreshold(t *testing.T) {
	logger := hivetest.Logger(t)
	threshold := 1.0
	underThreshold := threshold - 0.5
	overThreshold := threshold + 0.5
	reg := NewAgentRegistry(RegistryParams{
		Logger: logger,
	})

	gauge := reg.NewGaugeWithThreshold(
		"test_metric",
		"test_subsystem",
		"test_metric",
		map[string]string{
			"test_label": "test_value",
		},
		threshold,
	)

	metrics, err := reg.inner.Gather()
	require.NoError(t, err)
	initMetricLen := len(metrics)

	gauge.Set(underThreshold)
	metrics, err = reg.inner.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, initMetricLen)
	require.Equal(t, underThreshold, GetGaugeValue(gauge.gauge))

	gauge.Set(overThreshold)
	metrics, err = reg.inner.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, initMetricLen+1)
	require.Equal(t, overThreshold, GetGaugeValue(gauge.gauge))

	gauge.Set(threshold)
	metrics, err = reg.inner.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, initMetricLen)
	require.Equal(t, threshold, GetGaugeValue(gauge.gauge))

	gauge.Set(overThreshold)
	metrics, err = reg.inner.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, initMetricLen+1)
	require.Equal(t, overThreshold, GetGaugeValue(gauge.gauge))

	gauge.Set(underThreshold)
	metrics, err = reg.inner.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, initMetricLen)
	require.Equal(t, underThreshold, GetGaugeValue(gauge.gauge))
}

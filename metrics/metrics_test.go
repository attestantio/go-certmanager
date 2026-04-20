// Copyright © 2026 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metrics

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// stubMonitor is a minimal Service implementation returning the configured presenter.
type stubMonitor struct {
	presenter string
}

func (s stubMonitor) Presenter() string { return s.presenter }

// resetForTest restores the package-level state so each test starts clean.
// It registers a t.Cleanup handler so teardown is automatic.
func resetForTest(t *testing.T) {
	t.Helper()

	registerMutex.Lock()
	notAfterMetric = nil
	notBeforeMetric = nil
	registerMutex.Unlock()

	t.Cleanup(func() {
		registerMutex.Lock()
		notAfterMetric = nil
		notBeforeMetric = nil
		registerMutex.Unlock()
	})
}

func TestRegister(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		monitor     Service
		wantMetrics bool
	}{
		{
			name:        "NilMonitor",
			monitor:     nil,
			wantMetrics: false,
		},
		{
			name:        "NonPrometheusMonitor",
			monitor:     stubMonitor{presenter: "otel"},
			wantMetrics: false,
		},
		{
			name:        "PrometheusMonitor",
			monitor:     stubMonitor{presenter: "prometheus"},
			wantMetrics: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resetForTest(t)

			registry := prometheus.NewRegistry()
			err := register(ctx, test.monitor, registry)
			require.NoError(t, err)

			if test.wantMetrics {
				require.NotNil(t, notAfterMetric)
				require.NotNil(t, notBeforeMetric)
			} else {
				require.Nil(t, notAfterMetric)
				require.Nil(t, notBeforeMetric)
			}
		})
	}
}

func TestRegisterIdempotent(t *testing.T) {
	ctx := context.Background()
	resetForTest(t)

	registry := prometheus.NewRegistry()
	monitor := stubMonitor{presenter: "prometheus"}

	require.NoError(t, register(ctx, monitor, registry))
	firstNotAfter := notAfterMetric
	firstNotBefore := notBeforeMetric

	require.NoError(t, register(ctx, monitor, registry))
	require.Same(t, firstNotAfter, notAfterMetric, "second Register must not swap notAfterMetric")
	require.Same(t, firstNotBefore, notBeforeMetric, "second Register must not swap notBeforeMetric")
}

func TestRegisterReusesExistingCollector(t *testing.T) {
	ctx := context.Background()
	resetForTest(t)

	registry := prometheus.NewRegistry()
	monitor := stubMonitor{presenter: "prometheus"}

	// First call registers the gauges.
	require.NoError(t, register(ctx, monitor, registry))

	// Simulate another process having registered the same collector by dropping
	// our package-level refs and re-running register against the same registry.
	registerMutex.Lock()
	notAfterMetric = nil
	notBeforeMetric = nil
	registerMutex.Unlock()

	require.NoError(t, register(ctx, monitor, registry))
	require.NotNil(t, notAfterMetric)
	require.NotNil(t, notBeforeMetric)
}

func TestSetCertificateExpiryBeforeRegister(t *testing.T) {
	resetForTest(t)

	// Must not panic when gauges are not yet registered.
	require.NotPanics(t, func() {
		SetCertificateExpiry("test", "server", time.Now(), time.Now())
	})
}

func TestSetCertificateExpiryAfterRegister(t *testing.T) {
	ctx := context.Background()
	resetForTest(t)

	registry := prometheus.NewRegistry()
	require.NoError(t, register(ctx, stubMonitor{presenter: "prometheus"}, registry))

	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	SetCertificateExpiry("dirk", "client", notAfter, notBefore)

	require.InDelta(t,
		float64(notAfter.Unix()),
		testutil.ToFloat64(notAfterMetric.WithLabelValues("dirk", "client")),
		0,
	)
	require.InDelta(t,
		float64(notBefore.Unix()),
		testutil.ToFloat64(notBeforeMetric.WithLabelValues("dirk", "client")),
		0,
	)
}

func TestSetCertificateExpiryMultipleNames(t *testing.T) {
	ctx := context.Background()
	resetForTest(t)

	registry := prometheus.NewRegistry()
	require.NoError(t, register(ctx, stubMonitor{presenter: "prometheus"}, registry))

	dirkNotAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	dirkNotBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tracingNotAfter := time.Date(2031, 6, 1, 0, 0, 0, 0, time.UTC)
	tracingNotBefore := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	SetCertificateExpiry("dirk", "client", dirkNotAfter, dirkNotBefore)
	SetCertificateExpiry("tracing", "client", tracingNotAfter, tracingNotBefore)

	require.InDelta(t,
		float64(dirkNotAfter.Unix()),
		testutil.ToFloat64(notAfterMetric.WithLabelValues("dirk", "client")),
		0,
	)
	require.InDelta(t,
		float64(tracingNotAfter.Unix()),
		testutil.ToFloat64(notAfterMetric.WithLabelValues("tracing", "client")),
		0,
	)
	require.InDelta(t,
		float64(dirkNotBefore.Unix()),
		testutil.ToFloat64(notBeforeMetric.WithLabelValues("dirk", "client")),
		0,
	)
	require.InDelta(t,
		float64(tracingNotBefore.Unix()),
		testutil.ToFloat64(notBeforeMetric.WithLabelValues("tracing", "client")),
		0,
	)

	// Sanity-check the registry exposes both series.
	families, err := registry.Gather()
	require.NoError(t, err)
	require.NotEmpty(t, families)
	foundNames := map[string]int{}
	for _, family := range families {
		if family.GetName() != "certmanager_certificate_not_after_seconds" {
			continue
		}
		for _, m := range family.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "name" {
					foundNames[l.GetValue()]++
				}
			}
		}
	}
	require.Equal(t, 1, foundNames["dirk"])
	require.Equal(t, 1, foundNames["tracing"])
}

func TestConcurrentRegister(t *testing.T) {
	ctx := context.Background()
	resetForTest(t)

	registry := prometheus.NewRegistry()
	monitor := stubMonitor{presenter: "prometheus"}

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			require.NoError(t, register(ctx, monitor, registry))
		}()
	}
	wg.Wait()

	require.NotNil(t, notAfterMetric)
	require.NotNil(t, notBeforeMetric)
}

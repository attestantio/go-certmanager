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
	"errors"
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

	notAfterMetric.Store(nil)
	notBeforeMetric.Store(nil)

	t.Cleanup(func() {
		notAfterMetric.Store(nil)
		notBeforeMetric.Store(nil)
	})
}

func TestRegister(t *testing.T) {
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
			require.NoError(t, register(test.monitor, registry))

			if test.wantMetrics {
				require.NotNil(t, notAfterMetric.Load())
				require.NotNil(t, notBeforeMetric.Load())
			} else {
				require.Nil(t, notAfterMetric.Load())
				require.Nil(t, notBeforeMetric.Load())
			}
		})
	}
}

func TestRegisterIdempotent(t *testing.T) {
	resetForTest(t)

	registry := prometheus.NewRegistry()
	monitor := stubMonitor{presenter: "prometheus"}

	require.NoError(t, register(monitor, registry))
	firstNotAfter := notAfterMetric.Load()
	firstNotBefore := notBeforeMetric.Load()

	require.NoError(t, register(monitor, registry))
	require.Same(t, firstNotAfter, notAfterMetric.Load(), "second Register must not swap notAfterMetric")
	require.Same(t, firstNotBefore, notBeforeMetric.Load(), "second Register must not swap notBeforeMetric")
}

func TestRegisterReusesExistingCollector(t *testing.T) {
	resetForTest(t)

	registry := prometheus.NewRegistry()
	monitor := stubMonitor{presenter: "prometheus"}

	// First call registers the gauges against the shared registry.
	require.NoError(t, register(monitor, registry))
	firstNotAfter := notAfterMetric.Load()
	firstNotBefore := notBeforeMetric.Load()
	require.NotNil(t, firstNotAfter)
	require.NotNil(t, firstNotBefore)

	// Drop our package-level refs — simulates a fresh caller that has not yet
	// observed registration but whose registry already contains the gauges.
	notAfterMetric.Store(nil)
	notBeforeMetric.Store(nil)

	require.NoError(t, register(monitor, registry))
	require.Same(t, firstNotAfter, notAfterMetric.Load(),
		"register must reuse the existing notAfter collector rather than creating a new one")
	require.Same(t, firstNotBefore, notBeforeMetric.Load(),
		"register must reuse the existing notBefore collector rather than creating a new one")
}

// failingRegisterer succeeds for the first N registrations, then returns an error
// for all subsequent ones. Used to exercise the partial-failure cleanup path.
type failingRegisterer struct {
	mu           sync.Mutex
	succeedUntil int
	calls        int
	registered   []prometheus.Collector
}

func (f *failingRegisterer) Register(c prometheus.Collector) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls > f.succeedUntil {
		return errors.New("mock registrar failure")
	}
	f.registered = append(f.registered, c)
	return nil
}

func (f *failingRegisterer) Unregister(c prometheus.Collector) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, r := range f.registered {
		if r == c {
			f.registered = append(f.registered[:i], f.registered[i+1:]...)
			return true
		}
	}
	return false
}

func (f *failingRegisterer) MustRegister(cs ...prometheus.Collector) {
	for _, c := range cs {
		if err := f.Register(c); err != nil {
			panic(err)
		}
	}
}

func TestRegisterPartialFailureRollsBack(t *testing.T) {
	resetForTest(t)

	registrar := &failingRegisterer{succeedUntil: 1}

	err := register(stubMonitor{presenter: "prometheus"}, registrar)
	require.Error(t, err)

	require.Nil(t, notAfterMetric.Load(), "package var must stay nil on partial failure")
	require.Nil(t, notBeforeMetric.Load(), "package var must stay nil on partial failure")
	require.Empty(t, registrar.registered, "first gauge must be unregistered when second fails")
}

func TestSetCertificateExpiryBeforeRegister(t *testing.T) {
	resetForTest(t)

	// Must not panic when gauges are not yet registered.
	require.NotPanics(t, func() {
		SetCertificateExpiry("test", RoleServer, time.Now(), time.Now())
	})
}

func TestSetCertificateExpiryAfterRegister(t *testing.T) {
	resetForTest(t)

	registry := prometheus.NewRegistry()
	require.NoError(t, register(stubMonitor{presenter: "prometheus"}, registry))

	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	SetCertificateExpiry("dirk", RoleClient, notAfter, notBefore)

	require.InDelta(t,
		float64(notAfter.Unix()),
		testutil.ToFloat64(notAfterMetric.Load().WithLabelValues("dirk", RoleClient)),
		0,
	)
	require.InDelta(t,
		float64(notBefore.Unix()),
		testutil.ToFloat64(notBeforeMetric.Load().WithLabelValues("dirk", RoleClient)),
		0,
	)
}

func TestSetCertificateExpiryMultipleNames(t *testing.T) {
	resetForTest(t)

	registry := prometheus.NewRegistry()
	require.NoError(t, register(stubMonitor{presenter: "prometheus"}, registry))

	dirkNotAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	dirkNotBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tracingNotAfter := time.Date(2031, 6, 1, 0, 0, 0, 0, time.UTC)
	tracingNotBefore := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	SetCertificateExpiry("dirk", RoleClient, dirkNotAfter, dirkNotBefore)
	SetCertificateExpiry("tracing", RoleClient, tracingNotAfter, tracingNotBefore)

	notAfter := notAfterMetric.Load()
	notBefore := notBeforeMetric.Load()

	require.InDelta(t,
		float64(dirkNotAfter.Unix()),
		testutil.ToFloat64(notAfter.WithLabelValues("dirk", RoleClient)),
		0,
	)
	require.InDelta(t,
		float64(tracingNotAfter.Unix()),
		testutil.ToFloat64(notAfter.WithLabelValues("tracing", RoleClient)),
		0,
	)
	require.InDelta(t,
		float64(dirkNotBefore.Unix()),
		testutil.ToFloat64(notBefore.WithLabelValues("dirk", RoleClient)),
		0,
	)
	require.InDelta(t,
		float64(tracingNotBefore.Unix()),
		testutil.ToFloat64(notBefore.WithLabelValues("tracing", RoleClient)),
		0,
	)

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
	resetForTest(t)

	registry := prometheus.NewRegistry()
	monitor := stubMonitor{presenter: "prometheus"}

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			require.NoError(t, register(monitor, registry))
		}()
	}
	wg.Wait()

	require.NotNil(t, notAfterMetric.Load())
	require.NotNil(t, notBeforeMetric.Load())
}

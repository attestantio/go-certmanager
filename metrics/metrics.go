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
	"errors"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	registerMutex sync.Mutex

	notAfterMetric  *prometheus.GaugeVec
	notBeforeMetric *prometheus.GaugeVec
)

// Register installs the Prometheus gauges exposing certificate expiry data.
// The call is idempotent and is a no-op when monitor is nil or when the monitor
// presenter is not "prometheus".
func Register(ctx context.Context, monitor Service) error {
	return register(ctx, monitor, prometheus.DefaultRegisterer)
}

// register is the test-friendly implementation that accepts an explicit registerer.
func register(_ context.Context, monitor Service, registerer prometheus.Registerer) error {
	if monitor == nil {
		return nil
	}
	if monitor.Presenter() != "prometheus" {
		return nil
	}

	registerMutex.Lock()
	defer registerMutex.Unlock()

	// Package-level gauges are always assigned together, so a non-nil notAfterMetric
	// is sufficient evidence that registration already completed.
	if notAfterMetric != nil {
		return nil
	}

	notAfter := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "certmanager",
		Subsystem: "certificate",
		Name:      "not_after_seconds",
		Help:      "The unix timestamp at which the certificate expires.",
	}, []string{"name", "role"})
	if err := registerer.Register(notAfter); err != nil {
		var are prometheus.AlreadyRegisteredError
		if !errors.As(err, &are) {
			return err
		}
		if existing, ok := are.ExistingCollector.(*prometheus.GaugeVec); ok {
			notAfter = existing
		}
	}

	notBefore := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "certmanager",
		Subsystem: "certificate",
		Name:      "not_before_seconds",
		Help:      "The unix timestamp at which the certificate becomes valid.",
	}, []string{"name", "role"})
	if err := registerer.Register(notBefore); err != nil {
		var are prometheus.AlreadyRegisteredError
		if !errors.As(err, &are) {
			return err
		}
		if existing, ok := are.ExistingCollector.(*prometheus.GaugeVec); ok {
			notBefore = existing
		}
	}

	notAfterMetric = notAfter
	notBeforeMetric = notBefore

	return nil
}

// SetCertificateExpiry records the expiry timestamps for the named certificate.
// Calls made before Register (or when the monitor is non-Prometheus) are no-ops.
func SetCertificateExpiry(name, role string, notAfter, notBefore time.Time) {
	registerMutex.Lock()
	defer registerMutex.Unlock()

	if notAfterMetric == nil || notBeforeMetric == nil {
		return
	}
	notAfterMetric.WithLabelValues(name, role).Set(float64(notAfter.Unix()))
	notBeforeMetric.WithLabelValues(name, role).Set(float64(notBefore.Unix()))
}

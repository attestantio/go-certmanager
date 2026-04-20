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
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Role values applied to the "role" label on certificate metrics.
const (
	RoleServer = "server"
	RoleClient = "client"
)

var (
	registerMutex sync.Mutex

	notAfterMetric  atomic.Pointer[prometheus.GaugeVec]
	notBeforeMetric atomic.Pointer[prometheus.GaugeVec]
)

// Register installs the Prometheus gauges exposing certificate expiry data.
// The call is idempotent and is a no-op when monitor is nil or when the monitor
// presenter is not "prometheus". If registration of the second gauge fails after
// the first has been registered, the first is unregistered before the error is
// returned so the Prometheus registry is not left in a partial state.
func Register(monitor Service) error {
	return register(monitor, prometheus.DefaultRegisterer)
}

// register is the test-friendly implementation that accepts an explicit registerer.
func register(monitor Service, registerer prometheus.Registerer) error {
	if monitor == nil {
		return nil
	}
	if monitor.Presenter() != "prometheus" {
		return nil
	}

	registerMutex.Lock()
	defer registerMutex.Unlock()

	// notAfterMetric and notBeforeMetric are assigned together, so a non-nil
	// notAfterMetric is sufficient evidence that registration already completed.
	if notAfterMetric.Load() != nil {
		return nil
	}

	notAfter, notAfterOwned, err := registerOrReuseGauge(registerer, prometheus.GaugeOpts{
		Namespace: "certmanager",
		Subsystem: "certificate",
		Name:      "not_after_seconds",
		Help:      "The unix timestamp at which the certificate expires.",
	})
	if err != nil {
		return err
	}

	notBefore, _, err := registerOrReuseGauge(registerer, prometheus.GaugeOpts{
		Namespace: "certmanager",
		Subsystem: "certificate",
		Name:      "not_before_seconds",
		Help:      "The unix timestamp at which the certificate becomes valid.",
	})
	if err != nil {
		// Roll back the first gauge if we actually registered it, so the Prometheus
		// registry is not left with a half-registered set of certmanager gauges.
		if notAfterOwned {
			registerer.Unregister(notAfter)
		}
		return err
	}

	notAfterMetric.Store(notAfter)
	notBeforeMetric.Store(notBefore)

	return nil
}

// registerOrReuseGauge registers a new gauge or reuses the one already present
// in the registerer under the same metric identity. The boolean return indicates
// whether this call produced the registration (true) or reused an existing
// collector (false); the caller uses it to decide rollback on subsequent errors.
func registerOrReuseGauge(
	registerer prometheus.Registerer,
	opts prometheus.GaugeOpts,
) (*prometheus.GaugeVec, bool, error) {
	gauge := prometheus.NewGaugeVec(opts, []string{"name", "role"})
	if err := registerer.Register(gauge); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if !errors.As(err, &alreadyRegistered) {
			return nil, false, err
		}
		existing, ok := alreadyRegistered.ExistingCollector.(*prometheus.GaugeVec)
		if !ok {
			return nil, false, fmt.Errorf("unexpected collector type for gauge %q", opts.Name)
		}

		return existing, false, nil
	}

	return gauge, true, nil
}

// SetCertificateExpiry records the expiry timestamps for the named certificate.
// Calls made before Register (or when the monitor is non-Prometheus) are no-ops.
// The read path is lock-free; only Register serializes via the register mutex.
func SetCertificateExpiry(name, role string, notAfter, notBefore time.Time) {
	na := notAfterMetric.Load()
	nb := notBeforeMetric.Load()
	if na == nil || nb == nil {
		return
	}
	na.WithLabelValues(name, role).Set(float64(notAfter.Unix()))
	nb.WithLabelValues(name, role).Set(float64(notBefore.Unix()))
}

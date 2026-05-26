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

// Package metrics provides the provider-agnostic monitor interface for go-certmanager
// along with a Prometheus-backed implementation of certificate expiry gauges.
package metrics

// Service is the minimal interface consumers implement to opt their monitoring
// backend into metric recording. Callers typically pass the same monitor service
// they already use for the rest of their application (e.g. Vouch, Dirk).
type Service interface {
	// Presenter returns the name of the monitoring backend, e.g. "prometheus".
	Presenter() string
}

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

package standard

import (
	"time"

	certmanager "github.com/attestantio/go-certmanager"
	"github.com/attestantio/go-certmanager/metrics"
	"github.com/rs/zerolog"
	"github.com/wealdtech/go-majordomo"
)

type parameters struct {
	monitor     metrics.Service
	logLevel    zerolog.Level
	majordomo   majordomo.Service
	loadTimeout time.Duration
	certPEMURI  string
	certKeyURI  string
	name        string
}

// Parameter is the interface for service parameters.
type Parameter interface {
	apply(p *parameters)
}

type parameterFunc func(*parameters)

func (f parameterFunc) apply(p *parameters) {
	f(p)
}

// WithLogLevel sets the log level for the module.
func WithLogLevel(logLevel zerolog.Level) Parameter {
	return parameterFunc(func(p *parameters) {
		p.logLevel = logLevel
	})
}

// WithMajordomo sets the majordomo service for this module.
func WithMajordomo(service majordomo.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.majordomo = service
	})
}

// WithLoadTimeout sets the load timeout for the module.
// If set to 0, loads will have no timeout.
func WithLoadTimeout(timeout time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.loadTimeout = timeout
	})
}

// WithCertKeyURI sets the key URI for the module.
func WithCertKeyURI(certKeyURI string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.certKeyURI = certKeyURI
	})
}

// WithCertPEMURI sets the PEM URI for the module.
func WithCertPEMURI(certPEMURI string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.certPEMURI = certPEMURI
	})
}

// WithName sets the certificate name used as the metric "name" label.
// The value is stable across certificate rotations and distinguishes multiple
// managers within a single process (e.g. "dirk", "tracing", "api").
// Required when WithMonitor is set.
func WithName(name string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.name = name
	})
}

// WithMonitor sets the monitor service used to opt into metric recording.
// When omitted (or nil), the manager records no metrics and carries zero overhead.
func WithMonitor(monitor metrics.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel: zerolog.GlobalLevel(),
	}
	for _, p := range params {
		if p != nil {
			p.apply(&parameters)
		}
	}

	if parameters.majordomo == nil {
		return nil, certmanager.ErrNoMajordomo
	}
	if parameters.certPEMURI == "" {
		return nil, certmanager.ErrNoCertPEMURI
	}
	if parameters.certKeyURI == "" {
		return nil, certmanager.ErrNoCertKeyURI
	}
	if parameters.monitor != nil && parameters.name == "" {
		return nil, certmanager.ErrNoNameWithMonitor
	}

	return &parameters, nil
}

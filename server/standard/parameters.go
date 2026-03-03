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
	"github.com/attestantio/go-certmanager/fetcher"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel      zerolog.Level
	fetcher       fetcher.Fetcher
	reloadTimeout time.Duration
	certPEMURI    string
	certKeyURI    string
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

// WithFetcher sets the certificate fetcher for this module.
func WithFetcher(fetcher fetcher.Fetcher) Parameter {
	return parameterFunc(func(p *parameters) {
		p.fetcher = fetcher
	})
}

// WithReloadTimeout sets the reload timeout for the module.
// If set to 0, reloads will have no timeout.
func WithReloadTimeout(reloadTimeout time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.reloadTimeout = reloadTimeout
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

	if parameters.fetcher == nil {
		return nil, certmanager.ErrNoFetcher
	}
	if parameters.certPEMURI == "" {
		return nil, certmanager.ErrNoCertPEMURI
	}
	if parameters.certKeyURI == "" {
		return nil, certmanager.ErrNoCertKeyURI
	}

	return &parameters, nil
}

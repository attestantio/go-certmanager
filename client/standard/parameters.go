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
	certmanager "github.com/attestantio/go-certmanager"
	"github.com/rs/zerolog"
	"github.com/wealdtech/go-majordomo"
)

type parameters struct {
	logLevel   zerolog.Level
	majordomo  majordomo.Service
	certPEMURI string
	certKeyURI string
	caCertURI  string // Optional.
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

// WithCACertURI sets the CA certificate URI for the module.
// This is optional; if not set, system CA pool is used.
func WithCACertURI(caCertURI string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.caCertURI = caCertURI
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

	return &parameters, nil
}

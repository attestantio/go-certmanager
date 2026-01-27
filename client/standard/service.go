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
	"context"
	"crypto/tls"
	"crypto/x509"

	"github.com/attestantio/go-certmanager/client"
	"github.com/attestantio/go-certmanager/fetcher"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the standard client certificate manager implementation.
type Service struct {
	log        zerolog.Logger
	fetcher    fetcher.Fetcher
	certPEMURI string
	certKeyURI string
	caCertURI  string
}

var _ client.Service = (*Service)(nil)

// New creates a new client certificate manager.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	log := zerologger.With().Str("service", "certmanager").Str("impl", "client").Str("type", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	return &Service{
		log:        log,
		fetcher:    parameters.fetcher,
		certPEMURI: parameters.certPEMURI,
		certKeyURI: parameters.certKeyURI,
		caCertURI:  parameters.caCertURI,
	}, nil
}

func (s *Service) GetCertificatePair(ctx context.Context) (*tls.Certificate, error) {
	clientCert, err := s.fetcher.Fetch(ctx, s.certPEMURI)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain client certificate")
	}
	clientKey, err := s.fetcher.Fetch(ctx, s.certKeyURI)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain client key")
	}

	clientPair, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load client keypair")
	}

	return &clientPair, nil
}

func (s *Service) GetTLSConfig(ctx context.Context) (*tls.Config, error) {
	clientPair, err := s.GetCertificatePair(ctx)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*clientPair},
		MinVersion:   tls.VersionTLS13,
	}

	// Add CA certificate if specified.
	if s.caCertURI != "" {
		caCert, err := s.fetcher.Fetch(ctx, s.caCertURI)
		if err != nil {
			return nil, errors.Wrap(err, "failed to obtain CA certificate")
		}
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to add CA certificate")
		}
		tlsCfg.RootCAs = cp
	}

	return tlsCfg, nil
}

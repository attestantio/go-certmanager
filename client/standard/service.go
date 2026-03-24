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
	"fmt"

	certmanager "github.com/attestantio/go-certmanager"
	"github.com/attestantio/go-certmanager/client"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/wealdtech/go-majordomo"
)

// Service is the standard client certificate manager implementation.
type Service struct {
	log        zerolog.Logger
	majordomo  majordomo.Service
	certPEMURI string
	certKeyURI string
	caCertURI  string
}

var _ client.Service = (*Service)(nil)

// New creates a new client certificate manager.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, fmt.Errorf("problem with parameters: %w", err)
	}

	log := zerologger.With().Str("service", "certmanager").Str("impl", "client").Str("type", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	return &Service{
		log:        log,
		majordomo:  parameters.majordomo,
		certPEMURI: parameters.certPEMURI,
		certKeyURI: parameters.certKeyURI,
		caCertURI:  parameters.caCertURI,
	}, nil
}

// GetCertificatePair fetches the certificate and key via majordomo and returns a TLS certificate pair.
func (s *Service) GetCertificatePair(ctx context.Context) (*tls.Certificate, error) {
	clientCert, err := s.majordomo.Fetch(ctx, s.certPEMURI)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain client certificate: %w", err)
	}
	clientKey, err := s.majordomo.Fetch(ctx, s.certKeyURI)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain client key: %w", err)
	}

	clientPair, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load client keypair: %w", err)
	}

	return &clientPair, nil
}

// GetTLSConfig returns a TLS configuration for client use.
// The returned config includes the client certificate pair and minimum TLS version.
// If a CA certificate URI is configured, it is used to create a custom root CA pool.
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
		caCert, err := s.majordomo.Fetch(ctx, s.caCertURI)
		if err != nil {
			return nil, fmt.Errorf("failed to obtain CA certificate: %w", err)
		}
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(caCert) {
			return nil, certmanager.ErrInvalidCAPool
		}
		tlsCfg.RootCAs = cp
	}

	return tlsCfg, nil
}

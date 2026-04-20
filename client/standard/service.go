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
	"time"

	certmanager "github.com/attestantio/go-certmanager"
	"github.com/attestantio/go-certmanager/client"
	"github.com/attestantio/go-certmanager/metrics"
	"github.com/attestantio/go-certmanager/san"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the standard client certificate manager implementation.
type Service struct {
	log      zerolog.Logger
	certPair *tls.Certificate
	rootCAs  *x509.CertPool
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

	if err := metrics.Register(ctx, parameters.monitor); err != nil {
		return nil, fmt.Errorf("failed to register metrics: %w", err)
	}

	if parameters.loadTimeout > 0 {
		var cancel context.CancelFunc
		// Give up on the load if it takes longer than the load timeout.
		ctx, cancel = context.WithTimeout(ctx, parameters.loadTimeout)
		defer cancel()
	}

	// Validate the certificate at startup.
	certPEMBlock, err := parameters.majordomo.Fetch(ctx, parameters.certPEMURI)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain client certificate: %w", err)
	}
	certKeyBlock, err := parameters.majordomo.Fetch(ctx, parameters.certKeyURI)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain client key: %w", err)
	}

	clientPair, err := tls.X509KeyPair(certPEMBlock, certKeyBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to load client keypair: %w", err)
	}
	if len(clientPair.Certificate) == 0 {
		return nil, certmanager.ErrEmptyCertificate
	}
	// Backfill Leaf when GODEBUG=x509keypairleaf=0 disables the Go 1.23+ auto-population.
	if clientPair.Leaf == nil {
		parsedCert, err := x509.ParseCertificate(clientPair.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse client certificate: %w", err)
		}
		clientPair.Leaf = parsedCert
	}
	if clientPair.Leaf.NotAfter.Before(time.Now()) {
		log.Error().Time("expiry", clientPair.Leaf.NotAfter).Msg("Client certificate expired")
		return nil, certmanager.ErrExpiredCertificate
	}

	// Load CA certificate if specified.
	var rootCAs *x509.CertPool
	if parameters.caCertURI != "" {
		caCert, err := parameters.majordomo.Fetch(ctx, parameters.caCertURI)
		if err != nil {
			return nil, fmt.Errorf("failed to obtain CA certificate: %w", err)
		}
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(caCert) {
			return nil, certmanager.ErrInvalidCAPool
		}
	}

	log.Info().
		Str("identity", san.IdentityString(clientPair.Leaf)).
		Str("issued_by", clientPair.Leaf.Issuer.CommonName).
		Time("valid_until", clientPair.Leaf.NotAfter).
		Msg("Client certificate loaded")

	if parameters.name != "" {
		metrics.SetCertificateExpiry(parameters.name, "client", clientPair.Leaf.NotAfter, clientPair.Leaf.NotBefore)
	}

	return &Service{
		log:      log,
		certPair: &clientPair,
		rootCAs:  rootCAs,
	}, nil
}

// GetCertificatePair returns the cached TLS certificate pair.
func (s *Service) GetCertificatePair(_ context.Context) (*tls.Certificate, error) {
	return s.certPair, nil
}

// GetTLSConfig returns a TLS configuration for client use.
// The returned config includes the cached client certificate pair, minimum TLS version,
// and the cached root CA pool if one was configured at construction time.
func (s *Service) GetTLSConfig(_ context.Context) (*tls.Config, error) {
	return &tls.Config{
		Certificates: []tls.Certificate{*s.certPair},
		MinVersion:   tls.VersionTLS13,
		RootCAs:      s.rootCAs,
	}, nil
}

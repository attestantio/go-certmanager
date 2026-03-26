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
	"sync"
	"sync/atomic"
	"time"

	certmanager "github.com/attestantio/go-certmanager"
	"github.com/attestantio/go-certmanager/san"
	"github.com/attestantio/go-certmanager/server"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/wealdtech/go-majordomo"
)

// certWithExpiry bundles a TLS certificate with its cached expiry time,
// avoiding repeated x509.ParseCertificate calls on the hot path.
type certWithExpiry struct {
	cert   *tls.Certificate
	expiry time.Time
}

// Ensure Service implements server.Service.
var _ server.Service = (*Service)(nil)

// Service is the standard server certificate manager implementation.
type Service struct {
	log         zerolog.Logger
	majordomo   majordomo.Service
	loadTimeout time.Duration
	certPEMURI  string
	certKeyURI  string

	currentCert      atomic.Pointer[certWithExpiry]
	currentCertMutex sync.Mutex
}

// New creates a new server certificate manager.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, fmt.Errorf("problem with parameters: %w", err)
	}

	// Set logging.
	log := zerologger.With().Str("service", "certmanager").Str("impl", "server").Str("type", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		log:         log,
		majordomo:   parameters.majordomo,
		certPEMURI:  parameters.certPEMURI,
		certKeyURI:  parameters.certKeyURI,
		loadTimeout: parameters.loadTimeout,
	}

	// Load the certificates immediately.
	if err := s.loadCertificate(ctx); err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	return s, nil
}

// ReloadCertificate attempts to reload the certificate from its source.
// This is thread-safe and non-blocking. If a reload is already in progress,
// this method returns nil immediately without waiting.
// Returns an error if the reload fails (e.g., certificate fetch or parse error).
func (s *Service) ReloadCertificate(ctx context.Context) error {
	if !s.currentCertMutex.TryLock() {
		// Certificate is already being reloaded; do nothing.
		s.log.Debug().Msg("Certificate is already being reloaded; ReloadCertificate will do nothing")
		return nil
	}
	defer s.currentCertMutex.Unlock()

	if err := s.loadCertificate(ctx); err != nil {
		return fmt.Errorf("failed to reload server certificate: %w", err)
	}

	return nil
}

// GetCertificate returns the current certificate for TLS handshake.
// This method is designed to be used as tls.Config.GetCertificate callback.
func (s *Service) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	current := s.currentCert.Load()
	if current == nil || current.cert == nil {
		return nil, certmanager.ErrNoCertificateLoaded
	}

	return current.cert, nil
}

// GetTLSConfig returns a TLS configuration for server use.
// The returned config includes GetCertificate callback and minimum TLS version.
// ctx is currently unused but is accepted for forward-compatibility.
func (s *Service) GetTLSConfig(_ context.Context) (*tls.Config, error) {
	return &tls.Config{
		GetCertificate: s.GetCertificate,
		MinVersion:     tls.VersionTLS13,
	}, nil
}

// GetClientTLSConfig returns a TLS configuration suitable for client connections.
// Unlike GetTLSConfig(), this returns a config with static certificates suitable
// for use in gRPC client credentials.
//
// The returned config contains a snapshot of the current certificate. It will NOT
// reflect subsequent ReloadCertificate calls; callers must call GetClientTLSConfig
// again after a reload to obtain the updated certificate.
func (s *Service) GetClientTLSConfig(_ context.Context) (*tls.Config, error) {
	current := s.currentCert.Load()
	if current == nil || current.cert == nil {
		return nil, certmanager.ErrNoCertificateLoaded
	}

	// Return a TLS config with static certificates for client use.
	return &tls.Config{
		Certificates: []tls.Certificate{*current.cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func (s *Service) loadCertificate(ctx context.Context) error {
	if s.loadTimeout > 0 {
		var cancel context.CancelFunc
		// Give up on the load if it takes longer than the load timeout.
		ctx, cancel = context.WithDeadline(ctx, time.Now().Add(s.loadTimeout))
		defer cancel()
	}

	certPEMBlock, err := s.majordomo.Fetch(ctx, s.certPEMURI)
	if err != nil {
		return fmt.Errorf("failed to obtain server certificate: %w", err)
	}
	certKeyBlock, err := s.majordomo.Fetch(ctx, s.certKeyURI)
	if err != nil {
		return fmt.Errorf("failed to obtain server key: %w", err)
	}

	// Initialize the certificate pair.
	serverCert, err := tls.X509KeyPair(certPEMBlock, certKeyBlock)
	if err != nil {
		return fmt.Errorf("failed to load certificate pair: %w", err)
	}
	if len(serverCert.Certificate) == 0 {
		return certmanager.ErrEmptyCertificate
	}
	cert, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse server certificate: %w", err)
	}

	if cert.NotAfter.Before(time.Now()) {
		s.log.Error().Time("expiry", cert.NotAfter).Msg("Server certificate expired")
		return certmanager.ErrExpiredCertificate
	}

	s.currentCert.Store(&certWithExpiry{
		cert:   &serverCert,
		expiry: cert.NotAfter,
	})

	s.log.Info().
		Str("identity", san.IdentityString(cert)).
		Str("issued_by", cert.Issuer.CommonName).
		Time("valid_until", cert.NotAfter).
		Msg("Server certificate loaded")

	return nil
}

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
	"sync"
	"sync/atomic"
	"time"

	"github.com/attestantio/go-certmanager/fetcher"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the standard server certificate manager implementation.
type Service struct {
	log           zerolog.Logger
	fetcher       fetcher.Fetcher
	reloadTimeout time.Duration
	certPEMURI    string
	certKeyURI    string

	lastReloadAttemptTime time.Time
	currentCertMutex      sync.RWMutex
	currentCert           atomic.Pointer[tls.Certificate]
}

// New creates a new server certificate manager.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("service", "certmanager").Str("impl", "server").Str("type", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	// Load the certificates immediately.
	certPEMBlock, err := parameters.fetcher.Fetch(ctx, parameters.certPEMURI)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain server certificate")
	}
	certKeyBlock, err := parameters.fetcher.Fetch(ctx, parameters.certKeyURI)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain server key")
	}

	// Initialize the certificate pair.
	serverCert, err := tls.X509KeyPair(certPEMBlock, certKeyBlock)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load certificate pair")
	}
	if len(serverCert.Certificate) == 0 {
		return nil, errors.New("certificate file does not contain a certificate")
	}
	cert, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil || cert == nil {
		return nil, errors.Wrap(err, "failed to parse server certificate")
	}
	if cert.NotAfter.Before(time.Now()) {
		log.Warn().Time("expiry", cert.NotAfter).Msg("Server certificate expired")
	}

	log.Info().
		Str("issued_to", cert.Subject.CommonName).
		Str("issued_by", cert.Issuer.CommonName).
		Time("valid_until", cert.NotAfter).
		Msg("Server certificate loaded")

	s := &Service{
		log:           log,
		fetcher:       parameters.fetcher,
		certPEMURI:    parameters.certPEMURI,
		certKeyURI:    parameters.certKeyURI,
		reloadTimeout: parameters.reloadTimeout,
	}
	s.currentCert.Store(&serverCert)
	return s, nil
}

func (s *Service) TryReloadCertificate(ctx context.Context) {
	if !s.currentCertMutex.TryLock() {
		// Certificate is already being reloaded; do nothing.
		return
	}
	defer s.currentCertMutex.Unlock()

	s.lastReloadAttemptTime = time.Now()

	if s.reloadTimeout > 0 {
		var cancel context.CancelFunc
		// Give up on the reload if it takes longer than the reload timeout.
		ctx, cancel = context.WithDeadline(ctx, s.lastReloadAttemptTime.Add(s.reloadTimeout))
		defer cancel()
	}

	certPEMBlock, err := s.fetcher.Fetch(ctx, s.certPEMURI)
	if err != nil {
		s.log.Warn().Err(err).Msg("Failed to obtain server certificate during reload")
		return
	}
	certKeyBlock, err := s.fetcher.Fetch(ctx, s.certKeyURI)
	if err != nil {
		s.log.Warn().Err(err).Msg("Failed to obtain server key during reload")
		return
	}

	// Load the certificate pair.
	serverCert, err := tls.X509KeyPair(certPEMBlock, certKeyBlock)
	if err != nil {
		s.log.Warn().Err(err).Msg("Failed to load certificate pair during reload")
		return
	}
	if len(serverCert.Certificate) == 0 {
		s.log.Warn().Msg("Certificate file does not contain a certificate")
		return
	}
	cert, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil || cert == nil {
		s.log.Warn().Msg("Failed to parse certificate")
		return
	}

	newExpiry := cert.NotAfter
	if newExpiry.Before(time.Now()) {
		s.log.Warn().
			Str("issued_to", cert.Subject.CommonName).
			Str("issued_by", cert.Issuer.CommonName).
			Time("expiry", newExpiry).
			Msg("Server certificate expired, send SIGHUP to reload it")
		return
	}

	s.log.Info().
		Str("issued_to", cert.Subject.CommonName).
		Str("issued_by", cert.Issuer.CommonName).
		Time("valid_until", newExpiry).
		Msg("Server certificate reloaded successfully")

	s.currentCert.Store(&serverCert)
}

func (s *Service) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	currentCert := s.currentCert.Load()
	cert, err := x509.ParseCertificate(currentCert.Certificate[0])
	if err != nil || cert == nil {
		s.log.Warn().Err(err).Msg("Failed to parse certificate")
		return nil, errors.New("could not parse certificate")
	}

	// Auto-reload if expired.
	// Do we want to reload automatically the certificate if it is expired?
	// If not, shall we return an error or just use the existing certificate?
	// The code block below should be commented out or removed if we don't want to reload automatically the certificate if it is expired.
	expiry := cert.NotAfter
	if expiry.Before(time.Now()) {
		s.log.Warn().
			Str("issued_to", cert.Subject.CommonName).
			Str("issued_by", cert.Issuer.CommonName).
			Time("expiry", expiry).
			Msg("Server certificate expired, reloading...")
		// Reload the certificate.
		s.TryReloadCertificate(context.Background())
	}

	// Use the existing certificate.
	// It will use the expired certificate if it is not reloaded successfully.
	return currentCert, nil
}

func (s *Service) GetTLSConfig(ctx context.Context) (*tls.Config, error) {
	return &tls.Config{
		GetCertificate: s.GetCertificate,
		MinVersion:     tls.VersionTLS13,
	}, nil
}

func (s *Service) GetClientTLSConfig(ctx context.Context) (*tls.Config, error) {
	currentCert := s.currentCert.Load()
	if currentCert == nil {
		return nil, errors.New("no certificate loaded")
	}

	cert, err := x509.ParseCertificate(currentCert.Certificate[0])
	if err != nil || cert == nil {
		s.log.Warn().Err(err).Msg("Failed to parse certificate")
		return nil, errors.New("could not parse certificate")
	}

	// Auto-reload if expired.
	expiry := cert.NotAfter
	if expiry.Before(time.Now()) {
		s.log.Warn().
			Str("issued_to", cert.Subject.CommonName).
			Str("issued_by", cert.Issuer.CommonName).
			Time("expiry", expiry).
			Msg("Server certificate expired, reloading for client connection...")
		// Reload the certificate.
		s.TryReloadCertificate(ctx)

		// Re-fetch the certificate after reload attempt.
		currentCert = s.currentCert.Load()
		if currentCert == nil {
			return nil, errors.New("no certificate loaded after reload attempt")
		}
	}

	// Return a TLS config with static certificates for client use.
	return &tls.Config{
		Certificates: []tls.Certificate{*currentCert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

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

package server

import (
	"context"
	"crypto/tls"
)

// Service manages server-side certificates with reload-on-expiry capabilities.
type Service interface {
	// GetCertificate returns the current certificate for TLS handshake.
	// This method is designed to be used as tls.Config.GetCertificate callback.
	// It automatically reloads expired certificates.
	GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error)

	// ReloadCertificate attempts to reload the certificate from its source.
	// This is thread-safe and non-blocking. If a reload is already in progress,
	// this method returns nil immediately without waiting.
	// Returns an error if the reload fails (e.g., certificate fetch or parse error).
	// Typically called in response to SIGHUP or expiry detection.
	ReloadCertificate(ctx context.Context) error

	// GetTLSConfig returns a TLS configuration for server use.
	// The returned config includes GetCertificate callback and minimum TLS version.
	GetTLSConfig(ctx context.Context) (*tls.Config, error)

	// GetClientTLSConfig returns a TLS configuration suitable for client connections.
	// Unlike GetTLSConfig(), this returns a config with static certificates suitable
	// for use in gRPC client credentials.
	//
	// This is useful when the same certificate is used for both server and client
	// roles (e.g., in peer-to-peer communication).
	GetClientTLSConfig(ctx context.Context) (*tls.Config, error)
}

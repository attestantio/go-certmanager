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

package client

import (
	"context"
	"crypto/tls"
)

// Service manages client-side certificates for TLS connections.
type Service interface {
	// GetTLSConfig returns a TLS configuration for client connections.
	// The returned config includes client certificates and CA pool if specified.
	GetTLSConfig(ctx context.Context) (*tls.Config, error)

	// GetCertificatePair returns the client certificate pair.
	// Useful for direct access to the certificate without full TLS config.
	GetCertificatePair(ctx context.Context) (*tls.Certificate, error)
}

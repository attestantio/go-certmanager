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

package certmanager

import "errors"

var (
	// ErrNoFetcher is returned when no fetcher is specified.
	ErrNoFetcher = errors.New("no fetcher specified")

	// ErrNoCertPEMURI is returned when no certificate PEM URI is specified.
	ErrNoCertPEMURI = errors.New("no cert PEM URI specified")

	// ErrNoCertKeyURI is returned when no certificate key URI is specified.
	ErrNoCertKeyURI = errors.New("no cert key URI specified")

	// ErrInvalidCertificate is returned when the certificate is invalid or cannot be parsed.
	ErrInvalidCertificate = errors.New("invalid certificate")

	// ErrEmptyCertificate is returned when the certificate file does not contain a certificate.
	ErrEmptyCertificate = errors.New("certificate file does not contain a certificate")

	// ErrInvalidCAPool is returned when CA certificate cannot be added to pool.
	ErrInvalidCAPool = errors.New("failed to add CA certificate to pool")
)

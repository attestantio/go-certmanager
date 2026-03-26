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

package san

import "crypto/x509"

// ExtractIdentity extracts the primary client identity from an x509 certificate.
//
// It checks DNS names from the SAN extension, validating each with ValidateDNSName
// and returning the first valid one. Invalid DNS names are silently skipped.
// If no valid DNS name is found, it falls back to the Common Name (CN) for
// backward compatibility with legacy certificates.
//
// Returns the identity string and the source from which it was extracted.
// If no identity can be determined, returns empty string and IdentitySourceUnknown.
func ExtractIdentity(cert *x509.Certificate) (string, IdentitySource) {
	// DNS names from SAN with validation.
	for _, name := range cert.DNSNames {
		if ValidateDNSName(name) != nil {
			continue
		}
		return name, IdentitySourceSANDNS
	}

	// CN fallback for backward compatibility with legacy certificates.
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName, IdentitySourceCN
	}

	return "", IdentitySourceUnknown
}

// IdentityString returns the primary identity string from a certificate.
// This is a convenience wrapper around ExtractIdentity that discards the source.
func IdentityString(cert *x509.Certificate) string {
	identity, _ := ExtractIdentity(cert)
	return identity
}

// ExtractAllSANs extracts all DNS Subject Alternative Names from a certificate.
//
// This function creates a copy of all DNS SAN values, ensuring the returned data
// is independent of the original certificate structure.
func ExtractAllSANs(cert *x509.Certificate) *CertificateSANs {
	sans := &CertificateSANs{
		DNSNames: make([]string, len(cert.DNSNames)),
	}
	copy(sans.DNSNames, cert.DNSNames)
	return sans
}

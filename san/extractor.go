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
// It follows RFC 6125 compliant priority:
//  1. DNS names from SAN extension (preferred for service-to-service authentication)
//  2. IP addresses from SAN extension (for direct IP-based connections)
//  3. Email addresses from SAN extension (common in client certificate user identity)
//  4. Common Name (CN) - fallback for backward compatibility with legacy certificates
//
// Returns the identity string and the source from which it was extracted.
// If no identity can be determined, returns empty string and IdentitySourceUnknown.
func ExtractIdentity(cert *x509.Certificate) (string, IdentitySource) {
	// Priority 1: DNS names from SAN (RFC 6125 compliant).
	if len(cert.DNSNames) > 0 && cert.DNSNames[0] != "" {
		return cert.DNSNames[0], IdentitySourceSANDNS
	}

	// Priority 2: IP addresses from SAN.
	if len(cert.IPAddresses) > 0 {
		return cert.IPAddresses[0].String(), IdentitySourceSANIP
	}

	// Priority 3: Email addresses from SAN.
	if len(cert.EmailAddresses) > 0 && cert.EmailAddresses[0] != "" {
		return cert.EmailAddresses[0], IdentitySourceSANEmail
	}

	// Priority 4: CN fallback for backward compatibility with legacy certificates.
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName, IdentitySourceCN
	}

	return "", IdentitySourceUnknown
}

// ExtractAllSANs extracts all Subject Alternative Names from a certificate.
//
// This function creates copies of all SAN values, ensuring the returned data
// is independent of the original certificate structure. IP addresses are
// converted to string format.
func ExtractAllSANs(cert *x509.Certificate) *CertificateSANs {
	sans := &CertificateSANs{
		DNSNames:       make([]string, len(cert.DNSNames)),
		IPAddresses:    make([]string, len(cert.IPAddresses)),
		EmailAddresses: make([]string, len(cert.EmailAddresses)),
	}

	copy(sans.DNSNames, cert.DNSNames)

	for i, ip := range cert.IPAddresses {
		sans.IPAddresses[i] = ip.String()
	}

	copy(sans.EmailAddresses, cert.EmailAddresses)

	return sans
}

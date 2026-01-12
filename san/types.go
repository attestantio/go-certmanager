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

// CertificateSANs contains all Subject Alternative Name values from a certificate.
type CertificateSANs struct {
	// DNSNames contains all DNS names from the certificate's SAN extension.
	DNSNames []string
	// IPAddresses contains all IP addresses from the certificate's SAN extension (as strings).
	IPAddresses []string
	// EmailAddresses contains all email addresses from the certificate's SAN extension.
	EmailAddresses []string
}

// IdentitySource indicates where the client identity was extracted from.
type IdentitySource string

const (
	// IdentitySourceSANDNS indicates the identity was extracted from a DNS name in the SAN extension.
	IdentitySourceSANDNS IdentitySource = "san-dns"
	// IdentitySourceSANIP indicates the identity was extracted from an IP address in the SAN extension.
	IdentitySourceSANIP IdentitySource = "san-ip"
	// IdentitySourceSANEmail indicates the identity was extracted from an email address in the SAN extension.
	IdentitySourceSANEmail IdentitySource = "san-email"
	// IdentitySourceCN indicates the identity was extracted from the Common Name (legacy fallback).
	IdentitySourceCN IdentitySource = "cn"
	// IdentitySourceUnknown indicates no identity could be extracted from the certificate.
	IdentitySourceUnknown IdentitySource = ""
)

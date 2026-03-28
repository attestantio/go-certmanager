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

package san_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"

	"github.com/attestantio/go-certmanager/san"
	certtesting "github.com/attestantio/go-certmanager/testing"
	"github.com/stretchr/testify/require"
)

func TestExtractIdentity(t *testing.T) {
	tests := []struct {
		name             string
		certPEM          string
		keyPEM           string
		expectedIdentity string
		expectedSource   san.IdentitySource
	}{
		{
			name:             "ClientCertWithDNS",
			certPEM:          certtesting.ClientTest01Crt,
			keyPEM:           certtesting.ClientTest01Key,
			expectedIdentity: "client-test01",
			expectedSource:   san.IdentitySourceSANDNS,
		},
		{
			name:             "ClientCertWithDNS2",
			certPEM:          certtesting.ClientTest02Crt,
			keyPEM:           certtesting.ClientTest02Key,
			expectedIdentity: "client-test02",
			expectedSource:   san.IdentitySourceSANDNS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pair, err := tls.X509KeyPair([]byte(tt.certPEM), []byte(tt.keyPEM))
			require.NoError(t, err)
			cert, err := x509.ParseCertificate(pair.Certificate[0])
			require.NoError(t, err)

			identity, source := san.ExtractIdentity(cert)
			require.Equal(t, tt.expectedIdentity, identity)
			require.Equal(t, tt.expectedSource, source)
		})
	}
}

func TestExtractIdentityPriority(t *testing.T) {
	tests := []struct {
		name         string
		cert         *x509.Certificate
		wantIdentity string
		wantSource   san.IdentitySource
		description  string
	}{
		{
			name: "SAN DNS single",
			cert: &x509.Certificate{
				DNSNames: []string{"validator-01.example.com"},
				Subject: pkix.Name{
					CommonName: "should-not-use-this",
				},
			},
			wantIdentity: "validator-01.example.com",
			wantSource:   san.IdentitySourceSANDNS,
			description:  "Single DNS name in SAN should be preferred over CN",
		},
		{
			name: "SAN DNS multiple",
			cert: &x509.Certificate{
				DNSNames: []string{
					"primary.example.com",
					"secondary.example.com",
					"tertiary.example.com",
				},
				Subject: pkix.Name{
					CommonName: "should-not-use-this",
				},
			},
			wantIdentity: "primary.example.com",
			wantSource:   san.IdentitySourceSANDNS,
			description:  "First DNS name should be selected when multiple are present",
		},
		{
			name: "CN only (legacy)",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "legacy-client.example.com",
				},
			},
			wantIdentity: "legacy-client.example.com",
			wantSource:   san.IdentitySourceCN,
			description:  "CN should be used as fallback when no SAN present",
		},
		{
			name: "SAN DNS used when IP also present",
			cert: &x509.Certificate{
				DNSNames:    []string{"dns-name.example.com"},
				IPAddresses: []net.IP{net.ParseIP("192.168.1.1")},
				Subject: pkix.Name{
					CommonName: "should-not-use-this",
				},
			},
			wantIdentity: "dns-name.example.com",
			wantSource:   san.IdentitySourceSANDNS,
			description:  "DNS name should be preferred over IP address",
		},
		{
			name: "SAN DNS used when Email also present",
			cert: &x509.Certificate{
				DNSNames:       []string{"dns-name.example.com"},
				EmailAddresses: []string{"email@example.com"},
				Subject: pkix.Name{
					CommonName: "should-not-use-this",
				},
			},
			wantIdentity: "dns-name.example.com",
			wantSource:   san.IdentitySourceSANDNS,
			description:  "DNS name should be preferred over email address",
		},
		{
			name: "All SAN types present",
			cert: &x509.Certificate{
				DNSNames:       []string{"dns.example.com"},
				IPAddresses:    []net.IP{net.ParseIP("10.0.0.1")},
				EmailAddresses: []string{"email@example.com"},
				Subject: pkix.Name{
					CommonName: "cn.example.com",
				},
			},
			wantIdentity: "dns.example.com",
			wantSource:   san.IdentitySourceSANDNS,
			description:  "DNS should win when all identity types are present",
		},
		{
			name: "Empty DNS name ignored",
			cert: &x509.Certificate{
				DNSNames: []string{""},
				Subject: pkix.Name{
					CommonName: "fallback.example.com",
				},
			},
			wantIdentity: "fallback.example.com",
			wantSource:   san.IdentitySourceCN,
			description:  "Empty DNS name should be skipped, CN used as fallback",
		},
		{
			name: "No identity available",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "",
				},
			},
			wantIdentity: "",
			wantSource:   san.IdentitySourceUnknown,
			description:  "Empty string and source when no identity available",
		},
		{
			name: "Complex realistic scenario - modern CA",
			cert: &x509.Certificate{
				DNSNames: []string{
					"validator-prod-01.validators.example.com",
					"validator-prod-01.internal",
					"10-0-1-100.validators.example.com",
				},
				IPAddresses: []net.IP{
					net.ParseIP("10.0.1.100"),
					net.ParseIP("192.168.50.10"),
				},
				Subject: pkix.Name{
					CommonName: "",
				},
			},
			wantIdentity: "validator-prod-01.validators.example.com",
			wantSource:   san.IdentitySourceSANDNS,
			description:  "Modern CA certificate with multiple SANs and empty CN",
		},
		{
			name: "Certificate with public IP when localhost expected",
			cert: &x509.Certificate{
				IPAddresses: []net.IP{
					net.ParseIP("8.8.8.8"),
				},
				DNSNames: []string{"localhost"},
				Subject: pkix.Name{
					CommonName: "localhost",
				},
			},
			wantIdentity: "localhost",
			wantSource:   san.IdentitySourceSANDNS,
			description:  "DNS names take priority over IPs, even with mismatched values",
		},
		{
			name: "Certificate with wrong domain email",
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"admin@wrong-domain.com",
				},
				DNSNames: []string{"validator.example.com"},
				Subject: pkix.Name{
					CommonName: "validator.example.com",
				},
			},
			wantIdentity: "validator.example.com",
			wantSource:   san.IdentitySourceSANDNS,
			description:  "DNS identity takes priority over email, regardless of email domain",
		},
		{
			name: "Invalid DNS name falls through to CN",
			cert: &x509.Certificate{
				DNSNames: []string{"-invalid.com"},
				Subject: pkix.Name{
					CommonName: "fallback.example.com",
				},
			},
			wantIdentity: "fallback.example.com",
			wantSource:   san.IdentitySourceCN,
			description:  "Invalid DNS name should be skipped, CN used as fallback",
		},
		{
			name: "First DNS invalid, second valid",
			cert: &x509.Certificate{
				DNSNames: []string{"-bad.example.com", "good.example.com"},
				Subject: pkix.Name{
					CommonName: "should-not-use-this",
				},
			},
			wantIdentity: "good.example.com",
			wantSource:   san.IdentitySourceSANDNS,
			description:  "First invalid DNS name skipped, second valid one used",
		},
		{
			name: "All DNS names invalid, fall through to CN",
			cert: &x509.Certificate{
				DNSNames: []string{"-bad1.com", "-bad2.com"},
				Subject: pkix.Name{
					CommonName: "fallback.example.com",
				},
			},
			wantIdentity: "fallback.example.com",
			wantSource:   san.IdentitySourceCN,
			description:  "All invalid DNS names skipped, CN used as fallback",
		},
		{
			name: "DNS name that is IP string",
			cert: &x509.Certificate{
				DNSNames: []string{"192.168.1.1"},
				Subject: pkix.Name{
					CommonName: "fallback.example.com",
				},
			},
			wantIdentity: "fallback.example.com",
			wantSource:   san.IdentitySourceCN,
			description:  "DNS name that is actually an IP address should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, source := san.ExtractIdentity(tt.cert)
			require.Equal(t, tt.wantIdentity, identity)
			require.Equal(t, tt.wantSource, source)
		})
	}
}

func TestExtractAllSANs(t *testing.T) {
	tests := []struct {
		name     string
		cert     *x509.Certificate
		wantSANs *san.CertificateSANs
	}{
		{
			name: "DNS names populated",
			cert: &x509.Certificate{
				DNSNames: []string{
					"dns1.example.com",
					"dns2.example.com",
				},
			},
			wantSANs: &san.CertificateSANs{
				DNSNames: []string{
					"dns1.example.com",
					"dns2.example.com",
				},
			},
		},
		{
			name: "Empty certificate",
			cert: &x509.Certificate{},
			wantSANs: &san.CertificateSANs{
				DNSNames: []string{},
			},
		},
		{
			name: "Only DNS names",
			cert: &x509.Certificate{
				DNSNames: []string{"example.com"},
			},
			wantSANs: &san.CertificateSANs{
				DNSNames: []string{"example.com"},
			},
		},
		{
			name: "Many SANs",
			cert: &x509.Certificate{
				DNSNames: []string{
					"host1.example.com",
					"host2.example.com",
					"host3.example.com",
					"host4.example.com",
					"host5.example.com",
				},
			},
			wantSANs: &san.CertificateSANs{
				DNSNames: []string{
					"host1.example.com",
					"host2.example.com",
					"host3.example.com",
					"host4.example.com",
					"host5.example.com",
				},
			},
		},
		{
			name: "Unusual but valid SAN values",
			cert: &x509.Certificate{
				DNSNames: []string{
					"localhost",
					"my-server.internal",
				},
			},
			wantSANs: &san.CertificateSANs{
				DNSNames: []string{
					"localhost",
					"my-server.internal",
				},
			},
		},
		{
			name: "Invalid DNS names filtered out",
			cert: &x509.Certificate{
				DNSNames: []string{
					"valid.example.com",
					"192.168.1.1",
					"also-valid.example.com",
					"-invalid.example.com",
				},
			},
			wantSANs: &san.CertificateSANs{
				DNSNames: []string{
					"valid.example.com",
					"also-valid.example.com",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sans := san.ExtractAllSANs(tt.cert)

			require.NotNil(t, sans)
			require.Equal(t, tt.wantSANs.DNSNames, sans.DNSNames)
		})
	}
}

func TestIdentitySourceString(t *testing.T) {
	tests := []struct {
		name   string
		source san.IdentitySource
		want   string
	}{
		{name: "Unknown", source: san.IdentitySourceUnknown, want: "unknown"},
		{name: "SANDNS", source: san.IdentitySourceSANDNS, want: "san-dns"},
		{name: "CN", source: san.IdentitySourceCN, want: "cn"},
		{name: "OutOfRange", source: san.IdentitySource(99), want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.source.String())
		})
	}
}

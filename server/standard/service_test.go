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

package standard_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/attestantio/go-certmanager/fetcher/majordomo"
	"github.com/attestantio/go-certmanager/server/standard"
	certtesting "github.com/attestantio/go-certmanager/testing"
	"github.com/attestantio/go-certmanager/testing/mock"
	"github.com/stretchr/testify/require"
	fileconfidant "github.com/wealdtech/go-majordomo/confidants/file"
	majordomostandard "github.com/wealdtech/go-majordomo/standard"
)

// newMajordomo creates a majordomo service with file confidant registered.
func newMajordomo(t *testing.T) *majordomostandard.Service {
	t.Helper()
	ctx := context.Background()

	majordomoSvc, err := majordomostandard.New(ctx)
	require.NoError(t, err)

	// Register file confidant for file:// URIs
	fileConf, err := fileconfidant.New(ctx)
	require.NoError(t, err)
	err = majordomoSvc.RegisterConfidant(ctx, fileConf)
	require.NoError(t, err)

	return majordomoSvc
}

func TestNew(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		params  func(t *testing.T) []standard.Parameter
		wantErr bool
	}{
		{
			name: "Success",
			params: func(t *testing.T) []standard.Parameter {
				t.Helper()
				fetcher := mock.NewFetcher(map[string][]byte{
					"cert.pem": []byte(certtesting.SignerTest01Crt),
					"cert.key": []byte(certtesting.SignerTest01Key),
				})
				return []standard.Parameter{
					standard.WithFetcher(fetcher),
					standard.WithCertPEMURI("cert.pem"),
					standard.WithCertKeyURI("cert.key"),
				}
			},
			wantErr: false,
		},
		{
			name: "NoFetcher",
			params: func(t *testing.T) []standard.Parameter {
				t.Helper()
				return []standard.Parameter{
					standard.WithCertPEMURI("cert.pem"),
					standard.WithCertKeyURI("cert.key"),
				}
			},
			wantErr: true,
		},
		{
			name: "NoCertPEMURI",
			params: func(t *testing.T) []standard.Parameter {
				t.Helper()
				fetcher := mock.NewFetcher(map[string][]byte{})
				return []standard.Parameter{
					standard.WithFetcher(fetcher),
					standard.WithCertKeyURI("cert.key"),
				}
			},
			wantErr: true,
		},
		{
			name: "NoCertKeyURI",
			params: func(t *testing.T) []standard.Parameter {
				t.Helper()
				fetcher := mock.NewFetcher(map[string][]byte{})
				return []standard.Parameter{
					standard.WithFetcher(fetcher),
					standard.WithCertPEMURI("cert.pem"),
				}
			},
			wantErr: true,
		},
		{
			name: "InvalidCertificate",
			params: func(t *testing.T) []standard.Parameter {
				t.Helper()
				fetcher := mock.NewFetcher(map[string][]byte{
					"cert.pem": []byte("invalid"),
					"cert.key": []byte("invalid"),
				})
				return []standard.Parameter{
					standard.WithFetcher(fetcher),
					standard.WithCertPEMURI("cert.pem"),
					standard.WithCertKeyURI("cert.key"),
				}
			},
			wantErr: true,
		},
		{
			name: "FetcherError",
			params: func(t *testing.T) []standard.Parameter {
				t.Helper()
				fetcher := mock.NewFetcherWithError(os.ErrNotExist)
				return []standard.Parameter{
					standard.WithFetcher(fetcher),
					standard.WithCertPEMURI("cert.pem"),
					standard.WithCertKeyURI("cert.key"),
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := standard.New(ctx, tt.params(t)...)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetCertificate(t *testing.T) {
	ctx := context.Background()
	fetcher := mock.NewFetcher(map[string][]byte{
		"cert.pem": []byte(certtesting.SignerTest01Crt),
		"cert.key": []byte(certtesting.SignerTest01Key),
	})

	svc, err := standard.New(ctx,
		standard.WithFetcher(fetcher),
		standard.WithCertPEMURI("cert.pem"),
		standard.WithCertKeyURI("cert.key"),
	)
	require.NoError(t, err)
	require.NotNil(t, svc)

	// Get certificate
	cert, err := svc.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert)
	require.NotEmpty(t, cert.Certificate)

	// Verify certificate is valid
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	require.NotNil(t, x509Cert)
	require.NotEmpty(t, x509Cert.Subject.CommonName)
}

func TestReloadCertificate(t *testing.T) {
	ctx := context.Background()

	// Create temp directory for certificates
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "server.crt")
	keyPath := filepath.Join(tempDir, "server.key")

	// Write initial certificate
	err := os.WriteFile(certPath, []byte(certtesting.SignerTest01Crt), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(keyPath, []byte(certtesting.SignerTest01Key), 0o600)
	require.NoError(t, err)

	// Create majordomo fetcher with file confidant
	fetcher, err := majordomo.New(ctx,
		majordomo.WithMajordomo(newMajordomo(t)),
	)
	require.NoError(t, err)

	// Create service
	svc, err := standard.New(ctx,
		standard.WithFetcher(fetcher),
		standard.WithCertPEMURI("file://"+certPath),
		standard.WithCertKeyURI("file://"+keyPath),
	)
	require.NoError(t, err)

	// Get initial certificate
	cert1, err := svc.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert1)
	require.NotEmpty(t, cert1.Certificate)

	// Replace certificate on disk with a different one
	err = os.WriteFile(certPath, []byte(certtesting.SignerTest02Crt), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(keyPath, []byte(certtesting.SignerTest02Key), 0o600)
	require.NoError(t, err)

	// Trigger reload
	svc.ReloadCertificate(ctx)

	// Get new certificate
	cert2, err := svc.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert2)
	require.NotEmpty(t, cert2.Certificate)

	// Verify certificates are different
	require.NotEqual(t, cert1.Certificate[0], cert2.Certificate[0], "Certificate should have changed after reload")

	// Verify the new certificate is actually SignerTest02
	x509Cert, err := x509.ParseCertificate(cert2.Certificate[0])
	require.NoError(t, err)
	require.Contains(t, x509Cert.Subject.CommonName, "signer-test02")
}

func TestConcurrentReload(t *testing.T) {
	ctx := context.Background()

	// Create temp directory for certificates
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "server.crt")
	keyPath := filepath.Join(tempDir, "server.key")

	// Write initial certificate
	err := os.WriteFile(certPath, []byte(certtesting.SignerTest01Crt), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(keyPath, []byte(certtesting.SignerTest01Key), 0o600)
	require.NoError(t, err)

	// Create majordomo fetcher with file confidant
	fetcher, err := majordomo.New(ctx,
		majordomo.WithMajordomo(newMajordomo(t)),
	)
	require.NoError(t, err)

	// Create service
	svc, err := standard.New(ctx,
		standard.WithFetcher(fetcher),
		standard.WithCertPEMURI("file://"+certPath),
		standard.WithCertKeyURI("file://"+keyPath),
	)
	require.NoError(t, err)

	// Trigger multiple concurrent reloads
	// Only one should actually reload due to TryLock()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			svc.ReloadCertificate(ctx)
		}()
	}
	wg.Wait()

	// Service should still work
	cert, err := svc.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestReloadTimeout(t *testing.T) {
	ctx := context.Background()

	fetcher := mock.NewFetcher(map[string][]byte{
		"cert.pem": []byte(certtesting.SignerTest01Crt),
		"cert.key": []byte(certtesting.SignerTest01Key),
	})

	// Create service with very short timeout
	svc, err := standard.New(ctx,
		standard.WithFetcher(fetcher),
		standard.WithCertPEMURI("cert.pem"),
		standard.WithCertKeyURI("cert.key"),
		standard.WithReloadTimeout(1*time.Millisecond),
	)
	require.NoError(t, err)

	// Reload should complete even with short timeout (mock fetcher is instant)
	svc.ReloadCertificate(ctx)

	cert, err := svc.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestGetTLSConfig(t *testing.T) {
	ctx := context.Background()

	fetcher := mock.NewFetcher(map[string][]byte{
		"cert.pem": []byte(certtesting.SignerTest01Crt),
		"cert.key": []byte(certtesting.SignerTest01Key),
	})

	svc, err := standard.New(ctx,
		standard.WithFetcher(fetcher),
		standard.WithCertPEMURI("cert.pem"),
		standard.WithCertKeyURI("cert.key"),
	)
	require.NoError(t, err)

	// Get TLS config
	tlsCfg, err := svc.GetTLSConfig(ctx)
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)
	require.NotNil(t, tlsCfg.GetCertificate)
	require.Equal(t, uint16(tls.VersionTLS13), tlsCfg.MinVersion)

	// Test GetCertificate callback works
	cert, err := tlsCfg.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestGetClientTLSConfig(t *testing.T) {
	ctx := context.Background()

	fetcher := mock.NewFetcher(map[string][]byte{
		"cert.pem": []byte(certtesting.SignerTest01Crt),
		"cert.key": []byte(certtesting.SignerTest01Key),
	})

	svc, err := standard.New(ctx,
		standard.WithFetcher(fetcher),
		standard.WithCertPEMURI("cert.pem"),
		standard.WithCertKeyURI("cert.key"),
	)
	require.NoError(t, err)

	// Get client TLS config
	tlsCfg, err := svc.GetClientTLSConfig(ctx)
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)
	require.Nil(t, tlsCfg.GetCertificate) // Should not have callback for client config
	require.Equal(t, uint16(tls.VersionTLS13), tlsCfg.MinVersion)
	require.Len(t, tlsCfg.Certificates, 1) // Should have static certificate

	// Verify certificate is valid
	cert := tlsCfg.Certificates[0]
	require.NotEmpty(t, cert.Certificate)
	require.NotNil(t, cert.PrivateKey)

	// Parse and verify certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	require.NotNil(t, x509Cert)
}

func TestGetClientTLSConfigWithExpiredCert(t *testing.T) {
	ctx := context.Background()

	// Create a mock fetcher that simulates certificate expiry and auto-reload.
	// Initial fetch returns expired cert, subsequent fetches return valid cert.
	var certFetchCount, keyFetchCount int
	var mu sync.Mutex
	dynamicFetcher := &dynamicMockFetcher{
		fetchFunc: func(ctx context.Context, uri string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()

			if uri == "cert.pem" {
				certFetchCount++
				if certFetchCount == 1 {
					// First fetch (during New()): return expired certificate
					// This simulates a certificate that expired before service startup
					return []byte(certtesting.ExpiredCrt), nil
				}
				// Subsequent fetches: return valid certificate (reload succeeds)
				return []byte(certtesting.SignerTest01Crt), nil
			}
			// Keys - must match the cert
			keyFetchCount++
			if keyFetchCount == 1 {
				return []byte(certtesting.ExpiredKey), nil
			}
			return []byte(certtesting.SignerTest01Key), nil
		},
	}

	// Create service with expired certificate
	// Note: New() will log a warning but still load the expired cert
	svc, err := standard.New(ctx,
		standard.WithFetcher(dynamicFetcher),
		standard.WithCertPEMURI("cert.pem"),
		standard.WithCertKeyURI("cert.key"),
	)
	require.NoError(t, err)

	// Call GetClientTLSConfig() - this should:
	// 1. Detect the certificate is expired
	// 2. Automatically trigger ReloadCertificate()
	// 3. Return the newly reloaded valid certificate
	tlsCfg, err := svc.GetClientTLSConfig(ctx)
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)
	require.Len(t, tlsCfg.Certificates, 1)

	// Parse the certificate
	x509Cert, err := x509.ParseCertificate(tlsCfg.Certificates[0].Certificate[0])
	require.NoError(t, err)

	// Verify we got the reloaded valid certificate (NOT the expired one)
	require.Equal(t, "signer-test01", x509Cert.Subject.CommonName)
	require.True(t, x509Cert.NotAfter.After(time.Now()), "Certificate should not be expired")

	// Verify that multiple fetches occurred (initial + reload)
	mu.Lock()
	require.Equal(t, 2, certFetchCount, "Should have fetched cert twice (initial + reload)")
	require.Equal(t, 2, keyFetchCount, "Should have fetched key twice (initial + reload)")
	mu.Unlock()
}

func TestGetCertificateWithExpiredCert(t *testing.T) {
	ctx := context.Background()

	// Create a mock fetcher that simulates certificate expiry and auto-reload.
	// Initial fetch returns expired cert, subsequent fetches return valid cert.
	var certFetchCount, keyFetchCount int
	var mu sync.Mutex
	dynamicFetcher := &dynamicMockFetcher{
		fetchFunc: func(_ context.Context, uri string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()

			if uri == "cert.pem" {
				certFetchCount++
				if certFetchCount == 1 {
					// First fetch (during New()): return expired certificate
					return []byte(certtesting.ExpiredCrt), nil
				}
				// Subsequent fetches: return valid certificate (reload succeeds)
				return []byte(certtesting.SignerTest01Crt), nil
			}
			// Keys - must match the cert
			keyFetchCount++
			if keyFetchCount == 1 {
				return []byte(certtesting.ExpiredKey), nil
			}
			return []byte(certtesting.SignerTest01Key), nil
		},
	}

	// Create service with expired certificate.
	// New() will log a warning but still load the expired cert.
	svc, err := standard.New(ctx,
		standard.WithFetcher(dynamicFetcher),
		standard.WithCertPEMURI("cert.pem"),
		standard.WithCertKeyURI("cert.key"),
	)
	require.NoError(t, err)

	// Call GetCertificate() - this should:
	// 1. Detect the certificate is expired
	// 2. Automatically trigger ReloadCertificate()
	// 3. Return the newly reloaded valid certificate (not the stale expired one)
	cert, err := svc.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert)
	require.NotEmpty(t, cert.Certificate)

	// Parse the returned certificate.
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	// Verify we got the reloaded valid certificate (NOT the expired one).
	require.Equal(t, "signer-test01", x509Cert.Subject.CommonName)
	require.True(t, x509Cert.NotAfter.After(time.Now()), "Certificate should not be expired")

	// Verify that multiple fetches occurred (initial + reload).
	mu.Lock()
	require.Equal(t, 2, certFetchCount, "Should have fetched cert twice (initial + reload)")
	require.Equal(t, 2, keyFetchCount, "Should have fetched key twice (initial + reload)")
	mu.Unlock()
}

// dynamicMockFetcher is a test helper that allows dynamic fetch behavior
type dynamicMockFetcher struct {
	fetchFunc func(ctx context.Context, uri string) ([]byte, error)
}

func (f *dynamicMockFetcher) Fetch(ctx context.Context, uri string) ([]byte, error) {
	return f.fetchFunc(ctx, uri)
}

func TestReloadWithInvalidCertificate(t *testing.T) {
	ctx := context.Background()

	// Create temp directory for certificates
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "server.crt")
	keyPath := filepath.Join(tempDir, "server.key")

	// Write initial valid certificate
	err := os.WriteFile(certPath, []byte(certtesting.SignerTest01Crt), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(keyPath, []byte(certtesting.SignerTest01Key), 0o600)
	require.NoError(t, err)

	// Create majordomo fetcher with file confidant
	fetcher, err := majordomo.New(ctx,
		majordomo.WithMajordomo(newMajordomo(t)),
	)
	require.NoError(t, err)

	// Create service
	svc, err := standard.New(ctx,
		standard.WithFetcher(fetcher),
		standard.WithCertPEMURI("file://"+certPath),
		standard.WithCertKeyURI("file://"+keyPath),
	)
	require.NoError(t, err)

	// Get initial certificate
	cert1, err := svc.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert1)

	// Replace with invalid certificate
	err = os.WriteFile(certPath, []byte("invalid cert"), 0o600)
	require.NoError(t, err)

	// Trigger reload - should fail but service should continue with old cert
	svc.ReloadCertificate(ctx)

	// Should still return the old valid certificate
	cert2, err := svc.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert2)
	require.Equal(t, cert1.Certificate[0], cert2.Certificate[0], "Should keep old certificate when reload fails")
}

func TestReloadWithMismatchedKeyPair(t *testing.T) {
	ctx := context.Background()

	// Create temp directory for certificates
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "server.crt")
	keyPath := filepath.Join(tempDir, "server.key")

	// Write initial valid certificate
	err := os.WriteFile(certPath, []byte(certtesting.SignerTest01Crt), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(keyPath, []byte(certtesting.SignerTest01Key), 0o600)
	require.NoError(t, err)

	// Create majordomo fetcher with file confidant
	fetcher, err := majordomo.New(ctx,
		majordomo.WithMajordomo(newMajordomo(t)),
	)
	require.NoError(t, err)

	// Create service
	svc, err := standard.New(ctx,
		standard.WithFetcher(fetcher),
		standard.WithCertPEMURI("file://"+certPath),
		standard.WithCertKeyURI("file://"+keyPath),
	)
	require.NoError(t, err)

	// Get initial certificate
	cert1, err := svc.GetCertificate(nil)
	require.NoError(t, err)

	// Replace cert but keep old key (mismatched pair)
	err = os.WriteFile(certPath, []byte(certtesting.SignerTest02Crt), 0o600)
	require.NoError(t, err)

	// Trigger reload - should fail due to key mismatch
	svc.ReloadCertificate(ctx)

	// Should still return the old valid certificate
	cert2, err := svc.GetCertificate(nil)
	require.NoError(t, err)
	require.Equal(t, cert1.Certificate[0], cert2.Certificate[0], "Should keep old certificate when key mismatch")
}

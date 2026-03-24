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
	"testing"

	certmanager "github.com/attestantio/go-certmanager"
	"github.com/attestantio/go-certmanager/client/standard"
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
				majordomoSvc := mock.NewMajordomo(map[string][]byte{
					"cert.pem": []byte(certtesting.ClientTest01Crt),
					"cert.key": []byte(certtesting.ClientTest01Key),
				})
				return []standard.Parameter{
					standard.WithMajordomo(majordomoSvc),
					standard.WithCertPEMURI("cert.pem"),
					standard.WithCertKeyURI("cert.key"),
				}
			},
			wantErr: false,
		},
		{
			name: "SuccessWithCA",
			params: func(t *testing.T) []standard.Parameter {
				t.Helper()
				majordomoSvc := mock.NewMajordomo(map[string][]byte{
					"cert.pem": []byte(certtesting.ClientTest01Crt),
					"cert.key": []byte(certtesting.ClientTest01Key),
					"ca.pem":   []byte(certtesting.CACrt),
				})
				return []standard.Parameter{
					standard.WithMajordomo(majordomoSvc),
					standard.WithCertPEMURI("cert.pem"),
					standard.WithCertKeyURI("cert.key"),
					standard.WithCACertURI("ca.pem"),
				}
			},
			wantErr: false,
		},
		{
			name: "NoMajordomo",
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
				majordomoSvc := mock.NewMajordomo(map[string][]byte{})
				return []standard.Parameter{
					standard.WithMajordomo(majordomoSvc),
					standard.WithCertKeyURI("cert.key"),
				}
			},
			wantErr: true,
		},
		{
			name: "NoCertKeyURI",
			params: func(t *testing.T) []standard.Parameter {
				t.Helper()
				majordomoSvc := mock.NewMajordomo(map[string][]byte{})
				return []standard.Parameter{
					standard.WithMajordomo(majordomoSvc),
					standard.WithCertPEMURI("cert.pem"),
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

func TestGetCertificatePair(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		setup   func(t *testing.T) *standard.Service
		wantErr bool
	}{
		{
			name: "Success",
			setup: func(t *testing.T) *standard.Service {
				t.Helper()
				majordomoSvc := mock.NewMajordomo(map[string][]byte{
					"cert.pem": []byte(certtesting.ClientTest01Crt),
					"cert.key": []byte(certtesting.ClientTest01Key),
				})
				svc, err := standard.New(ctx,
					standard.WithMajordomo(majordomoSvc),
					standard.WithCertPEMURI("cert.pem"),
					standard.WithCertKeyURI("cert.key"),
				)
				require.NoError(t, err)
				return svc
			},
			wantErr: false,
		},
		{
			name: "InvalidCertificate",
			setup: func(t *testing.T) *standard.Service {
				t.Helper()
				majordomoSvc := mock.NewMajordomo(map[string][]byte{
					"cert.pem": []byte("invalid"),
					"cert.key": []byte("invalid"),
				})
				svc, err := standard.New(ctx,
					standard.WithMajordomo(majordomoSvc),
					standard.WithCertPEMURI("cert.pem"),
					standard.WithCertKeyURI("cert.key"),
				)
				require.NoError(t, err)
				return svc
			},
			wantErr: true,
		},
		{
			name: "MismatchedKeyPair",
			setup: func(t *testing.T) *standard.Service {
				t.Helper()
				majordomoSvc := mock.NewMajordomo(map[string][]byte{
					"cert.pem": []byte(certtesting.ClientTest01Crt),
					"cert.key": []byte(certtesting.ClientTest02Key), // Mismatched key
				})
				svc, err := standard.New(ctx,
					standard.WithMajordomo(majordomoSvc),
					standard.WithCertPEMURI("cert.pem"),
					standard.WithCertKeyURI("cert.key"),
				)
				require.NoError(t, err)
				return svc
			},
			wantErr: true,
		},
		{
			name: "FetchError",
			setup: func(t *testing.T) *standard.Service {
				t.Helper()
				majordomoSvc := mock.NewMajordomoWithError(os.ErrNotExist)
				svc, err := standard.New(ctx,
					standard.WithMajordomo(majordomoSvc),
					standard.WithCertPEMURI("cert.pem"),
					standard.WithCertKeyURI("cert.key"),
				)
				require.NoError(t, err)
				return svc
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := tt.setup(t)
			cert, err := svc.GetCertificatePair(ctx)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cert)
			require.NotEmpty(t, cert.Certificate)
		})
	}
}

func TestGetTLSConfig(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		setup     func(t *testing.T) *standard.Service
		wantErr   bool
		checkFunc func(t *testing.T, cfg *tls.Config)
	}{
		{
			name: "WithoutCA",
			setup: func(t *testing.T) *standard.Service {
				t.Helper()
				majordomoSvc := mock.NewMajordomo(map[string][]byte{
					"cert.pem": []byte(certtesting.ClientTest01Crt),
					"cert.key": []byte(certtesting.ClientTest01Key),
				})
				svc, err := standard.New(ctx,
					standard.WithMajordomo(majordomoSvc),
					standard.WithCertPEMURI("cert.pem"),
					standard.WithCertKeyURI("cert.key"),
				)
				require.NoError(t, err)
				return svc
			},
			wantErr: false,
			checkFunc: func(t *testing.T, cfg *tls.Config) {
				t.Helper()
				require.NotNil(t, cfg)
				require.Len(t, cfg.Certificates, 1)
				require.Equal(t, uint16(0x0304), cfg.MinVersion) // TLS 1.3
				require.Nil(t, cfg.RootCAs) // No CA specified
			},
		},
		{
			name: "WithCA",
			setup: func(t *testing.T) *standard.Service {
				t.Helper()
				majordomoSvc := mock.NewMajordomo(map[string][]byte{
					"cert.pem": []byte(certtesting.ClientTest01Crt),
					"cert.key": []byte(certtesting.ClientTest01Key),
					"ca.pem":   []byte(certtesting.CACrt),
				})
				svc, err := standard.New(ctx,
					standard.WithMajordomo(majordomoSvc),
					standard.WithCertPEMURI("cert.pem"),
					standard.WithCertKeyURI("cert.key"),
					standard.WithCACertURI("ca.pem"),
				)
				require.NoError(t, err)
				return svc
			},
			wantErr: false,
			checkFunc: func(t *testing.T, cfg *tls.Config) {
				t.Helper()
				require.NotNil(t, cfg)
				require.Len(t, cfg.Certificates, 1)
				require.Equal(t, uint16(0x0304), cfg.MinVersion) // TLS 1.3
				require.NotNil(t, cfg.RootCAs) // CA was specified
			},
		},
		{
			name: "InvalidCA",
			setup: func(t *testing.T) *standard.Service {
				t.Helper()
				majordomoSvc := mock.NewMajordomo(map[string][]byte{
					"cert.pem": []byte(certtesting.ClientTest01Crt),
					"cert.key": []byte(certtesting.ClientTest01Key),
					"ca.pem":   []byte("invalid CA"),
				})
				svc, err := standard.New(ctx,
					standard.WithMajordomo(majordomoSvc),
					standard.WithCertPEMURI("cert.pem"),
					standard.WithCertKeyURI("cert.key"),
					standard.WithCACertURI("ca.pem"),
				)
				require.NoError(t, err)
				return svc
			},
			wantErr: true,
		},
		{
			name: "CAFetchError",
			setup: func(t *testing.T) *standard.Service {
				t.Helper()
				// Majordomo with cert/key but CA fetch will fail
				data := map[string][]byte{
					"cert.pem": []byte(certtesting.ClientTest01Crt),
					"cert.key": []byte(certtesting.ClientTest01Key),
					// "ca.pem" intentionally missing
				}
				majordomoSvc := mock.NewMajordomo(data)
				svc, err := standard.New(ctx,
					standard.WithMajordomo(majordomoSvc),
					standard.WithCertPEMURI("cert.pem"),
					standard.WithCertKeyURI("cert.key"),
					standard.WithCACertURI("ca.pem"),
				)
				require.NoError(t, err)
				return svc
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := tt.setup(t)
			cfg, err := svc.GetTLSConfig(ctx)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.checkFunc != nil {
				tt.checkFunc(t, cfg)
			}
		})
	}
}

func TestGetTLSConfigVerifiesCertificate(t *testing.T) {
	ctx := context.Background()

	majordomoSvc := mock.NewMajordomo(map[string][]byte{
		"cert.pem": []byte(certtesting.ClientTest01Crt),
		"cert.key": []byte(certtesting.ClientTest01Key),
	})

	svc, err := standard.New(ctx,
		standard.WithMajordomo(majordomoSvc),
		standard.WithCertPEMURI("cert.pem"),
		standard.WithCertKeyURI("cert.key"),
	)
	require.NoError(t, err)

	cfg, err := svc.GetTLSConfig(ctx)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify the certificate can be parsed
	require.Len(t, cfg.Certificates, 1)
	cert, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	require.NoError(t, err)
	require.NotNil(t, cert)
	require.Contains(t, cert.Subject.CommonName, "client-test01")
}

func TestWithFilesystem(t *testing.T) {
	ctx := context.Background()

	// Create temp directory for certificates
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "client.crt")
	keyPath := filepath.Join(tempDir, "client.key")
	caPath := filepath.Join(tempDir, "ca.crt")

	// Write certificates to filesystem
	err := os.WriteFile(certPath, []byte(certtesting.ClientTest01Crt), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(keyPath, []byte(certtesting.ClientTest01Key), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(caPath, []byte(certtesting.CACrt), 0o600)
	require.NoError(t, err)

	// Create service using majordomo with file confidant
	svc, err := standard.New(ctx,
		standard.WithMajordomo(newMajordomo(t)),
		standard.WithCertPEMURI("file://"+certPath),
		standard.WithCertKeyURI("file://"+keyPath),
		standard.WithCACertURI("file://"+caPath),
	)
	require.NoError(t, err)

	// Verify certificate pair can be loaded
	certPair, err := svc.GetCertificatePair(ctx)
	require.NoError(t, err)
	require.NotNil(t, certPair)
	require.NotEmpty(t, certPair.Certificate)

	// Verify TLS config can be created with CA
	cfg, err := svc.GetTLSConfig(ctx)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.RootCAs)
	require.Len(t, cfg.Certificates, 1)
	require.Equal(t, uint16(0x0304), cfg.MinVersion) // TLS 1.3
}

func TestNewSentinelErrors(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		params   []standard.Parameter
		sentinel error
	}{
		{
			name: "NoMajordomo",
			params: []standard.Parameter{
				standard.WithCertPEMURI("cert.pem"),
				standard.WithCertKeyURI("cert.key"),
			},
			sentinel: certmanager.ErrNoMajordomo,
		},
		{
			name: "NoCertPEMURI",
			params: []standard.Parameter{
				standard.WithMajordomo(mock.NewMajordomo(nil)),
				standard.WithCertKeyURI("cert.key"),
			},
			sentinel: certmanager.ErrNoCertPEMURI,
		},
		{
			name: "NoCertKeyURI",
			params: []standard.Parameter{
				standard.WithMajordomo(mock.NewMajordomo(nil)),
				standard.WithCertPEMURI("cert.pem"),
			},
			sentinel: certmanager.ErrNoCertKeyURI,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := standard.New(ctx, test.params...)
			require.Error(t, err)
			require.ErrorIs(t, err, test.sentinel)
		})
	}
}

func TestMultipleGetTLSConfigCalls(t *testing.T) {
	ctx := context.Background()

	majordomoSvc := mock.NewMajordomo(map[string][]byte{
		"cert.pem": []byte(certtesting.ClientTest01Crt),
		"cert.key": []byte(certtesting.ClientTest01Key),
	})

	svc, err := standard.New(ctx,
		standard.WithMajordomo(majordomoSvc),
		standard.WithCertPEMURI("cert.pem"),
		standard.WithCertKeyURI("cert.key"),
	)
	require.NoError(t, err)

	// Call GetTLSConfig multiple times to ensure it works consistently
	for i := range 5 {
		cfg, err := svc.GetTLSConfig(ctx)
		require.NoError(t, err, "iteration %d", i)
		require.NotNil(t, cfg, "iteration %d", i)
		require.Len(t, cfg.Certificates, 1, "iteration %d", i)
	}
}

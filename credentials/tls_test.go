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

package credentials_test

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/attestantio/go-certmanager/credentials"
	certtesting "github.com/attestantio/go-certmanager/testing"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

// mockServerCertMgr is a simple mock implementing server.Service for testing.
type mockServerCertMgr struct {
	tlsConfig *tls.Config
	err       error
}

func (m *mockServerCertMgr) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, nil
}

func (m *mockServerCertMgr) ReloadCertificate(_ context.Context) {}

func (m *mockServerCertMgr) GetTLSConfig(_ context.Context) (*tls.Config, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.tlsConfig, nil
}

func (m *mockServerCertMgr) GetClientTLSConfig(_ context.Context) (*tls.Config, error) {
	return nil, nil
}

func TestNewServerTLSConfig(t *testing.T) {
	tests := []struct {
		name      string
		mock      *mockServerCertMgr
		caCertPEM []byte
		expectErr string
	}{
		{
			name: "empty CA PEM returns error",
			mock: &mockServerCertMgr{
				tlsConfig: &tls.Config{
					MinVersion: tls.VersionTLS13,
				},
			},
			caCertPEM: []byte{},
			expectErr: "CA certificate PEM is required when client cert verification is enabled",
		},
		{
			name: "nil CA PEM returns error",
			mock: &mockServerCertMgr{
				tlsConfig: &tls.Config{
					MinVersion: tls.VersionTLS13,
				},
			},
			caCertPEM: nil,
			expectErr: "CA certificate PEM is required when client cert verification is enabled",
		},
		{
			name: "invalid CA PEM returns error",
			mock: &mockServerCertMgr{
				tlsConfig: &tls.Config{
					MinVersion: tls.VersionTLS13,
				},
			},
			caCertPEM: []byte("not a valid PEM"),
			expectErr: "could not add CA certificate to pool",
		},
		{
			name: "GetTLSConfig error propagated",
			mock: &mockServerCertMgr{
				err: errors.New("mock TLS config error"),
			},
			caCertPEM: []byte(certtesting.CACrt),
			expectErr: "failed to get base TLS config",
		},
		{
			name: "happy path",
			mock: &mockServerCertMgr{
				tlsConfig: &tls.Config{
					MinVersion: tls.VersionTLS13,
				},
			},
			caCertPEM: []byte(certtesting.CACrt),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			cfg, err := credentials.NewServerTLSConfig(ctx, tc.mock, tc.caCertPEM)

			if tc.expectErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectErr)
				require.Nil(t, cfg)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				require.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
				require.NotNil(t, cfg.ClientCAs)
				require.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
			}
		})
	}
}

func TestNewServerTLSConfig_ConfigNotMutated(t *testing.T) {
	ctx := context.Background()

	baseCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	mock := &mockServerCertMgr{
		tlsConfig: baseCfg,
	}

	result, err := credentials.NewServerTLSConfig(ctx, mock, []byte(certtesting.CACrt))
	require.NoError(t, err)
	require.NotNil(t, result)

	// The returned config must NOT be the same pointer as the base config.
	require.NotSame(t, baseCfg, result, "returned config must be a clone, not the original")

	// The base config must NOT have been mutated.
	require.Equal(t, tls.NoClientCert, baseCfg.ClientAuth, "base config ClientAuth must not be mutated")
	require.Nil(t, baseCfg.ClientCAs, "base config ClientCAs must not be mutated")
}

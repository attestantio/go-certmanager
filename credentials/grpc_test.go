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
	"errors"
	"testing"

	"github.com/attestantio/go-certmanager/credentials"
	"github.com/stretchr/testify/require"
)

// mockClientCertMgr is a simple mock implementing client.Service for testing.
type mockClientCertMgr struct {
	tlsConfig *tls.Config
	err       error
}

func (m *mockClientCertMgr) GetTLSConfig(_ context.Context) (*tls.Config, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.tlsConfig, nil
}

func (m *mockClientCertMgr) GetCertificatePair(_ context.Context) (*tls.Certificate, error) {
	return nil, nil
}

func TestNewGRPCClientCredentials(t *testing.T) {
	tests := []struct {
		name      string
		mock      *mockClientCertMgr
		expectErr string
	}{
		{
			name: "happy path",
			mock: &mockClientCertMgr{
				tlsConfig: &tls.Config{
					MinVersion: tls.VersionTLS13,
				},
			},
		},
		{
			name: "GetTLSConfig error propagated",
			mock: &mockClientCertMgr{
				err: errors.New("mock TLS config error"),
			},
			expectErr: "failed to get TLS config",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			creds, err := credentials.NewGRPCClientCredentials(ctx, tc.mock)

			if tc.expectErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectErr)
				require.Nil(t, creds)
			} else {
				require.NoError(t, err)
				require.NotNil(t, creds)
				require.Equal(t, "tls", creds.Info().SecurityProtocol)
			}
		})
	}
}

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

package credentials

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	"github.com/attestantio/go-certmanager/server"
	"github.com/pkg/errors"
)

// NewServerTLSConfig creates a TLS config for gRPC servers with client certificate verification.
//
// Parameters:
//   - ctx: Context for the operation
//   - serverCertMgr: Server certificate manager providing the server's certificate
//   - caCertPEM: CA certificate (PEM format) for validating client certificates
//
// The returned config requires and verifies client certificates, enforces TLS 1.3 minimum,
// and uses the server certificate manager's dynamic certificate retrieval.
//
// Example usage:
//
//	serverCertMgr, _ := servercert.New(ctx, ...)
//	tlsCfg, _ := credentials.NewServerTLSConfig(ctx, serverCertMgr, caCertPEM)
//	serverCreds := credentials.NewTLS(tlsCfg)
//	grpcServer := grpc.NewServer(grpc.Creds(serverCreds))
func NewServerTLSConfig(
	ctx context.Context,
	serverCertMgr server.Service,
	caCertPEM []byte,
) (*tls.Config, error) {
	baseCfg, err := serverCertMgr.GetTLSConfig(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get base TLS config")
	}

	certPool := x509.NewCertPool()
	if len(caCertPEM) > 0 {
		if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
			return nil, errors.New("could not add CA certificate to pool")
		}
	}

	baseCfg.ClientAuth = tls.RequireAndVerifyClientCert
	baseCfg.ClientCAs = certPool

	return baseCfg, nil
}

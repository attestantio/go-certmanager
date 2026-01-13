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

	"github.com/attestantio/go-certmanager/client"
	"github.com/pkg/errors"
	"google.golang.org/grpc/credentials"
)

// NewGRPCClientCredentials creates gRPC TransportCredentials from a client certificate manager.
// This is a convenience function for creating gRPC client connections with TLS.
//
// Example usage:
//
//	clientCertMgr, _ := clientcert.New(ctx, ...)
//	creds, _ := credentials.NewGRPCClientCredentials(ctx, clientCertMgr)
//	conn, _ := grpc.Dial("server:9091", grpc.WithTransportCredentials(creds))
func NewGRPCClientCredentials(ctx context.Context, clientCertMgr client.Service) (credentials.TransportCredentials, error) {
	tlsCfg, err := clientCertMgr.GetTLSConfig(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get TLS config")
	}
	return credentials.NewTLS(tlsCfg), nil
}

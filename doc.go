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

// Package certmanager provides certificate management capabilities for both
// server and client TLS configurations.
//
// The library supports:
//   - Server certificate loading with manual reload via ReloadCertificate (e.g., on SIGHUP)
//   - Client certificate loading for gRPC and TLS connections
//   - DNS-based SAN identity extraction with CN fallback (RFC 1123/6125)
//   - Flexible certificate fetching via majordomo service
//   - Thread-safe operations for concurrent access
//
// Server Certificate Management:
//
// The server package provides certificate management for TLS servers with
// manual reloading capabilities. Use this for long-running services that
// need to reload certificates without restarting.
//
//	import servercert "github.com/attestantio/go-certmanager/server/standard"
//
//	certMgr, err := servercert.New(ctx,
//	    servercert.WithMajordomo(majordomoSvc),
//	    servercert.WithCertPEMURI("file:///path/to/server.crt"),
//	    servercert.WithCertKeyURI("file:///path/to/server.key"),
//	)
//
//	// Use in TLS server config
//	tlsConfig, _ := certMgr.GetTLSConfig(ctx)
//
//	// Trigger reload (e.g., on SIGHUP)
//	if err := certMgr.ReloadCertificate(ctx); err != nil {
//	    log.Warn().Err(err).Msg("Certificate reload failed")
//	}
//
// For peer-to-peer scenarios where the same certificate is used for both
// server and client roles, use the concrete standard.Service's
// GetClientTLSConfig() to get a static certificate config suitable for
// client connections:
//
//	// Use the same cert manager for client connections
//	clientTLSConfig, _ := certMgr.GetClientTLSConfig(ctx)
//	conn, _ := grpc.NewClient("peer:port",
//	    grpc.WithTransportCredentials(credentials.NewTLS(clientTLSConfig)))
//
// Important: GetClientTLSConfig returns a point-in-time snapshot — it will not
// reflect subsequent ReloadCertificate calls. After a SIGHUP reload, callers
// must re-fetch the client TLS config and replace existing transport credentials.
// Recommended pattern:
//
//	certMgr.ReloadCertificate(ctx)
//	clientTLSConfig, _ = certMgr.GetClientTLSConfig(ctx)
//	// Replace transport credentials on your gRPC client connection.
//
// Client Certificate Management:
//
// The client package provides certificate loading for client connections.
//
//	import clientcert "github.com/attestantio/go-certmanager/client/standard"
//
//	certMgr, err := clientcert.New(ctx,
//	    clientcert.WithMajordomo(majordomoSvc),
//	    clientcert.WithCertPEMURI("file:///path/to/client.crt"),
//	    clientcert.WithCertKeyURI("file:///path/to/client.key"),
//	    clientcert.WithCACertURI("file:///path/to/ca.crt"), // Optional
//	)
//
//	// Use in gRPC client
//	creds, _ := credentials.NewGRPCClientCredentials(ctx, certMgr)
//	conn, _ := grpc.NewClient("server:port", grpc.WithTransportCredentials(creds))
//
// Certificate Fetching:
//
// Certificate data is fetched via go-majordomo (github.com/wealdtech/go-majordomo),
// which supports pluggable "confidants" for files, HTTP endpoints, secret vaults, etc.
// Pass a majordomo.Service directly to WithMajordomo() when creating certificate managers.
//
// SAN Extraction:
//
// The san package extracts DNS-based identity from X.509 certificates with
// CN fallback. DNS names are validated against RFC 1123 and RFC 6125; invalid
// names are skipped. If no valid DNS name is found, the Common Name is used.
//
//	import "github.com/attestantio/go-certmanager/san"
//
//	identity, source := san.ExtractIdentity(cert)
//	allSANs := san.ExtractAllSANs(cert)
package certmanager

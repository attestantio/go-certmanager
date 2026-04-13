# go-certmanager

[![Tag](https://img.shields.io/github/tag/attestantio/go-certmanager.svg)](https://github.com/attestantio/go-certmanager/releases/)
[![License](https://img.shields.io/github/license/attestantio/go-certmanager.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/attestantio/go-certmanager.svg)](https://pkg.go.dev/github.com/attestantio/go-certmanager)
![Lint](https://github.com/attestantio/go-certmanager/workflows/golangci-lint/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/attestantio/go-certmanager)](https://goreportcard.com/report/github.com/attestantio/go-certmanager)

Go library providing certificate management capabilities for both server and client TLS configurations.

The library supports:
  - Server certificate loading with manual reload via `ReloadCertificate()` (e.g., on SIGHUP)
  - Client certificate loading for gRPC and TLS connections
  - DNS-based SAN identity extraction with CN fallback (RFC 1123/6125)
  - Flexible certificate fetching via majordomo service
  - Thread-safe operations for concurrent access

This library is used by Attestant projects such as [Vouch](https://github.com/attestantio/vouch) (Ethereum validator client) and [Dirk](https://github.com/attestantio/dirk) (distributed remote keymanager) for certificate management in Ethereum staking infrastructure.

## Package Overview

| Package | Description |
|---------|-------------|
| `server/standard` | Server certificate manager with reload support |
| `client/standard` | Client certificate manager with optional CA pool |
| `credentials` | gRPC credential helpers (`NewGRPCClientCredentials`, `NewServerTLSConfig`) |
| `san` | X.509 SAN identity extraction and DNS name validation |
| `testing` | Pre-generated test certificates and mock majordomo |

## Table of Contents

- [go-certmanager](#go-certmanager)
  - [Package Overview](#package-overview)
  - [Table of Contents](#table-of-contents)
  - [Requirements](#requirements)
  - [Install](#install)
  - [Usage](#usage)
    - [Certificate Fetching](#certificate-fetching)
    - [Server Certificate Management](#server-certificate-management)
    - [Client Certificate Management](#client-certificate-management)
    - [gRPC Credentials](#grpc-credentials)
    - [SAN Extraction](#san-extraction)
  - [Maintainers](#maintainers)
  - [Contributing](#contributing)
  - [License](#license)

## Requirements

- Go 1.25.5 or later
- [go-majordomo](https://github.com/wealdtech/go-majordomo) for certificate fetching
- [gRPC-Go](https://google.golang.org/grpc) (required by the `credentials` package)

## Install

`go-certmanager` is a standard Go module which can be installed with:

```sh
go get github.com/attestantio/go-certmanager
```

## Usage

### Certificate Fetching

Certificate data is fetched via [go-majordomo](https://github.com/wealdtech/go-majordomo), which supports pluggable "confidants" for files, HTTP endpoints, secret vaults, etc. You must create a majordomo service and pass it to certificate managers via `WithMajordomo()`.

Setting up a file-based majordomo service:

```go
import (
    "github.com/wealdtech/go-majordomo"
    fsc "github.com/wealdtech/go-majordomo/confidants/fs"
)

confidant, err := fsc.New(ctx)
if err != nil {
    return err
}

majordomoSvc, err := majordomo.New(ctx,
    majordomo.WithConfidants(map[string]majordomo.Confidant{"file": confidant}),
)
if err != nil {
    return err
}

// Use majordomoSvc with certificate managers (see below)
```

Certificate URIs follow the majordomo format: `file:///path/to/cert.pem`, `https://vault.example.com/secret/cert`, etc.

### Server Certificate Management

The server package provides certificate management for TLS servers with manual reloading capabilities. Use this for long-running services that need to reload certificates without restarting.

```go
import servercert "github.com/attestantio/go-certmanager/server/standard"

certMgr, err := servercert.New(ctx,
    servercert.WithMajordomo(majordomoSvc),
    servercert.WithCertPEMURI("file:///path/to/server.crt"),
    servercert.WithCertKeyURI("file:///path/to/server.key"),
    servercert.WithLoadTimeout(30*time.Second), // Optional: timeout for certificate fetch operations
)
if err != nil {
    return err
}

// Use in TLS server config
tlsConfig, err := certMgr.GetTLSConfig(ctx)

// Trigger reload (e.g., on SIGHUP)
if err := certMgr.ReloadCertificate(ctx); err != nil {
    log.Warn().Err(err).Msg("Certificate reload failed")
}
```

For peer-to-peer scenarios where the same certificate is used for both server and client roles, use `GetClientTLSConfig()` to get a static certificate config suitable for client connections:

```go
// Use the same cert manager for client connections
clientTLSConfig, err := certMgr.GetClientTLSConfig(ctx)
conn, err := grpc.NewClient("peer:port",
    grpc.WithTransportCredentials(credentials.NewTLS(clientTLSConfig)))
```

This is useful for peer-to-peer communication where a single certificate serves both roles.

> **Important:** `GetClientTLSConfig()` returns a point-in-time snapshot — it will **not** reflect subsequent `ReloadCertificate()` calls. After a SIGHUP reload, callers must re-fetch the client TLS config and re-establish connections, as gRPC does not support in-place credential replacement.

Recommended pattern for SIGHUP handlers:

```go
// In your SIGHUP handler:
if err := certMgr.ReloadCertificate(ctx); err != nil {
    log.Warn().Err(err).Msg("Certificate reload failed")
    return
}

// Re-fetch client TLS config after successful reload
newClientTLSConfig, err := certMgr.GetClientTLSConfig(ctx)
if err != nil {
    log.Error().Err(err).Msg("Failed to get updated client TLS config")
    return
}

// gRPC does not support in-place credential replacement;
// close and re-establish the connection with the new config.
oldConn.Close()
conn, err = grpc.NewClient("peer:port",
    grpc.WithTransportCredentials(credentials.NewTLS(newClientTLSConfig)))
```

### Client Certificate Management

The client package provides certificate loading for client connections.

```go
import clientcert "github.com/attestantio/go-certmanager/client/standard"

certMgr, err := clientcert.New(ctx,
    clientcert.WithMajordomo(majordomoSvc),
    clientcert.WithCertPEMURI("file:///path/to/client.crt"),
    clientcert.WithCertKeyURI("file:///path/to/client.key"),
    clientcert.WithCACertURI("file:///path/to/ca.crt"),      // Optional: CA for server verification
    clientcert.WithLoadTimeout(30*time.Second),               // Optional: timeout for certificate fetch operations
)
if err != nil {
    return err
}

// Get TLS config for client connections
tlsConfig, err := certMgr.GetTLSConfig(ctx)
```

### gRPC Credentials

The `credentials` package provides helpers for setting up TLS in gRPC services.

**Client credentials** from a client certificate manager:

```go
import (
    clientcert "github.com/attestantio/go-certmanager/client/standard"
    certcreds "github.com/attestantio/go-certmanager/credentials"
)

clientCertMgr, err := clientcert.New(ctx,
    clientcert.WithMajordomo(majordomoSvc),
    clientcert.WithCertPEMURI("file:///path/to/client.crt"),
    clientcert.WithCertKeyURI("file:///path/to/client.key"),
)
if err != nil {
    return err
}

creds, err := certcreds.NewGRPCClientCredentials(ctx, clientCertMgr)
if err != nil {
    return err
}

conn, err := grpc.NewClient("server:9091", grpc.WithTransportCredentials(creds))
```

**Server TLS with mutual authentication** (client certificate verification):

```go
import (
    servercert "github.com/attestantio/go-certmanager/server/standard"
    certcreds "github.com/attestantio/go-certmanager/credentials"
    grpccreds "google.golang.org/grpc/credentials"
)

serverCertMgr, err := servercert.New(ctx,
    servercert.WithMajordomo(majordomoSvc),
    servercert.WithCertPEMURI("file:///path/to/server.crt"),
    servercert.WithCertKeyURI("file:///path/to/server.key"),
)
if err != nil {
    return err
}

tlsCfg, err := certcreds.NewServerTLSConfig(ctx, serverCertMgr, caCertPEM)
if err != nil {
    return err
}

grpcServer := grpc.NewServer(grpc.Creds(grpccreds.NewTLS(tlsCfg)))
```

### SAN Extraction

The san package extracts DNS-based identity from X.509 certificates with CN fallback. DNS names are validated against RFC 1123 and RFC 6125; invalid names are skipped.

```go
import "github.com/attestantio/go-certmanager/san"

// Extract primary identity from certificate
identity, source := san.ExtractIdentity(cert)
// source indicates: IdentitySourceSANDNS, IdentitySourceCN, or IdentitySourceUnknown

// Convenience wrapper that returns just the identity string
name := san.IdentityString(cert)

// Extract all DNS Subject Alternative Names (returned as a CertificateSANs struct)
allSANs := san.ExtractAllSANs(cert)
// Access: allSANs.DNSNames

// Validate a DNS name against RFC 1123 and RFC 6125
if err := san.ValidateDNSName("example.com"); err != nil {
    log.Error().Err(err).Msg("Invalid DNS name")
}
```

## Maintainers

[@AntiD2ta](https://github.com/AntiD2ta)
[@Bez625](https://github.com/Bez625)

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[Apache-2.0](LICENSE) - see [LICENSE](LICENSE) for the full text.

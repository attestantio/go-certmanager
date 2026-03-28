# go-certmanager

[![Tag](https://img.shields.io/github/tag/attestantio/go-certmanager.svg)](https://github.com/attestantio/go-certmanager/releases/)
[![License](https://img.shields.io/github/license/attestantio/go-certmanager.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/attestantio/go-certmanager?status.svg)](https://godoc.org/github.com/attestantio/go-certmanager)
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

## Table of Contents

- [go-certmanager](#go-certmanager)
  - [Table of Contents](#table-of-contents)
  - [Install](#install)
  - [Usage](#usage)
    - [Server Certificate Management](#server-certificate-management)
    - [Client Certificate Management](#client-certificate-management)
    - [Certificate Fetching](#certificate-fetching)
    - [SAN Extraction](#san-extraction)
  - [Maintainers](#maintainers)
  - [Contributing](#contributing)
  - [License](#license)

## Install

`go-certmanager` is a standard Go module which can be installed with:

```sh
go get github.com/attestantio/go-certmanager
```

## Usage

### Server Certificate Management

The server package provides certificate management for TLS servers with manual reloading capabilities. Use this for long-running services that need to reload certificates without restarting.

```go
import servercert "github.com/attestantio/go-certmanager/server/standard"

certMgr, err := servercert.New(ctx,
    servercert.WithMajordomo(majordomoSvc),
    servercert.WithCertPEMURI("file:///path/to/server.crt"),
    servercert.WithCertKeyURI("file:///path/to/server.key"),
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

> **Important:** `GetClientTLSConfig()` returns a point-in-time snapshot — it will **not** reflect subsequent `ReloadCertificate()` calls. After a SIGHUP reload, callers must re-fetch the client TLS config and replace existing transport credentials, otherwise live connections will continue using the old certificate.

Recommended pattern for SIGHUP handlers:

```go
// In your SIGHUP handler:
if err := certMgr.ReloadCertificate(ctx); err != nil {
    log.Warn().Err(err).Msg("Certificate reload failed")
} else {
    // Re-fetch client TLS config after successful reload
    clientTLSConfig, err = certMgr.GetClientTLSConfig(ctx)
    // Replace transport credentials on your gRPC client connection
}
```

### Client Certificate Management

The client package provides certificate loading for client connections.

```go
import clientcert "github.com/attestantio/go-certmanager/client/standard"

certMgr, err := clientcert.New(ctx,
    clientcert.WithMajordomo(majordomoSvc),
    clientcert.WithCertPEMURI("file:///path/to/client.crt"),
    clientcert.WithCertKeyURI("file:///path/to/client.key"),
    clientcert.WithCACertURI("file:///path/to/ca.crt"), // Optional
)
if err != nil {
    return err
}

// Get TLS config for client connections
tlsConfig, err := certMgr.GetTLSConfig(ctx)
```

### Certificate Fetching

Certificate data is fetched via [go-majordomo](https://github.com/wealdtech/go-majordomo), which supports pluggable "confidants" for files, HTTP endpoints, secret vaults, etc. Pass a `majordomo.Service` directly to `WithMajordomo()` when creating certificate managers.

### SAN Extraction

The san package extracts DNS-based identity from X.509 certificates with CN fallback. DNS names are validated against RFC 1123 and RFC 6125; invalid names are skipped.

```go
import "github.com/attestantio/go-certmanager/san"

// Extract primary identity from certificate
identity, source := san.ExtractIdentity(cert)
// source indicates: IdentitySourceSANDNS, IdentitySourceCN, or IdentitySourceUnknown

// Extract all DNS Subject Alternative Names
allSANs := san.ExtractAllSANs(cert)
// Access: allSANs.DNSNames
```

## Maintainers

[@AntiD2ta](https://github.com/AntiD2ta)
[@Bez625](https://github.com/Bez625)

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[Apache-2.0](LICENSE) - see [LICENSE](LICENSE) for the full text.

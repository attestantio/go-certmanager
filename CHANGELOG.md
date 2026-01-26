# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-01-XX

### Added

- **Server Certificate Manager** (`server/standard/`)
  - Dynamic certificate loading with automatic reload on expiry
  - SIGHUP signal support for manual certificate reload
  - Thread-safe certificate access using atomic operations
  - `GetTLSConfig()` for server-side TLS configuration with dynamic certificate callback
  - `GetClientTLSConfig()` for peer-to-peer scenarios using the same certificate

- **Client Certificate Manager** (`client/standard/`)
  - Client certificate loading for TLS/gRPC connections
  - Optional CA certificate support for server verification
  - `GetTLSConfig()` for client-side TLS configuration
  - `GetCertificatePair()` for direct certificate access

- **Fetcher Abstraction** (`fetcher/`)
  - Pluggable `Fetcher` interface for certificate retrieval
  - Majordomo implementation supporting files, HTTP endpoints, and secret vaults

- **SAN Extraction Utilities** (`san/`)
  - RFC 6125-compliant identity extraction from X.509 certificates
  - Priority order: DNS names > IP addresses > Email addresses > Common Name
  - `ExtractIdentity()` for primary identity retrieval with source indication
  - `ExtractAllSANs()` for comprehensive Subject Alternative Name extraction

- **gRPC Credentials Helpers** (`credentials/`)
  - `NewGRPCClientCredentials()` for simplified gRPC client setup
  - `NewServerTLSConfig()` for gRPC server setup with client certificate verification

- **Testing Utilities** (`testing/`)
  - Pre-generated test certificates (valid and expired) for unit testing
  - Mock fetcher implementation for controlled testing scenarios

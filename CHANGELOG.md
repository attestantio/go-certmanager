# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-03-26

### Added

- **Server Certificate Manager** (`server/standard/`)
  - Certificate loading with expiry validation at startup
  - Manual reload via `ReloadCertificate()` (e.g., on SIGHUP)
  - Thread-safe certificate access using atomic operations
  - `GetTLSConfig()` for server-side TLS configuration with dynamic certificate callback
  - `GetClientTLSConfig()` for peer-to-peer scenarios using the same certificate

- **Client Certificate Manager** (`client/standard/`)
  - Certificate loading with expiry validation at startup
  - Cached certificate pair and CA pool loaded at construction time
  - `GetTLSConfig()` for client-side TLS configuration
  - `GetCertificatePair()` for direct certificate access

- **Certificate Fetching**
  - Direct integration with go-majordomo for flexible certificate retrieval
  - Supports files, HTTP endpoints, and secret vaults via majordomo confidants

- **SAN Extraction Utilities** (`san/`)
  - DNS-only identity extraction from X.509 certificates with CN fallback
  - DNS name validation following RFC 1123 and RFC 6125
  - `ExtractIdentity()` for primary identity retrieval with source indication
  - `ExtractAllSANs()` for DNS Subject Alternative Name extraction
  - `ValidateDNSName()` for RFC-compliant DNS name validation

- **gRPC Credentials Helpers** (`credentials/`)
  - `NewGRPCClientCredentials()` for simplified gRPC client setup
  - `NewServerTLSConfig()` for gRPC server setup with client certificate verification

- **Testing Utilities** (`testing/`)
  - Pre-generated test certificates (valid and expired) for unit testing
  - Mock majordomo implementation for controlled testing scenarios

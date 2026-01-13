# go-certmanager


4. Client Certificate Manager (client/standard/)
    - Extracted from vouch's credentialsFromCerts patterns
    - Supports optional CA certificates
    - TLS 1.3 minimum enforcement
    - Lazy certificate fetching
  5. SAN Extraction Utilities (san/)
    - RFC 6125-compliant identity extraction
    - Priority: DNS > IP > Email > CN
    - Comprehensive tests (all passing)
  6. Credentials Helpers (credentials/)
    - gRPC client credentials builder
    - Server TLS config with client cert verification
  7. Testing Utilities (testing/)
    - All test certificates from vouch (CA + 5 server + 3 client pairs)
    - Mock fetcher for testing
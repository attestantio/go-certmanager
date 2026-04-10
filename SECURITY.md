# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in go-certmanager, please report it responsibly:

1. **Do not** open a public issue
2. Email security concerns to security@attestant.io
3. Include a detailed description of the vulnerability
4. Provide steps to reproduce if possible

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Security Considerations

This library handles TLS certificates and private keys. Users should:

- Store private keys securely with appropriate file permissions
- Use secure majordomo confidants for production environments
- Regularly rotate certificates before expiry
- Monitor certificate reload logs for failures

# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of Booli Admin API seriously. If you discover a security vulnerability, please follow these steps:

1. **Do not** create a public GitHub issue for the vulnerability
2. Email security details to: security@booli.ai
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact
   - Suggested fix (if available)

## Security Features

### Built-in Security

- JWT-based authentication with Keycloak OIDC
- Role-based access control (RBAC)
- Row-level security (RLS) for multi-tenant isolation
- Input validation and sanitization
- Secure random generation for state parameters
- No sensitive data exposure in error messages

### Supply Chain Security

- All release artifacts are signed with Cosign
- SBOM (Software Bill of Materials) generated for all releases
- Vulnerability scanning with Trivy and Gosec
- Container images scanned for vulnerabilities
- Dependencies checked with govulncheck

### Verification

#### Verify Release Artifacts

```bash
# Download the release and signature files
wget https://github.com/booli/booli-auth-keycloak/releases/download/v1.0.0/checksums.txt
wget https://github.com/booli/booli-auth-keycloak/releases/download/v1.0.0/checksums.txt.cert
wget https://github.com/booli/booli-auth-keycloak/releases/download/v1.0.0/checksums.txt.sig

# Verify with cosign
cosign verify-blob \
  --certificate checksums.txt.cert \
  --signature checksums.txt.sig \
  checksums.txt
```

#### Verify Container Images

```bash
# Verify container image signature
cosign verify ghcr.io/booli/booli-admin-api:v1.0.0
```

## Security Scanning

This project uses automated security scanning:

- **CodeQL**: Static analysis for Go code
- **Gosec**: Go security checker
- **Trivy**: Vulnerability scanner for containers and filesystems
- **govulncheck**: Go vulnerability database checker
- **Dependency Review**: GitHub's dependency vulnerability checker

Scans run on:
- Every push to main/develop branches
- Every pull request
- Daily scheduled scans
- Every release

## Security Best Practices

When deploying Booli Admin API:

1. Use TLS/SSL for all external connections
2. Keep dependencies updated
3. Use strong database passwords
4. Rotate JWT secrets regularly
5. Enable audit logging
6. Implement network segmentation
7. Use security scanning tools
8. Monitor for vulnerabilities
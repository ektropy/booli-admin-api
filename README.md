# Booli Admin API

[![Fast CI/CD](https://github.com/booli/booli-admin-api/workflows/Fast%20CI%2FCD/badge.svg)](https://github.com/booli/booli-admin-api/actions/workflows/ci-fast.yml)
[![Code Coverage](https://img.shields.io/codecov/c/github/booli/booli-admin-api)](https://codecov.io/gh/booli/booli-admin-api)
[![Go Report Card](https://goreportcard.com/badge/github.com/booli/booli-admin-api)](https://goreportcard.com/report/github.com/booli/booli-admin-api)
[![Docker Image](https://img.shields.io/badge/docker-ghcr.io-blue)](https://ghcr.io/booli/booli-admin-api)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Multi-tenant administrative portal with Keycloak authentication and MSP support.

## Features

- **Multi-tenant architecture** with row-level security (PostgreSQL RLS)
- **Keycloak OIDC authentication** with multiple provider support
- **MSP (Managed Service Provider)** support with hierarchical tenants
- **Role-based access control** (RBAC) with granular permissions and validation
- **Infrastructure management** (domains, networks, IPs, DNS, security scanners)
- **RESTful API** with comprehensive OpenAPI documentation
- **Docker containerization** with development and production setups
- **PostgreSQL** with Valkey/Redis caching for performance
- **Advanced audit logging** with configuration change tracking
- **Bruno API testing** suite for comprehensive integration testing
- **JSON-based configuration** with validation and security controls
- **SSO provider management** with OIDC and SAML support

## Quick Start

### Prerequisites

- **PostgreSQL 15+**
- **Keycloak 26+**
- **Valkey/Redis 8+**
- **Go 1.24+** (for development)

### Using Docker (Recommended)

```bash
# Clone repository
git clone <repository>
cd booli-admin-api/backend

# Start development environment
docker-compose up -d

# The API will be available at http://localhost:8081
# Keycloak admin: http://localhost:8083 (admin/admin)
# PostgreSQL: localhost:5432
# Valkey: localhost:6379
```

### Manual Setup

1. **Configure environment variables:**
```bash
export BOOLI_DATABASE_HOST=localhost
export BOOLI_DATABASE_USER=postgres
export BOOLI_DATABASE_PASSWORD=your_password
export BOOLI_KEYCLOAK_URL=http://localhost:8083
export BOOLI_KEYCLOAK_ADMIN_USER=admin
export BOOLI_KEYCLOAK_ADMIN_PASSWORD=admin_password
```

2. **Initialize the system:**
```bash
# First-time setup (any environment)
./booli-admin-api -init

# Only use -force when overwriting existing configuration
./booli-admin-api -init -force
```

3. **Start the server:**
```bash
./booli-admin-api
```

## Configuration

The application supports multiple configuration methods with precedence order:

1. **Environment variables** (highest priority)
2. **Configuration files** (YAML, TOML, or JSON)
3. **Default values** (lowest priority)

### Configuration Files

Configuration files are automatically detected in these locations:
- `./config.yaml`, `./config.toml`, or `./config.json` (current directory)
- `./config/config.yaml`, `./config/config.toml`, or `./config/config.json` (config subdirectory)
- `/etc/booli-admin/config.yaml`, `/etc/booli-admin/config.toml`, or `/etc/booli-admin/config.json` (system directory)

Or specify a custom path:
```bash
./booli-admin-api -config /path/to/your/config.yaml
```

### Example Configuration Files

Copy and modify the example file:
```bash
cp config.yaml.example config.yaml
# Edit config.yaml with your settings
```

### Essential Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BOOLI_ENVIRONMENT` | Application environment (`development`, `production`, `test`) | `production` |
| `BOOLI_SERVER_PORT` | Server port | `8081` |
| `BOOLI_DATABASE_HOST` | PostgreSQL host | `localhost` |
| `BOOLI_DATABASE_PORT` | PostgreSQL port | `5432` |
| `BOOLI_DATABASE_USER` | Database user | - |
| `BOOLI_DATABASE_PASSWORD` | Database password | - |
| `BOOLI_DATABASE_DBNAME` | Database name | `booli_admin` |
| `BOOLI_DATABASE_SSLMODE` | SSL mode | `disable` |
| `BOOLI_REDIS_HOST` | Valkey/Redis host | `localhost` |
| `BOOLI_REDIS_PORT` | Valkey/Redis port | `6379` |
| `BOOLI_KEYCLOAK_URL` | Keycloak base URL | - |
| `BOOLI_KEYCLOAK_ADMIN_USER` | Keycloak admin user | - |
| `BOOLI_KEYCLOAK_ADMIN_PASSWORD` | Keycloak admin password | - |
| `BOOLI_KEYCLOAK_MSP_REALM` | MSP realm name | `msp-platform` |
| `BOOLI_KEYCLOAK_CLIENT_ID` | OAuth client ID | - |
| `BOOLI_KEYCLOAK_CLIENT_SECRET` | OAuth client secret | - |
| `BOOLI_KEYCLOAK_CALLBACK_URL` | OAuth callback URL | - |
| `BOOLI_KEYCLOAK_API_AUDIENCE` | JWT audience | `booli-admin-api` |

## API Documentation

Once running, access the comprehensive OpenAPI documentation at:
- **Swagger UI**: `http://localhost:8081/swagger/`
- **OpenAPI JSON**: `http://localhost:8081/swagger/doc.json`
- **Health Check**: `http://localhost:8081/health`
- **Keycloak Health**: `http://localhost:8081/health/keycloak`

### API Endpoints

- **Authentication**: `/api/v1/auth/*` - OIDC authentication, token validation
- **Admin**: `/api/v1/admin/*` - MSP admin operations (tenants, users, roles)
- **Tenant-scoped**: `/api/v1/*` - Tenant-specific operations
- **Infrastructure**: Environment, domain, network, IP management
- **Audit**: Logging and CSV export capabilities
- **SSO**: Provider management and testing with OIDC/SAML support

## Development

### Prerequisites

- **Go 1.23+**
- **Task** (go-task.github.io)
- **Docker & Docker Compose**

### Setup

```bash
# Install dependencies
task deps

# Build
task build

# Run tests
task test

# Run unit tests only
task test-unit

# Start development environment
task dev

# Run integration tests
task test-integration

# Run all integration test suites
task test-integration-all

# Format code
task fmt

# Run linter
task lint

# Run security scan
task security

# Build Docker image
task docker-build

# Start development services
task start-dev-env

# Run Bruno API tests
task bruno-test

# Generate OpenAPI docs
task swagger

# Clean build artifacts
task clean
```

### Available Tasks

```bash
task --list
```

### Bruno API Testing

The project includes a comprehensive Bruno API testing suite:

```bash
# Run tests against development environment
task bruno-test-dev

# Run tests with Docker Compose
task bruno-test
```

Test categories:
- **Health checks**: Basic connectivity
- **Authentication**: OIDC flows, token validation
- **Security tests**: Invalid tokens, unauthorized access
- **Admin workflows**: Tenant and user management
- **Tenant workflows**: Role management, SSO configuration
- **Validation tests**: Configuration validation and error handling

## Architecture

### Multi-Tenant Design

- **Row-Level Security (RLS)**: PostgreSQL RLS policies ensure tenant isolation
- **Keycloak Integration**: Single source of truth for users and authentication
- **Hierarchical Structure**: MSP -> Tenant -> Users with proper access controls
- **Infrastructure Management**: Comprehensive network and security asset tracking

### Security Features

- **Secure by default**: Production mode with security hardening
- **JWT-based authentication**: Keycloak OIDC integration
- **Role-based access control**: Granular permissions system with validation
- **Input validation**: Comprehensive validation and sanitization
- **Advanced audit logging**: Configuration change tracking and security events
- **Token security**: Proper token handling, no sensitive data exposure
- **Permission validation**: Prevents privilege escalation and invalid configurations
- **Configuration security**: Validates tenant settings, role permissions, and SSO configurations
- **Sensitive data protection**: Automatic redaction of credentials in logs

### Performance

- **Valkey/Redis caching**: Tenant-scoped caching for performance
- **Connection pooling**: Efficient database connection management
- **Optimized queries**: Proper indexing and query optimization
- **Pagination**: Consistent pagination across all endpoints

### Configuration Management

- **Modern JSONB storage**: Uses PostgreSQL JSONB with GORM `datatypes.JSON`
- **Schema validation**: Comprehensive validation for all JSON configurations
- **Change tracking**: Detailed audit logs for configuration modifications
- **Type safety**: Proper marshaling/unmarshaling with error handling
- **Security validation**: Prevents invalid configurations and privilege escalation

## Infrastructure Management

The system provides comprehensive infrastructure management capabilities:

### Supported Infrastructure Types

- **Domains**: DNS domain management with provider tracking
- **Networks**: Public/private subnets with CIDR validation
- **IP Addresses**: Public, private, and egress IP management
- **DNS Servers**: DNS infrastructure tracking
- **Security Scanners**: Network and vulnerability scanners
- **Infrastructure Services**: DHCP, proxy, VPN, SIEM, antivirus, firewalls

### Environment Management

- **Multi-environment support**: Production, staging, development
- **Access control**: Environment-specific permissions
- **Tagging system**: Flexible resource tagging
- **Audit trails**: Complete change tracking

## Commands

```bash
# Show help
./booli-admin-api -help

# Show version
./booli-admin-api -version

# Initialize complete system (first-time setup)
./booli-admin-api -init

# Initialize complete system (when overwriting existing configuration)
./booli-admin-api -init -force

# Initialize database only
./booli-admin-api -init-database

# Initialize Keycloak only
./booli-admin-api -init-keycloak

# Validate configuration
./booli-admin-api -validate-only

# Use custom configuration file
./booli-admin-api -config /path/to/config.yaml
```

### When is `-force` Required?

The `-force` flag behavior depends on which initialization command you're using:

**For full system initialization (`-init`):**
- **Not required** for first-time setup (any environment)
- **Required only** when existing databases or Keycloak configuration would be overwritten

**For individual commands (`-init-database`, `-init-keycloak`):**
- **Required** for non-development environments (`production`, `test`)
- **Required** when overwriting existing configurations

**Never required for:**
- Normal server startup
- Configuration validation (`-validate-only`)
- First-time full system setup (`-init`)

## Deployment

### Production Deployment

1. **Configure environment variables**
2. **Initialize system**: `./booli-admin-api -init` (first-time setup)
3. **Start with process manager**: systemd, supervisor, or container orchestrator
4. **Configure reverse proxy**: nginx, traefik, or API gateway
5. **Set up monitoring**: health checks, metrics, logging

### Docker Production

```bash
# Build production image
docker build -t booli-admin-api:latest .

# Run with environment variables
docker run -d \
  --name booli-admin-api \
  -p 8081:8081 \
  -e BOOLI_ENVIRONMENT=production \
  -e BOOLI_DATABASE_HOST=your-db-host \
  -e BOOLI_KEYCLOAK_URL=https://your-keycloak \
  booli-admin-api:latest
```

### Kubernetes

Example deployment manifests are available in the `k8s/` directory.

## Security

- **Defaults to production mode** (secure-by-default)
- **Smart `-force` flag** behavior prevents accidental overwrites
- **JWT-based authentication** with proper token validation
- **Role-based access control** with granular permissions
- **Row-level security** for multi-tenant isolation
- **Input validation and sanitization** on all endpoints
- **Advanced audit logging** for compliance and security monitoring
- **No sensitive data exposure** in error messages
- **Secure random generation** for state parameters

### Configuration Security

- **Permission validation**: Prevents client tenants from gaining system/tenant permissions
- **Tenant setting validation**: Validates limits and feature flags
- **SSO configuration validation**: Ensures proper OIDC/SAML configuration
- **Credential protection**: Automatic redaction of sensitive data in logs
- **Change tracking**: Comprehensive audit trail for all configuration changes
- **Type safety**: Proper JSON schema validation for all configurations

## Monitoring and Observability

- **Health endpoints**: `/health` and `/health/keycloak`
- **Structured logging**: JSON-formatted logs with correlation IDs
- **Metrics**: Application and system metrics
- **Audit trails**: Complete activity logging
- **Error tracking**: Comprehensive error handling and reporting

## Releases

This project uses **Calendar Versioning (CalVer)** with the format `YYYY.0M.00MICRO`:

- `2024.08.01` - First August 2024 release
- `2024.08.02` - August hotfix
- `2024.09.01` - September feature release

### Download

Download the latest release from [GitHub Releases](https://github.com/booli/booli-auth-keycloak/releases).

### Docker Images

```bash
# Pull specific version
docker pull ghcr.io/booli/booli-admin-api:2024.08.01

# Pull latest
docker pull ghcr.io/booli/booli-admin-api:latest
```

### Verification

All release artifacts are signed with [Cosign](https://docs.sigstore.dev/cosign/overview/):

```bash
# Verify checksums
cosign verify-blob \
  --certificate checksums.txt.cert \
  --signature checksums.txt.sig \
  checksums.txt

# Verify container images
cosign verify ghcr.io/booli/booli-admin-api:2024.08.01
```

### Security

- **Code Scanning**: CodeQL, Gosec, Trivy
- **Vulnerability Checking**: govulncheck
- **SBOM Generation**: Software Bill of Materials included
- **Signed Artifacts**: All releases signed with Cosign
- **Multi-Architecture**: amd64, arm64, arm builds

See [SECURITY.md](SECURITY.md) for security policy and reporting.

## License

CC BY-NC-ND 4.0

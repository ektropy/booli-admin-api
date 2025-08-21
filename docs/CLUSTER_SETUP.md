# Cluster Setup Guide - Adding Tenants and Users

## Prerequisites

Your cluster already has the following deployed:
- Booli Admin API pod
- Valkey (Redis) for caching
- PostgreSQL database
- Keycloak (should be deployed separately or configured)

## Step 1: Access the API

### Option A: Port Forwarding (Recommended for initial setup)

```bash
# Port-forward the API service
kubectl port-forward -n booli-admin-api svc/booli-admin-api 8081:8080

# Port-forward Keycloak (if not externally accessible)
kubectl port-forward -n booli-admin-api svc/booli-keycloak 8083:8080
```

### Option B: Use Ingress/LoadBalancer

If you have an ingress or LoadBalancer configured, use that URL instead.

## Step 2: Get Authentication Token

First, obtain an admin token from Keycloak:

```bash
# Get token from Keycloak master realm
TOKEN=$(curl -s -X POST \
  http://localhost:8083/realms/master/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=admin-cli" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" | jq -r '.access_token')

echo "Token obtained: ${TOKEN:0:50}..."
```

## Step 3: Create a Tenant

### Using the Script (Easiest)

```bash
# Make the script executable
chmod +x scripts/add-tenant-and-users.sh

# Run in interactive mode
./scripts/add-tenant-and-users.sh

# Or use command line arguments
./scripts/add-tenant-and-users.sh tenant "Acme Corp" "acme.com" client
```

### Using curl directly

```bash
# Create a client tenant
curl -X POST http://localhost:8081/api/v1/admin/tenants \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corporation",
    "domain": "acme.com",
    "type": "client",
    "settings": {
      "enable_sso": true,
      "enable_mfa": false,
      "enable_audit": true,
      "max_users": 100,
      "max_roles": 10,
      "max_sso_providers": 5
    }
  }'
```

The response will include the realm name, which you'll need for creating users:

```json
{
  "id": "uuid-here",
  "name": "Acme Corporation",
  "domain": "acme.com",
  "realm": "acme-corp",
  "type": "client",
  ...
}
```

## Step 4: Create Users in the Tenant

### Create an Admin User

```bash
# Replace 'acme-corp' with your actual tenant realm from Step 3
curl -X POST http://localhost:8081/api/v1/admin/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_realm": "acme-corp",
    "email": "admin@acme.com",
    "first_name": "Admin",
    "last_name": "User",
    "username": "acme-admin",
    "password": "SecurePassword123!",
    "temporary_password": true,
    "enabled": true,
    "default_role": "tenant-admin"
  }'
```

### Create Regular Users

```bash
# Create a regular user
curl -X POST http://localhost:8081/api/v1/admin/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_realm": "acme-corp",
    "email": "john.doe@acme.com",
    "first_name": "John",
    "last_name": "Doe",
    "username": "jdoe",
    "password": "TempPassword123!",
    "temporary_password": true,
    "enabled": true,
    "default_role": "tenant-user"
  }'
```

## Step 5: Bulk User Import (Optional)

### Via CSV File

1. Create a CSV file with users:

```csv
email,first_name,last_name,username,role
jane.smith@acme.com,Jane,Smith,jsmith,tenant-user
bob.jones@acme.com,Bob,Jones,bjones,tenant-viewer
alice.brown@acme.com,Alice,Brown,abrown,tenant-admin
```

2. Import the CSV:

```bash
curl -X POST http://localhost:8081/api/v1/users/import-csv \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@users.csv" \
  -F "tenant_realm=acme-corp"
```

### Via Bulk JSON

```bash
curl -X POST http://localhost:8081/api/v1/users/bulk-create \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "users": [
      {
        "tenant_realm": "acme-corp",
        "email": "user1@acme.com",
        "first_name": "User",
        "last_name": "One",
        "username": "user1",
        "enabled": true,
        "default_role": "tenant-user"
      },
      {
        "tenant_realm": "acme-corp",
        "email": "user2@acme.com",
        "first_name": "User",
        "last_name": "Two",
        "username": "user2",
        "enabled": true,
        "default_role": "tenant-user"
      }
    ]
  }'
```

## Available Roles

### Tenant Roles
- `tenant-admin`: Full access to tenant resources
- `tenant-user`: Standard user access to tenant resources
- `tenant-viewer`: Read-only access to tenant resources

### MSP Roles (for MSP tenants)
- `msp-admin`: Full access to all tenant realms and MSP operations
- `msp-power`: Write access to tenant realms, limited MSP operations
- `msp-viewer`: Read-only access to tenant realms and MSP information

## Verification

### List All Tenants

```bash
curl -X GET http://localhost:8081/api/v1/admin/tenants \
  -H "Authorization: Bearer $TOKEN"
```

### List Users in a Tenant

```bash
curl -X GET "http://localhost:8081/api/v1/admin/users?tenant_realm=acme-corp" \
  -H "Authorization: Bearer $TOKEN"
```

### Test User Login

Users can now authenticate using their credentials:

```bash
# Get token for the created user
USER_TOKEN=$(curl -s -X POST \
  http://localhost:8083/realms/acme-corp/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=your-client-id" \
  -d "username=jdoe" \
  -d "password=TempPassword123!" \
  -d "grant_type=password" | jq -r '.access_token')
```

## Production Considerations

1. **Secure Passwords**: Use strong, unique passwords for production
2. **TLS/HTTPS**: Ensure all communication is encrypted
3. **Network Policies**: Implement Kubernetes network policies
4. **RBAC**: Configure proper Kubernetes RBAC
5. **Secrets Management**: Use Kubernetes secrets or external secret managers
6. **Monitoring**: Set up logging and monitoring for audit trails

## Troubleshooting

### Common Issues

1. **401 Unauthorized**: Token expired or invalid
   - Solution: Get a fresh token from Keycloak

2. **409 Conflict**: Tenant or user already exists
   - Solution: Use a different name/domain or delete existing

3. **Connection Refused**: Services not accessible
   - Solution: Check port-forwards or service endpoints

4. **Realm Not Found**: Incorrect tenant realm name
   - Solution: Verify the realm name from tenant creation response

### Debug Commands

```bash
# Check pod status
kubectl get pods -n booli-admin-api

# View pod logs
kubectl logs -n booli-admin-api deployment/booli-admin-api

# Check service endpoints
kubectl get svc -n booli-admin-api

# Test health endpoint
curl http://localhost:8081/health
```

## Next Steps

1. **Configure SSO**: Set up identity providers for the tenant
2. **Set up Infrastructure**: Add network ranges, IPs, and domains
3. **Configure Audit Logging**: Enable and configure audit trails
4. **Set up Monitoring**: Configure alerts and dashboards
5. **Implement Backup Strategy**: Regular backups of Keycloak and database
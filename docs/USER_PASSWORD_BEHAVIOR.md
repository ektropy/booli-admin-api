# User Password Behavior

## Overview

The system handles user passwords differently depending on how users are created:

## Password Handling Methods

### 1. Direct API Call (JSON)

When creating a user via the API without a password:

```json
{
  "tenant_realm": "acme-corp",
  "email": "user@example.com",
  "username": "jdoe",
  // No password field
}
```

**Result**: User is created in Keycloak **without credentials**
- ❌ User cannot log in immediately
- ⚠️ Requires admin intervention to set password
- 📧 Could trigger password reset email (if configured)

### 2. CSV Import

When importing users via CSV without passwords:

```csv
email,first_name,last_name,username
user@example.com,John,Doe,jdoe
```

**Result**: System **automatically generates** a secure password
- ✅ 12-character cryptographically secure password
- ✅ Mix of letters, numbers, special characters
- ✅ User can log in immediately
- ⚠️ Password must be communicated to user securely

### 3. Using the Script

The updated script handles this intelligently:

```bash
# Interactive mode - press Enter when prompted for password
# Script will auto-generate and display it

# Command line mode with "auto" keyword
./scripts/add-tenant-and-users.sh user realm email first last username auto role
```

## Password Generation Algorithm

When auto-generated (CSV import or script):
- **Length**: 12 characters
- **Character set**: `a-zA-Z0-9!@#$%^&*`
- **Method**: Cryptographically secure random generation
- **Example**: `K9x@mP3&wL7n`

## Best Practices

### For Production

1. **Option A: Generate and Communicate**
   ```bash
   # Let system generate password
   # Securely communicate to user via separate channel
   # Force password change on first login
   ```

2. **Option B: User Self-Service**
   ```bash
   # Create user without password
   # Send password reset email
   # User sets their own password
   ```

3. **Option C: SSO Integration**
   ```bash
   # Create user without password
   # Configure SSO provider
   # User authenticates via SSO
   ```

### Security Considerations

#### DO:
- ✅ Use `temporary_password: true` to force change on first login
- ✅ Communicate passwords via secure channel (not email)
- ✅ Use password managers for generated passwords
- ✅ Implement password complexity requirements
- ✅ Enable MFA for sensitive accounts

#### DON'T:
- ❌ Create users without any authentication method
- ❌ Use predictable passwords
- ❌ Send passwords in plain text emails
- ❌ Store passwords in logs or files

## API Examples

### With Password (Recommended)

```bash
curl -X POST http://localhost:8081/api/v1/admin/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_realm": "acme-corp",
    "email": "user@example.com",
    "username": "jdoe",
    "password": "SecurePass123!",
    "temporary_password": true,
    "enabled": true
  }'
```

### Without Password (Requires Follow-up)

```bash
curl -X POST http://localhost:8081/api/v1/admin/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_realm": "acme-corp",
    "email": "user@example.com",
    "username": "jdoe",
    "enabled": false
  }'

# Then set password later
curl -X POST http://localhost:8081/api/v1/admin/users/{user-id}/reset-password \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "NewSecurePass123!",
    "temporary": true
  }'
```

## Keycloak Behavior

### User Created Without Password

In Keycloak, a user without credentials:
1. Exists in the realm
2. Can be assigned roles and groups
3. Cannot authenticate
4. Shows "No credentials" in admin console
5. Can receive password reset emails

### Password Requirements

Default Keycloak password policy:
- Minimum 8 characters
- No username in password
- No common passwords
- Configurable per realm

## Recommendations

### For Different Scenarios

| Scenario | Recommendation |
|----------|---------------|
| Admin creating users | Auto-generate, communicate securely |
| User self-registration | Email verification + user sets password |
| Bulk import | Generate passwords, provide secure CSV |
| SSO environments | No password, rely on IdP |
| Temporary accounts | Strong generated password, short expiry |

### Implementation TODO

Consider implementing these features:
1. **Email invitation flow** - Send setup link instead of password
2. **Password policy enforcement** - Validate before sending to Keycloak
3. **Secure password delivery** - Encrypted email or secure portal
4. **Audit logging** - Track password changes and resets
5. **Password expiry** - Automatic rotation policies

## Troubleshooting

### User Can't Login

1. Check if user has credentials:
   ```bash
   # Via Keycloak Admin Console
   # Navigate to Users -> {username} -> Credentials tab
   ```

2. Reset password if needed:
   ```bash
   # Via API
   curl -X POST ".../users/{user-id}/reset-password"
   ```

3. Verify user is enabled:
   ```bash
   # Check enabled status
   curl -X GET ".../users/{user-id}"
   ```

### Generated Password Not Working

- Check for special characters that need escaping in shell
- Verify password meets realm's password policy
- Ensure no whitespace in password
- Check if temporary password expired
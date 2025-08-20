# Identity Provider API Tests

This collection contains comprehensive Bruno tests for the Identity Provider API endpoints.

## Overview

The Identity Provider API allows you to manage federated authentication providers for tenant realms. It supports four provider types:

- **OIDC**: OpenID Connect providers
- **OAuth2**: OAuth 2.0 providers  
- **SAML**: SAML 2.0 providers
- **Microsoft**: Microsoft Azure AD providers

## Test Files

1. **create-oidc-provider.bru** - Creates an OIDC identity provider
2. **create-oauth2-provider.bru** - Creates an OAuth2 identity provider
3. **create-saml-provider.bru** - Creates a SAML identity provider
4. **create-microsoft-provider.bru** - Creates a Microsoft identity provider
5. **list-providers.bru** - Lists all identity providers
6. **get-provider.bru** - Gets a specific identity provider
7. **update-provider.bru** - Updates an identity provider
8. **error-invalid-type.bru** - Tests error handling for invalid provider types
9. **error-duplicate-provider.bru** - Tests error handling for duplicate provider aliases
10. **delete-providers-cleanup.bru** - Cleans up test providers

## Prerequisites

Before running these tests, ensure you have:

1. A running Booli Admin API server
2. Valid authentication tokens (set `accessToken` environment variable)
3. Properly configured environment with `baseUrl`

## Environment Variables

The tests use the following environment variables:

- `baseUrl` - Base URL of the API (e.g., `http://localhost:8749`)
- `accessToken` - Bearer token for authentication
- Various provider alias variables (automatically set during test execution)

## Test Execution Order

The tests are designed to run in sequence (seq 1-10). They create test providers, perform operations, and clean up afterward.

## Key Features Tested

### Provider Types
- **OIDC**: Tests issuer URL, client credentials, JWKS URL, and scope configuration
- **OAuth2**: Tests authorization URL, token URL, userinfo URL, and scope configuration
- **SAML**: Tests SSO service URL, entity ID, and signing certificate configuration
- **Microsoft**: Tests Azure tenant ID, authority URL, and Microsoft-specific configuration

### Security Features
- Client secret masking (automatically masked as "**********" in responses)
- Proper authentication and authorization checks
- Input validation and error handling

### CRUD Operations
- **Create**: Test provider creation with various configurations
- **Read**: Test individual provider retrieval and listing
- **Update**: Test provider configuration updates
- **Delete**: Test provider deletion

### Error Handling
- Invalid provider types (400 Bad Request)
- Duplicate provider aliases (409 Conflict)
- Authentication failures (401 Unauthorized)
- Provider not found (404 Not Found)

## Expected Response Formats

### Success Responses
- **201 Created**: For provider creation
- **200 OK**: For provider retrieval and updates
- **204 No Content**: For provider deletion

### Error Responses
All error responses follow the standard format:
```json
{
  "error": "error_code",
  "message": "Human readable error message"
}
```

## Attribute Mappings

The tests include examples of attribute mappings for:
- Email attribute mapping
- Custom claim mapping
- SAML attribute mapping with namespaces
- Different sync modes (INHERIT, FORCE, LEGACY)

## Notes

- The tests automatically generate unique provider aliases using timestamps
- Client secrets are never returned in plain text for security
- Tests include cleanup to avoid polluting the test environment
- All provider types are tested with realistic configuration examples
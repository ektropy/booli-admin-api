#!/bin/bash

# Script to test the new tenant-scoped user management endpoints
# Usage: ./test_tenant_users.sh <base_url> <auth_token>

BASE_URL=${1:-"http://localhost:8080"}
AUTH_TOKEN=${2:-""}

if [ -z "$AUTH_TOKEN" ]; then
    echo "Usage: $0 <base_url> <auth_token>"
    echo "Example: $0 http://localhost:8080 eyJhbGciOiJSUzI1NiIsInR5cC..."
    exit 1
fi

HEADERS=(
    -H "Authorization: Bearer $AUTH_TOKEN"
    -H "X-Auth-Provider: keycloak"
    -H "Content-Type: application/json"
)

echo "Testing tenant-scoped user management endpoints..."
echo "================================================="

# Test 1: List tenants to find a tenant ID
echo "1. Listing tenants..."
TENANT_RESPONSE=$(curl -s "${HEADERS[@]}" "$BASE_URL/api/tenants/v1")
echo "Response: $TENANT_RESPONSE"

# Extract first tenant ID (assuming JSON format)
TENANT_ID=$(echo "$TENANT_RESPONSE" | grep -o '"realm":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -z "$TENANT_ID" ]; then
    echo "No tenant found. Creating a test tenant first..."
    # Create a test tenant
    TEST_TENANT=$(curl -s "${HEADERS[@]}" -X POST "$BASE_URL/api/tenants/v1" -d '{
        "name": "test-tenant",
        "domain": "test.example.com",
        "type": "client"
    }')
    echo "Created tenant: $TEST_TENANT"
    TENANT_ID=$(echo "$TEST_TENANT" | grep -o '"realm":"[^"]*"' | cut -d'"' -f4)
fi

if [ -z "$TENANT_ID" ]; then
    echo "Error: Could not get or create tenant ID"
    exit 1
fi

echo "Using tenant ID: $TENANT_ID"
echo ""

# Test 2: List users in tenant (should be empty initially)
echo "2. Listing users in tenant $TENANT_ID..."
curl -s "${HEADERS[@]}" "$BASE_URL/api/tenants/v1/$TENANT_ID/users" | jq . || echo "Response not JSON"
echo ""

# Test 3: Create a user in the tenant
echo "3. Creating user in tenant $TENANT_ID..."
USER_RESPONSE=$(curl -s "${HEADERS[@]}" -X POST "$BASE_URL/api/tenants/v1/$TENANT_ID/users" -d '{
    "username": "testuser123",
    "email": "testuser123@example.com", 
    "firstName": "Test",
    "lastName": "User",
    "enabled": true
}')
echo "User creation response: $USER_RESPONSE"

# Extract user ID
USER_ID=$(echo "$USER_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "User ID: $USER_ID"
echo ""

if [ -n "$USER_ID" ]; then
    # Test 4: Get the created user
    echo "4. Getting user $USER_ID from tenant $TENANT_ID..."
    curl -s "${HEADERS[@]}" "$BASE_URL/api/tenants/v1/$TENANT_ID/users/$USER_ID" | jq . || echo "Response not JSON"
    echo ""

    # Test 5: Update the user
    echo "5. Updating user $USER_ID in tenant $TENANT_ID..."
    curl -s "${HEADERS[@]}" -X PUT "$BASE_URL/api/tenants/v1/$TENANT_ID/users/$USER_ID" -d '{
        "firstName": "Updated",
        "lastName": "TestUser"
    }' | jq . || echo "Response not JSON"
    echo ""

    # Test 6: List users again (should show our created user)
    echo "6. Listing users in tenant $TENANT_ID (should show created user)..."
    curl -s "${HEADERS[@]}" "$BASE_URL/api/tenants/v1/$TENANT_ID/users" | jq . || echo "Response not JSON"
    echo ""

    # Test 7: Delete the user
    echo "7. Deleting user $USER_ID from tenant $TENANT_ID..."
    curl -s "${HEADERS[@]}" -X DELETE "$BASE_URL/api/tenants/v1/$TENANT_ID/users/$USER_ID"
    echo ""
    echo "Delete completed."
fi

echo ""
echo "Tenant-scoped user management test completed!"
echo "============================================="
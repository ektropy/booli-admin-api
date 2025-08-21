#!/bin/bash

# Booli Admin API - Add Tenant and Users Script
# This script helps you add tenants and users to your Kubernetes cluster deployment

set -e

# Configuration - Update these values for your cluster
API_URL="${BOOLI_API_URL:-http://localhost:8081}"
KEYCLOAK_URL="${BOOLI_KEYCLOAK_URL:-http://localhost:8083}"
KEYCLOAK_ADMIN="${BOOLI_KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${BOOLI_KEYCLOAK_ADMIN_PASSWORD:-admin}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to get access token from Keycloak
get_access_token() {
    print_info "Getting access token from Keycloak..."
    
    TOKEN_RESPONSE=$(curl -s -X POST \
        "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=admin-cli" \
        -d "username=${KEYCLOAK_ADMIN}" \
        -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
        -d "grant_type=password")
    
    ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token')
    
    if [ "$ACCESS_TOKEN" == "null" ] || [ -z "$ACCESS_TOKEN" ]; then
        print_error "Failed to get access token"
        echo "Response: $TOKEN_RESPONSE"
        exit 1
    fi
    
    print_info "Successfully obtained access token"
    echo "$ACCESS_TOKEN"
}

# Function to create a tenant
create_tenant() {
    local tenant_name="$1"
    local tenant_domain="$2"
    local tenant_type="${3:-client}"
    
    print_info "Creating tenant: $tenant_name"
    
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
        "${API_URL}/api/v1/admin/tenants" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        -H "Content-Type: application/json" \
        -d @- <<EOF
{
    "name": "${tenant_name}",
    "domain": "${tenant_domain}",
    "type": "${tenant_type}",
    "settings": {
        "enable_sso": true,
        "enable_mfa": false,
        "enable_audit": true,
        "max_users": 100,
        "max_roles": 10,
        "max_sso_providers": 5
    }
}
EOF
    )
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    if [ "$HTTP_CODE" -eq 201 ]; then
        TENANT_REALM=$(echo "$BODY" | jq -r '.realm')
        print_info "Tenant created successfully with realm: $TENANT_REALM"
        echo "$TENANT_REALM"
    else
        print_error "Failed to create tenant (HTTP $HTTP_CODE)"
        echo "Response: $BODY"
        exit 1
    fi
}

# Function to generate random password
generate_password() {
    # Generate a secure random password
    openssl rand -base64 12 | tr -d "=+/" | cut -c1-12
}

# Function to create a user
create_user() {
    local tenant_realm="$1"
    local email="$2"
    local first_name="$3"
    local last_name="$4"
    local username="$5"
    local password="$6"
    local role="${7:-tenant-user}"
    local send_invite="${8:-false}"
    
    # Build JSON based on whether we're sending invite or setting password
    if [ "$send_invite" == "true" ]; then
        print_info "Creating user with email invitation: $username in realm: $tenant_realm"
        
        JSON_BODY=$(cat <<EOF
{
    "tenant_realm": "${tenant_realm}",
    "email": "${email}",
    "first_name": "${first_name}",
    "last_name": "${last_name}",
    "username": "${username}",
    "enabled": false,
    "default_role": "${role}",
    "send_invite": true
}
EOF
)
    else
        # If no password provided, generate one
        if [ -z "$password" ] || [ "$password" == "auto" ]; then
            password=$(generate_password)
            print_warning "Generated password for $username: $password"
            print_warning "Please save this password securely and share it with the user!"
        fi
        
        print_info "Creating user with password: $username in realm: $tenant_realm"
        
        JSON_BODY=$(cat <<EOF
{
    "tenant_realm": "${tenant_realm}",
    "email": "${email}",
    "first_name": "${first_name}",
    "last_name": "${last_name}",
    "username": "${username}",
    "password": "${password}",
    "temporary_password": true,
    "enabled": true,
    "default_role": "${role}",
    "send_invite": false
}
EOF
)
    fi
    
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
        "${API_URL}/api/v1/admin/users" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$JSON_BODY")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    if [ "$HTTP_CODE" -eq 201 ]; then
        USER_ID=$(echo "$BODY" | jq -r '.id')
        print_info "User created successfully with ID: $USER_ID"
        echo "$USER_ID"
    else
        print_error "Failed to create user (HTTP $HTTP_CODE)"
        echo "Response: $BODY"
        return 1
    fi
}

# Function to check if running in Kubernetes
check_kubernetes() {
    if kubectl get pods -n booli-admin-api &>/dev/null; then
        print_info "Kubernetes cluster detected"
        
        # Port-forward to the API if not already accessible
        if ! curl -s "${API_URL}/health" &>/dev/null; then
            print_warning "API not accessible at ${API_URL}, setting up port-forward..."
            kubectl port-forward -n booli-admin-api svc/booli-admin-api 8081:8080 &
            PF_PID=$!
            sleep 3
            
            # Also port-forward to Keycloak if needed
            if ! curl -s "${KEYCLOAK_URL}/health" &>/dev/null; then
                print_warning "Keycloak not accessible, setting up port-forward..."
                kubectl port-forward -n booli-admin-api svc/booli-keycloak 8083:8080 &
                KF_PID=$!
                sleep 3
            fi
        fi
    fi
}

# Main execution
main() {
    echo "================================================"
    echo "    Booli Admin API - Add Tenant and Users     "
    echo "================================================"
    echo ""
    
    # Check if we're running against Kubernetes
    check_kubernetes
    
    # Get access token
    ACCESS_TOKEN=$(get_access_token)
    
    # Interactive mode or use command line arguments
    if [ $# -eq 0 ]; then
        # Interactive mode
        read -p "Enter tenant name: " TENANT_NAME
        read -p "Enter tenant domain (e.g., acme.com): " TENANT_DOMAIN
        read -p "Enter tenant type (client/msp) [client]: " TENANT_TYPE
        TENANT_TYPE=${TENANT_TYPE:-client}
        
        # Create tenant
        TENANT_REALM=$(create_tenant "$TENANT_NAME" "$TENANT_DOMAIN" "$TENANT_TYPE")
        
        # Ask about users
        read -p "Do you want to add users to this tenant? (y/n): " ADD_USERS
        
        if [[ "$ADD_USERS" =~ ^[Yy]$ ]]; then
            while true; do
                echo ""
                read -p "Enter user email: " USER_EMAIL
                read -p "Enter first name: " FIRST_NAME
                read -p "Enter last name: " LAST_NAME
                read -p "Enter username: " USERNAME
                read -p "Send invitation email instead of setting password? (y/n) [n]: " SEND_INVITE
                
                if [[ "$SEND_INVITE" =~ ^[Yy]$ ]]; then
                    PASSWORD=""
                    INVITE_FLAG="true"
                    print_info "User will receive an email invitation to set up their account"
                else
                    INVITE_FLAG="false"
                    read -p "Enter temporary password (press Enter to auto-generate): " PASSWORD
                    if [ -z "$PASSWORD" ]; then
                        PASSWORD=$(generate_password)
                        print_warning "Generated password: $PASSWORD"
                        print_warning "Save this password! It won't be shown again."
                    fi
                fi
                
                read -p "Enter role (tenant-admin/tenant-user/tenant-viewer) [tenant-user]: " ROLE
                ROLE=${ROLE:-tenant-user}
                
                create_user "$TENANT_REALM" "$USER_EMAIL" "$FIRST_NAME" "$LAST_NAME" "$USERNAME" "$PASSWORD" "$ROLE" "$INVITE_FLAG"
                
                read -p "Add another user? (y/n): " CONTINUE
                if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
                    break
                fi
            done
        fi
    else
        # Command line mode
        case "$1" in
            tenant)
                shift
                create_tenant "$@"
                ;;
            user)
                shift
                create_user "$@"
                ;;
            *)
                echo "Usage:"
                echo "  Interactive mode: $0"
                echo "  Create tenant: $0 tenant <name> <domain> [type]"
                echo "  Create user: $0 user <realm> <email> <first> <last> <username> [password] [role]"
                exit 1
                ;;
        esac
    fi
    
    # Cleanup port-forwards if we created them
    if [ ! -z "$PF_PID" ]; then
        kill $PF_PID 2>/dev/null || true
    fi
    if [ ! -z "$KF_PID" ]; then
        kill $KF_PID 2>/dev/null || true
    fi
    
    print_info "Operation completed successfully!"
}

# Check dependencies
command -v jq >/dev/null 2>&1 || { print_error "jq is required but not installed. Please install it."; exit 1; }
command -v curl >/dev/null 2>&1 || { print_error "curl is required but not installed. Please install it."; exit 1; }

# Run main function
main "$@"
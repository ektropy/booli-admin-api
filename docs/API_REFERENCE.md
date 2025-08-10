# Booli Admin API - Comprehensive API Reference

## 🚀 **Overview**

The Booli Admin API provides comprehensive user and tenant management capabilities through a Keycloak-first architecture. All operations are automatically realm-scoped based on the user's authentication token.

**Base URL**: `https://api.booli.com/v1`  
**Authentication**: OAuth2/OIDC Bearer tokens  
**Content-Type**: `application/json` (except file uploads)

---

## 🔐 **Authentication**

### **Bearer Token Authentication**
```bash
Authorization: Bearer <your-jwt-token>
```

### **Token Structure**
```json
{
  "iss": "https://keycloak.booli.com/realms/customer-a",
  "sub": "123e4567-e89b-12d3-a456-426614174000", 
  "realm": "customer-a",
  "roles": ["tenant-admin", "tenant-user"],
  "exp": 1640995200
}
```

**Key Points:**
- Realm is automatically extracted from token `iss` field
- All operations are scoped to the token's realm
- Cross-realm access available for MSP users

---

## 👥 **User Management**

### **List Users**
```http
GET /api/v1/users?page=1&page_size=20&search=john&role=admin
```

**Query Parameters:**
- `page` (int): Page number (default: 1)
- `page_size` (int): Items per page (1-100, default: 20)  
- `search` (string): Search by email, username, first/last name
- `role` (string): Filter by role
- `enabled` (boolean): Filter by enabled status

**Response:**
```json
{
  "users": [
    {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "username": "john.doe",
      "email": "john.doe@customer-a.com",
      "first_name": "John",
      "last_name": "Doe", 
      "enabled": true,
      "roles": ["tenant-admin", "tenant-user"]
    }
  ],
  "total": 150,
  "page": 1,
  "page_size": 20,
  "total_pages": 8
}
```

### **Create User**
```http
POST /api/v1/users
Content-Type: application/json

{
  "username": "jane.smith",
  "email": "jane.smith@customer-a.com",
  "first_name": "Jane",
  "last_name": "Smith",
  "password": "SecurePassword123!",
  "temporary_password": false,
  "enabled": true,
  "default_role": "tenant-user",
  "send_invite": true
}
```

**Response:**
```json
{
  "id": "456e7890-e12b-34d5-a678-901234567890",
  "username": "jane.smith", 
  "email": "jane.smith@customer-a.com",
  "first_name": "Jane",
  "last_name": "Smith",
  "enabled": true,
  "roles": ["tenant-user"]
}
```

### **Get User**
```http
GET /api/v1/users/{user_id}
```

**Response:**
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "username": "john.doe",
  "email": "john.doe@customer-a.com", 
  "first_name": "John",
  "last_name": "Doe",
  "enabled": true,
  "roles": ["tenant-admin", "tenant-user"]
}
```

### **Update User**
```http
PUT /api/v1/users/{user_id}
Content-Type: application/json

{
  "first_name": "John",
  "last_name": "Doe-Smith",
  "enabled": true
}
```

**Response:**
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "username": "john.doe",
  "email": "john.doe@customer-a.com",
  "first_name": "John", 
  "last_name": "Doe-Smith",
  "enabled": true,
  "roles": ["tenant-admin", "tenant-user"]
}
```

### **Delete User**
```http
DELETE /api/v1/users/{user_id}
```

**Response:** `204 No Content`

---

## 📊 **Bulk Operations**

### **Bulk Create Users (JSON)**
```http
POST /api/v1/users/bulk-create
Content-Type: application/json

{
  "users": [
    {
      "username": "user1",
      "email": "user1@customer-a.com",
      "first_name": "User",
      "last_name": "One", 
      "password": "SecurePass123!",
      "enabled": true,
      "default_role": "tenant-user"
    },
    {
      "username": "user2", 
      "email": "user2@customer-a.com",
      "first_name": "User",
      "last_name": "Two",
      "password": "SecurePass456!", 
      "enabled": true,
      "default_role": "tenant-admin"
    }
  ]
}
```

**Response:**
```json
{
  "total_processed": 2,
  "success_count": 2,
  "failure_count": 0,
  "successful": [
    {
      "id": "user1-id",
      "username": "user1",
      "email": "user1@customer-a.com",
      "first_name": "User",
      "last_name": "One",
      "enabled": true,
      "roles": ["tenant-user"]
    },
    {
      "id": "user2-id",
      "username": "user2", 
      "email": "user2@customer-a.com",
      "first_name": "User",
      "last_name": "Two",
      "enabled": true,
      "roles": ["tenant-admin"] 
    }
  ],
  "failed": []
}
```

### **Import Users from CSV**
```http
POST /api/v1/users/import-csv
Content-Type: multipart/form-data

--boundary
Content-Disposition: form-data; name="file"; filename="users.csv"
Content-Type: text/csv

email,first_name,last_name,username,password,role,enabled
user1@customer-a.com,User,One,user1,SecurePass123!,tenant-user,true  
user2@customer-a.com,User,Two,user2,SecurePass456!,tenant-admin,true
--boundary--
```

**CSV Format Requirements:**
- **Required columns**: `email`, `first_name`, `last_name`
- **Optional columns**: `username`, `password`, `role`, `enabled`
- **File size limit**: 10MB
- **User limit**: 1000 users per file

**Response:**
```json
{
  "total_processed": 2,
  "success_count": 2, 
  "error_count": 0,
  "successful_users": [
    {
      "id": "user1-id",
      "username": "user1",
      "email": "user1@customer-a.com",
      "first_name": "User",
      "last_name": "One",
      "enabled": true,
      "roles": ["tenant-user"]
    }
  ],
  "failed_users": [],
  "parse_errors": []
}
```

**Error Response Example:**
```json
{
  "total_processed": 3,
  "success_count": 2,
  "error_count": 1,
  "successful_users": [...],
  "failed_users": [
    {
      "row": 3,
      "email": "invalid-email",
      "error": "User with email invalid-email already exists"
    }
  ],
  "parse_errors": []
}
```

---

## 🏢 **Tenant Management**

### **List Tenants**
```http
GET /api/v1/tenants?page=1&page_size=20
```

**Response:**
```json
{
  "tenants": [
    {
      "id": "tenant-123",
      "name": "Customer A Corp",
      "domain": "customer-a.com",
      "realm_name": "customer-a",
      "enabled": true,
      "user_count": 150,
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 25,
  "page": 1, 
  "page_size": 20,
  "total_pages": 2
}
```

### **Create Tenant**
```http
POST /api/v1/tenants
Content-Type: application/json

{
  "name": "Customer B Inc",
  "domain": "customer-b.com", 
  "type": "customer",
  "enabled": true
}
```

**Response:**
```json
{
  "id": "tenant-456",
  "name": "Customer B Inc",
  "domain": "customer-b.com",
  "realm_name": "customer-b", 
  "type": "customer",
  "enabled": true,
  "user_count": 0,
  "created_at": "2024-01-15T11:45:00Z"
}
```

---

## 🔍 **Cross-Realm Operations (MSP Users)**

### **Get Accessible Realms**
```http
GET /api/v1/auth/realm-summary
```

**Response (MSP Admin):**
```json
{
  "user_id": "msp-user-123",
  "source_realm": "msp-realm",
  "accessible_realms": [
    {
      "realm_name": "customer-a",
      "display_name": "Customer A Corp",
      "access_level": "admin", 
      "roles": ["tenant-admin"],
      "can_access": true
    },
    {
      "realm_name": "customer-b",
      "display_name": "Customer B Inc", 
      "access_level": "admin",
      "roles": ["tenant-admin"],
      "can_access": true
    }
  ],
  "total_realms": 15
}
```

**Response (Regular User):**
```json
{
  "user_id": "user-456", 
  "source_realm": "customer-a",
  "accessible_realms": [
    {
      "realm_name": "customer-a",
      "display_name": "Customer A Corp",
      "access_level": "viewer",
      "roles": ["tenant-user"], 
      "can_access": true
    }
  ],
  "total_realms": 15
}
```

---

## 🔒 **Authorization & Permissions**

### **Role Hierarchy**

**MSP Roles** (cross-realm access):
- `msp-admin`: Full admin access to all customer realms
- `msp-power`: Limited admin access to customer realms
- `msp-viewer`: Read-only access to customer realms

**Tenant Roles** (realm-specific):
- `tenant-admin`: Full admin access within their realm
- `tenant-user`: Standard user access within their realm  
- `tenant-viewer`: Read-only access within their realm

### **Permission Matrix**

| **Operation** | **MSP Admin** | **MSP Power** | **MSP Viewer** | **Tenant Admin** | **Tenant User** | **Tenant Viewer** |
|---------------|---------------|---------------|----------------|------------------|-----------------|-------------------|
| **List Users** | ✅ All Realms | ✅ All Realms | ✅ All Realms | ✅ Own Realm | ✅ Own Realm | ✅ Own Realm |
| **Create Users** | ✅ All Realms | ✅ All Realms | ❌ | ✅ Own Realm | ❌ | ❌ |
| **Update Users** | ✅ All Realms | ✅ All Realms | ❌ | ✅ Own Realm | ❌ | ❌ |
| **Delete Users** | ✅ All Realms | ❌ | ❌ | ✅ Own Realm | ❌ | ❌ |
| **Bulk Import** | ✅ All Realms | ✅ All Realms | ❌ | ✅ Own Realm | ❌ | ❌ |
| **Manage Tenants** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

---

## 📈 **Rate Limits**

| **Endpoint** | **Rate Limit** | **Burst** | **Window** |
|--------------|----------------|-----------|------------|
| **Standard APIs** | 100 req/min | 10 | 1 minute |
| **Bulk Create** | 10 req/min | 2 | 1 minute |
| **CSV Import** | 5 req/min | 1 | 1 minute |
| **Authentication** | 20 req/min | 5 | 1 minute |

**Rate Limit Headers:**
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995260
```

---

## ⚠️ **Error Responses**

### **Standard Error Format**
```json
{
  "error": "Validation failed",
  "code": "VALIDATION_FAILED",
  "message": "Invalid request body",
  "details": [
    {
      "field": "email",
      "message": "Invalid email format"
    }
  ],
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/v1/users"
}
```

### **Common Error Codes**
- `UNAUTHORIZED` (401): Invalid or missing authentication
- `FORBIDDEN` (403): Insufficient permissions
- `NOT_FOUND` (404): Resource not found
- `VALIDATION_FAILED` (400): Request validation errors
- `CONFLICT` (409): Resource already exists
- `RATE_LIMITED` (429): Rate limit exceeded
- `INTERNAL_ERROR` (500): Server error

---

## 🧪 **Testing Examples**

### **cURL Examples**

**Create User:**
```bash
curl -X POST https://api.booli.com/v1/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test.user",
    "email": "test.user@customer-a.com", 
    "first_name": "Test",
    "last_name": "User",
    "password": "SecurePass123!",
    "enabled": true,
    "default_role": "tenant-user"
  }'
```

**Bulk Import CSV:**
```bash
curl -X POST https://api.booli.com/v1/users/import-csv \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@users.csv"
```

**List Users with Filtering:**
```bash
curl -X GET "https://api.booli.com/v1/users?search=john&role=admin&page=1&page_size=10" \
  -H "Authorization: Bearer $TOKEN"
```

### **JavaScript Examples**

**Create User:**
```javascript
const response = await fetch('https://api.booli.com/v1/users', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    username: 'test.user',
    email: 'test.user@customer-a.com',
    first_name: 'Test', 
    last_name: 'User',
    password: 'SecurePass123!',
    enabled: true,
    default_role: 'tenant-user'
  })
});

const user = await response.json();
console.log('Created user:', user);
```

**Bulk CSV Import:**
```javascript
const formData = new FormData();
formData.append('file', csvFile);

const response = await fetch('https://api.booli.com/v1/users/import-csv', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`
  },
  body: formData
});

const result = await response.json();
console.log(`Imported ${result.success_count} users successfully`);
```

---

## 🔄 **Webhooks & Events**

### **Webhook Events**
- `user.created`
- `user.updated` 
- `user.deleted`
- `bulk_import.completed`
- `tenant.created`

### **Webhook Payload Example**
```json
{
  "event": "user.created",
  "timestamp": "2024-01-15T10:30:00Z", 
  "realm": "customer-a",
  "data": {
    "user": {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "email": "user@customer-a.com",
      "enabled": true
    }
  }
}
```

---

## 📝 **Best Practices**

### **Security**
- Always use HTTPS in production
- Rotate Bearer tokens regularly
- Validate all input data
- Use least-privilege access patterns
- Monitor API usage and set alerts

### **Performance** 
- Use pagination for large datasets
- Implement proper caching strategies
- Batch operations when possible
- Monitor rate limits
- Use compression (gzip) for responses

### **Error Handling**
- Always check HTTP status codes
- Implement exponential backoff for retries
- Log errors with correlation IDs
- Handle network timeouts gracefully
- Provide meaningful error messages to users

---

**Generated by Booli Admin API v1.0**  
**Last Updated: January 15, 2024**
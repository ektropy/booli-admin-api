# User Onboarding Options

## Overview

The system now supports multiple user onboarding methods to accommodate different security requirements, user experiences, and organizational workflows.

## Available Onboarding Methods

### 1. 🔐 Password-Based (Traditional)

**Best for**: Quick setup, testing, small teams

```json
{
  "method": "password",
  "user": {
    "email": "user@example.com",
    "username": "jdoe",
    "password": "SecurePass123!",
    "temporary_password": true
  }
}
```

**Flow**:
1. Admin creates user with password
2. User receives credentials
3. User logs in
4. User changes password (if temporary)

**Pros**:
- ✅ Simple and immediate
- ✅ No email configuration required
- ✅ Works offline

**Cons**:
- ❌ Password must be communicated securely
- ❌ Risk of weak passwords
- ❌ No email verification

---

### 2. 📧 Email Invitation

**Best for**: Enterprise deployments, verified users

```json
{
  "method": "invite_email",
  "user": {
    "email": "user@example.com",
    "username": "jdoe",
    "send_invite": true
  },
  "invite_options": {
    "subject": "Welcome to Booli Platform",
    "expiry_hours": 48,
    "custom_message": "Click the link below to set up your account",
    "required_actions": ["UPDATE_PASSWORD", "VERIFY_EMAIL", "UPDATE_PROFILE"]
  }
}
```

**Flow**:
1. Admin creates user without password
2. System sends invitation email
3. User clicks setup link
4. User sets password and completes profile
5. Account activated

**Pros**:
- ✅ No password sharing needed
- ✅ Email verification built-in
- ✅ Professional onboarding experience
- ✅ Audit trail of invitation

**Cons**:
- ❌ Requires email configuration
- ❌ User needs email access
- ❌ Links can expire

---

### 3. 🔗 Magic Link

**Best for**: Passwordless authentication, mobile users

```json
{
  "method": "magic_link",
  "user": {
    "email": "user@example.com",
    "username": "jdoe"
  },
  "magic_link_options": {
    "expiry_minutes": 15,
    "redirect_url": "/dashboard",
    "single_use": true
  }
}
```

**Flow**:
1. User created without password
2. User requests magic link
3. Link sent to email
4. Click link to authenticate
5. No password required

**Pros**:
- ✅ No passwords to remember
- ✅ Very user-friendly
- ✅ Secure (short-lived tokens)
- ✅ Great for mobile

**Cons**:
- ❌ Requires email every login
- ❌ Links expire quickly
- ❌ Email delays affect UX

---

### 4. 🌐 SSO (Single Sign-On)

**Best for**: Organizations with existing identity providers

```json
{
  "method": "sso",
  "user": {
    "email": "user@company.com",
    "username": "jdoe"
  }
}
```

**Flow**:
1. User created without password
2. User redirected to SSO provider
3. Authenticates with corporate credentials
4. Returns authenticated to app

**Pros**:
- ✅ No new passwords
- ✅ Centralized user management
- ✅ Enhanced security (MFA from IdP)
- ✅ Seamless experience

**Cons**:
- ❌ Requires SSO provider setup
- ❌ Complex configuration
- ❌ Dependency on external service

---

### 5. 📱 Activation Code

**Best for**: Mobile apps, SMS verification, offline scenarios

```json
{
  "method": "activation_code",
  "user": {
    "email": "user@example.com",
    "phone": "+1234567890"
  },
  "activation_options": {
    "code_length": 6,
    "numeric": true,
    "expiry_minutes": 30
  }
}
```

**Flow**:
1. User created (disabled)
2. Code sent via SMS/email
3. User enters code in app
4. Account activated
5. User sets password

**Pros**:
- ✅ Works with SMS
- ✅ Simple for users
- ✅ Good for mobile apps
- ✅ Offline code generation possible

**Cons**:
- ❌ SMS costs
- ❌ Code can be intercepted
- ❌ Limited expiry time

---

### 6. 👨‍💼 Admin Setup

**Best for**: High-security accounts, VIP users

```json
{
  "method": "admin_setup",
  "user": {
    "email": "vip@example.com",
    "username": "vip-user"
  }
}
```

**Flow**:
1. User created (disabled)
2. Admin receives setup task
3. Admin configures account
4. Admin provides credentials securely
5. User logs in

**Pros**:
- ✅ Maximum control
- ✅ Secure credential delivery
- ✅ Custom configuration
- ✅ Personal onboarding

**Cons**:
- ❌ Manual process
- ❌ Doesn't scale
- ❌ Admin bottleneck

---

## Comparison Matrix

| Method | Security | UX | Scalability | Email Required | Password Required | Setup Complexity |
|--------|----------|-----|------------|----------------|-------------------|------------------|
| Password | ⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ | No | Yes | ⭐ |
| Email Invite | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | Yes | User Sets | ⭐⭐ |
| Magic Link | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | Yes | No | ⭐⭐⭐ |
| SSO | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | No | External | ⭐⭐⭐⭐ |
| Activation Code | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | Optional | User Sets | ⭐⭐ |
| Admin Setup | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐ | No | Admin Sets | ⭐ |

## Implementation Examples

### Bulk Onboarding with Mixed Methods

```bash
curl -X POST http://localhost:8081/api/v1/users/bulk-onboard \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "users": [
      {
        "method": "invite_email",
        "user": {"email": "admin@company.com", "role": "admin"}
      },
      {
        "method": "sso",
        "user": {"email": "employee@company.com", "role": "user"}
      },
      {
        "method": "activation_code",
        "user": {"email": "contractor@external.com", "role": "viewer"}
      }
    ]
  }'
```

### Progressive Onboarding

```javascript
// Step 1: Create account
const response = await createUser({
  method: "magic_link",
  user: { email: "user@example.com" }
});

// Step 2: Send magic link
await sendMagicLink(response.user_id);

// Step 3: After authentication, prompt for profile
await updateProfile(userId, profileData);

// Step 4: Optional - Enable MFA
await enableMFA(userId);
```

## Security Considerations

### For Each Method

#### Password-Based
- Enforce strong password policies
- Use temporary passwords
- Implement password rotation
- Add MFA

#### Email Invitation
- Use secure token generation
- Implement rate limiting
- Set appropriate expiry times
- Log all invitations

#### Magic Link
- Very short expiry (5-15 minutes)
- Single-use tokens
- Rate limit requests
- Secure token storage

#### SSO
- Validate IdP certificates
- Implement proper SAML/OIDC
- Handle account linking
- Audit SSO events

#### Activation Code
- Use cryptographically secure generation
- Implement retry limits
- Consider 2-channel verification
- Time-based expiry

#### Admin Setup
- Secure credential delivery channel
- Audit all admin actions
- Implement approval workflow
- Document setup process

## Choosing the Right Method

### Decision Tree

```
Start
  ↓
Do users have corporate email?
  Yes → Do you have SSO? 
    Yes → Use SSO
    No → Use Email Invitation
  No → Is it a mobile app?
    Yes → Use Magic Link or Activation Code
    No → Are users technical?
      Yes → Use Password-Based
      No → Use Admin Setup
```

### Use Case Recommendations

| Use Case | Recommended Method | Alternative |
|----------|-------------------|-------------|
| Enterprise SaaS | SSO | Email Invitation |
| Small Business | Email Invitation | Password-Based |
| Consumer App | Magic Link | Social Login (OAuth) |
| Mobile App | Activation Code | Magic Link |
| High Security | Admin Setup | SSO with MFA |
| Development/Testing | Password-Based | Any |
| Contractors/Temp | Activation Code | Email Invitation |

## API Endpoints

### Create User with Onboarding

```
POST /api/v1/users/onboard
```

### Resend Invitation

```
POST /api/v1/users/{userId}/resend-invite
```

### Verify Activation Code

```
POST /api/v1/users/verify-activation
```

### Complete Magic Link

```
GET /api/v1/auth/magic?token={token}
```

### Check Onboarding Status

```
GET /api/v1/users/{userId}/onboarding-status
```

## Configuration

### Enable Methods in Config

```yaml
onboarding:
  enabled_methods:
    - password
    - invite_email
    - magic_link
    - sso
    - activation_code
    - admin_setup
  
  default_method: invite_email
  
  email:
    provider: smtp
    from: noreply@company.com
    templates_path: /templates/email
  
  magic_link:
    expiry_minutes: 15
    base_url: https://app.company.com
  
  activation:
    delivery: sms  # or email
    code_length: 6
    expiry_minutes: 30
```

## Monitoring and Analytics

### Key Metrics to Track

1. **Onboarding Completion Rate** by method
2. **Time to Activation** per method
3. **Failed Attempts** and reasons
4. **Invitation/Link Expiry Rate**
5. **Password Reset Frequency**
6. **SSO vs Local Authentication Ratio**

### Sample Dashboard Queries

```sql
-- Onboarding success rate by method
SELECT 
  onboarding_method,
  COUNT(*) as total_attempts,
  SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
  ROUND(100.0 * SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) / COUNT(*), 2) as success_rate
FROM user_onboarding_events
WHERE created_at > NOW() - INTERVAL '30 days'
GROUP BY onboarding_method;

-- Average time to activation
SELECT 
  onboarding_method,
  AVG(EXTRACT(EPOCH FROM (activated_at - created_at))/3600) as avg_hours_to_activation
FROM users
WHERE activated_at IS NOT NULL
GROUP BY onboarding_method;
```

## Future Enhancements

1. **Biometric Authentication** - Face ID, Touch ID
2. **WebAuthn/FIDO2** - Hardware security keys
3. **Social Login** - Google, GitHub, LinkedIn
4. **QR Code Onboarding** - Scan to setup
5. **Voice Authentication** - For accessibility
6. **Blockchain Identity** - Decentralized identity
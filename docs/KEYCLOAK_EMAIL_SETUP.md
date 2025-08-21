# Keycloak Email Configuration for Send Invite Feature

## Prerequisites

Before the `send_invite` feature will work, you need to configure Keycloak's email settings.

## Step 1: Configure SMTP in Keycloak

### Via Keycloak Admin Console

1. Login to Keycloak Admin Console:
   ```
   http://localhost:8083 (development)
   https://your-keycloak-domain (production)
   ```

2. Navigate to **Realm Settings** → **Email**

3. Configure SMTP settings:

   #### Gmail Example:
   ```
   Host: smtp.gmail.com
   Port: 587
   From: noreply@yourdomain.com
   From Display Name: Booli Platform
   Enable SSL: OFF
   Enable StartTLS: ON
   Enable Authentication: ON
   Username: your-gmail@gmail.com
   Password: your-app-specific-password
   ```

   #### Office 365 Example:
   ```
   Host: smtp.office365.com
   Port: 587
   From: noreply@yourdomain.com
   From Display Name: Booli Platform
   Enable SSL: OFF
   Enable StartTLS: ON
   Enable Authentication: ON
   Username: your-email@yourdomain.com
   Password: your-password
   ```

   #### SendGrid Example:
   ```
   Host: smtp.sendgrid.net
   Port: 587
   From: noreply@yourdomain.com
   From Display Name: Booli Platform
   Enable SSL: OFF
   Enable StartTLS: ON
   Enable Authentication: ON
   Username: apikey
   Password: your-sendgrid-api-key
   ```

4. Click **Test connection** to verify settings

5. **Save** the configuration

### Via Environment Variables (Docker)

Add these to your `docker-compose.yml`:

```yaml
keycloak:
  environment:
    # ... existing config ...
    KC_SPI_EMAIL_TEMPLATE_PROVIDER: freemarker
    KC_SPI_EMAIL_TEMPLATE_ENABLED: true
    KC_SPI_EMAIL_SENDER_PROVIDER: default
    KC_SPI_EMAIL_SENDER_DEFAULT_HOST: smtp.gmail.com
    KC_SPI_EMAIL_SENDER_DEFAULT_PORT: 587
    KC_SPI_EMAIL_SENDER_DEFAULT_FROM: noreply@yourdomain.com
    KC_SPI_EMAIL_SENDER_DEFAULT_FROM_DISPLAY_NAME: "Booli Platform"
    KC_SPI_EMAIL_SENDER_DEFAULT_STARTTLS: true
    KC_SPI_EMAIL_SENDER_DEFAULT_AUTH: true
    KC_SPI_EMAIL_SENDER_DEFAULT_USER: your-email@gmail.com
    KC_SPI_EMAIL_SENDER_DEFAULT_PASSWORD: your-app-password
```

### Via Kubernetes ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: keycloak-email-config
  namespace: booli-admin-api
data:
  EMAIL_HOST: "smtp.gmail.com"
  EMAIL_PORT: "587"
  EMAIL_FROM: "noreply@yourdomain.com"
  EMAIL_FROM_NAME: "Booli Platform"
  EMAIL_STARTTLS: "true"
  EMAIL_AUTH: "true"
---
apiVersion: v1
kind: Secret
metadata:
  name: keycloak-email-secret
  namespace: booli-admin-api
type: Opaque
data:
  email-username: base64-encoded-username
  email-password: base64-encoded-password
```

## Step 2: Configure Email Templates (Optional)

Keycloak uses FreeMarker templates for emails. To customize them:

1. Create custom theme directory:
   ```bash
   mkdir -p /opt/keycloak/themes/booli-theme/email
   ```

2. Copy default templates:
   ```bash
   cp -r /opt/keycloak/lib/lib/main/org.keycloak.keycloak-themes-*/email/* \
         /opt/keycloak/themes/booli-theme/email/
   ```

3. Edit templates as needed:
   - `executeActions.ftl` - For invitation emails
   - `email-verification.ftl` - For email verification
   - `password-reset.ftl` - For password resets

4. Apply theme to realm:
   - Go to **Realm Settings** → **Themes**
   - Set Email Theme to `booli-theme`

## Step 3: Test Email Sending

### Via API:

```bash
# Get token
TOKEN=$(curl -s -X POST \
  http://localhost:8083/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" | jq -r '.access_token')

# Create user with invitation
curl -X POST http://localhost:8081/api/v1/admin/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_realm": "test-realm",
    "email": "testuser@example.com",
    "first_name": "Test",
    "last_name": "User",
    "username": "testuser",
    "send_invite": true
  }'
```

### Via Script:

```bash
./scripts/add-tenant-and-users.sh
# Choose "y" when asked "Send invitation email instead of setting password?"
```

## Step 4: Verify Email Delivery

1. Check Keycloak logs:
   ```bash
   kubectl logs -n booli-admin-api deployment/keycloak | grep -i email
   ```

2. Check email provider logs/dashboard

3. Check spam folder (first emails often go there)

## Troubleshooting

### Common Issues:

#### 1. "Failed to send email" error

**Cause**: SMTP settings incorrect
**Solution**: 
- Verify SMTP host and port
- Check firewall rules
- Ensure credentials are correct

#### 2. "Connection refused" error

**Cause**: Network connectivity issue
**Solution**:
- Check if SMTP port is open: `telnet smtp.gmail.com 587`
- Verify Kubernetes network policies
- Check egress rules

#### 3. "Authentication failed"

**Cause**: Wrong credentials or security settings
**Solution**:
- For Gmail: Use App-specific password, not regular password
- Enable "Less secure app access" (not recommended for production)
- Use OAuth2 instead of password (more secure)

#### 4. Emails not received

**Cause**: Various
**Check**:
- Spam/Junk folder
- Email filters
- Sender reputation
- SPF/DKIM/DMARC records

### Debug Mode

Enable debug logging for email in Keycloak:

```bash
# Via CLI
/opt/keycloak/bin/kc.sh start --log-level=DEBUG --log="org.keycloak.email:debug"

# Via environment variable
KC_LOG_LEVEL=DEBUG
```

## Email Actions Available

When `send_invite` is true, the following actions are triggered:

1. **UPDATE_PASSWORD** - Forces user to set password
2. **VERIFY_EMAIL** - Validates email ownership
3. **UPDATE_PROFILE** - Complete profile information
4. **CONFIGURE_TOTP** - Set up 2FA (if enabled)

## Production Recommendations

1. **Use dedicated email service**:
   - SendGrid, Mailgun, AWS SES, Postmark
   - Better deliverability and analytics

2. **Configure SPF/DKIM/DMARC**:
   ```
   SPF: v=spf1 include:sendgrid.net ~all
   DKIM: Generated by email provider
   DMARC: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com
   ```

3. **Monitor email metrics**:
   - Delivery rate
   - Open rate
   - Click rate
   - Bounce rate

4. **Implement retry logic**:
   - Queue failed emails
   - Exponential backoff
   - Dead letter queue

5. **Set up email templates**:
   - Brand consistency
   - Multiple languages
   - Mobile-responsive

## API Endpoints

### Send Invitation
```
POST /api/v1/admin/users
{
  "email": "user@example.com",
  "send_invite": true
}
```

### Resend Invitation
```
POST /api/v1/users/{userId}/send-invite
{
  "actions": ["UPDATE_PASSWORD", "VERIFY_EMAIL"],
  "lifespan": 259200
}
```

### Send Verification Email
```
POST /api/v1/users/{userId}/verify-email
```

## Testing Without Real Email

For development/testing without real email:

### Option 1: MailPit (Recommended)
```yaml
mailpit:
  image: axllent/mailpit:latest
  ports:
    - "1025:1025"
    - "8025:8025"
  environment:
    - MP_MAX_MESSAGES=5000
    - MP_DATA_FILE=/data/mailpit.db
    - MP_SMTP_AUTH_DISABLED=1
  volumes:
    - mailpit-data:/data

volumes:
  mailpit-data:
```

Configure Keycloak:
```
Host: mailpit
Port: 1025
Enable Auth: OFF
Enable SSL: OFF
Enable StartTLS: OFF
```

**MailPit Features:**
- Modern web interface at http://localhost:8025
- Mobile responsive design
- Message search and filtering
- SQLite database for persistence
- REST API for automation
- No authentication required for testing

### Option 2: Log-only mode
Set Keycloak to log emails instead of sending:
```
KC_SPI_EMAIL_SENDER_PROVIDER=log
```

Emails appear in Keycloak logs instead of being sent.

## Next Steps

After email is configured:

1. Test with a real user
2. Monitor email delivery
3. Customize email templates
4. Set up email analytics
5. Implement email preference management
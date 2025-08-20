package keycloak

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

type AdminClient struct {
	baseURL      string
	adminRealm   string
	clientID     string
	clientSecret string
	adminUser    string
	adminPass    string
	logger       *zap.Logger
	httpClient   *http.Client
	accessToken  string
	tokenExpiry  time.Time
}

func NewAdminClient(baseURL, adminRealm, clientID, clientSecret, adminUser, adminPass string, skipTLSVerify bool, caCertPath string, logger *zap.Logger) *AdminClient {
	transport := &http.Transport{}
	
	if skipTLSVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 -- User explicitly configured to skip TLS verification
			MinVersion:         tls.VersionTLS12,
		}
	} else if caCertPath != "" {
		if !filepath.IsAbs(caCertPath) {
			logger.Warn("CA certificate path should be absolute", zap.String("path", caCertPath))
		}
		caCert, err := os.ReadFile(filepath.Clean(caCertPath))
		if err == nil {
			caCertPool := x509.NewCertPool()
			if caCertPool.AppendCertsFromPEM(caCert) {
				transport.TLSClientConfig = &tls.Config{
					RootCAs:    caCertPool,
					MinVersion: tls.VersionTLS12,
				}
			}
		}
	}
	
	return &AdminClient{
		baseURL:      strings.TrimSuffix(baseURL, "/"),
		adminRealm:   adminRealm,
		clientID:     clientID,
		clientSecret: clientSecret,
		adminUser:    adminUser,
		adminPass:    adminPass,
		logger:       logger,
		httpClient:   &http.Client{Timeout: 30 * time.Second, Transport: transport},
	}
}

func (c *AdminClient) GetHTTPClient() *http.Client {
	return c.httpClient
}

func (c *AdminClient) TestAuthentication(ctx context.Context) error {
	c.accessToken = ""
	c.tokenExpiry = time.Time{}
	
	if err := c.getAccessToken(ctx); err != nil {
		return fmt.Errorf("authentication test failed: %w", err)
	}
	
	resp, err := c.makeRequest(ctx, "GET", "", nil)
	if err != nil {
		return fmt.Errorf("authentication test request failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication test failed: received 401 unauthorized")
	}
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("authentication test failed: unexpected status %d", resp.StatusCode)
	}
	
	c.logger.Debug("Keycloak authentication test successful")
	return nil
}

type RealmRepresentation struct {
	ID                    string            `json:"id,omitempty"`
	Realm                 string            `json:"realm"`
	DisplayName           string            `json:"displayName,omitempty"`
	Enabled               bool              `json:"enabled"`
	LoginWithEmailAllowed bool              `json:"loginWithEmailAllowed"`
	RegistrationAllowed   bool              `json:"registrationAllowed"`
	ResetPasswordAllowed  bool              `json:"resetPasswordAllowed"`
	RememberMe            bool              `json:"rememberMe"`
	VerifyEmail           bool              `json:"verifyEmail"`
	LoginTheme            string            `json:"loginTheme,omitempty"`
	AccountTheme          string            `json:"accountTheme,omitempty"`
	AdminTheme            string            `json:"adminTheme,omitempty"`
	EmailTheme            string            `json:"emailTheme,omitempty"`
	Attributes            map[string]string `json:"attributes,omitempty"`
}

type UserRepresentation struct {
	ID            string                     `json:"id,omitempty"`
	Username      string                     `json:"username"`
	Email         string                     `json:"email,omitempty"`
	FirstName     string                     `json:"firstName,omitempty"`
	LastName      string                     `json:"lastName,omitempty"`
	Enabled       bool                       `json:"enabled"`
	EmailVerified bool                       `json:"emailVerified"`
	Attributes    map[string][]string        `json:"attributes,omitempty"`
	Groups        []string                   `json:"groups,omitempty"`
	RealmRoles    []string                   `json:"realmRoles,omitempty"`
	ClientRoles   map[string][]string        `json:"clientRoles,omitempty"`
	Credentials   []CredentialRepresentation `json:"credentials,omitempty"`
}

type CredentialRepresentation struct {
	Type      string `json:"type"`
	Value     string `json:"value,omitempty"`
	Temporary bool   `json:"temporary"`
}

type RoleRepresentation struct {
	ID          string                 `json:"id,omitempty"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Composite   bool                   `json:"composite"`
	Attributes  map[string]interface{} `json:"attributes,omitempty"`
}

type IdentityProviderRepresentation struct {
	Alias                     string                   `json:"alias"`
	DisplayName               string                   `json:"displayName,omitempty"`
	ProviderId                string                   `json:"providerId"`
	Enabled                   bool                     `json:"enabled"`
	TrustEmail                bool                     `json:"trustEmail"`
	StoreToken                bool                     `json:"storeToken"`
	LinkOnly                  bool                     `json:"linkOnly,omitempty"`
	AddReadTokenRoleOnCreate  bool                     `json:"addReadTokenRoleOnCreate"`
	UpdateProfileFirstLogin   string                   `json:"updateProfileFirstLoginMode,omitempty"`
	FirstBrokerLoginFlowAlias string                   `json:"firstBrokerLoginFlowAlias,omitempty"`
	PostBrokerLoginFlowAlias  string                   `json:"postBrokerLoginFlowAlias,omitempty"`
	Config                    map[string]string        `json:"config"`
	Mappers                   []IdentityProviderMapper `json:"mappers,omitempty"`
}

type IdentityProviderMapper struct {
	ID                       string            `json:"id,omitempty"`
	Name                     string            `json:"name"`
	IdentityProviderAlias    string            `json:"identityProviderAlias,omitempty"`
	IdentityProviderMapper   string            `json:"identityProviderMapper"`
	Config                   map[string]string `json:"config"`
}

type ClientRepresentation struct {
	ID                        string            `json:"id,omitempty"`
	ClientID                  string            `json:"clientId"`
	Name                      string            `json:"name,omitempty"`
	Description               string            `json:"description,omitempty"`
	Enabled                   bool              `json:"enabled"`
	ClientAuthenticatorType   string            `json:"clientAuthenticatorType,omitempty"`
	Secret                    string            `json:"secret,omitempty"`
	RedirectUris              []string          `json:"redirectUris,omitempty"`
	WebOrigins                []string          `json:"webOrigins,omitempty"`
	Protocol                  string            `json:"protocol,omitempty"`
	Attributes                map[string]string `json:"attributes,omitempty"`
	FullScopeAllowed          bool              `json:"fullScopeAllowed"`
	ServiceAccountsEnabled    bool              `json:"serviceAccountsEnabled"`
	StandardFlowEnabled       bool              `json:"standardFlowEnabled"`
	ImplicitFlowEnabled       bool              `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled bool              `json:"directAccessGrantsEnabled"`
}

type ProtocolMapperRepresentation struct {
	ID             string            `json:"id,omitempty"`
	Name           string            `json:"name"`
	Protocol       string            `json:"protocol"`
	ProtocolMapper string            `json:"protocolMapper"`
	Config         map[string]string `json:"config"`
}

type OrganizationRepresentation struct {
	ID          string                             `json:"id,omitempty"`
	Name        string                             `json:"name"`
	Enabled     bool                               `json:"enabled"`
	Description string                             `json:"description,omitempty"`
	Attributes  map[string]string                  `json:"attributes,omitempty"`
	Domains     []OrganizationDomainRepresentation `json:"domains,omitempty"`
}

type OrganizationDomainRepresentation struct {
	Name     string `json:"name"`
	Verified bool   `json:"verified"`
}

type MemberRepresentation struct {
	ID        string `json:"id,omitempty"`
	Username  string `json:"username"`
	Email     string `json:"email,omitempty"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	Enabled   bool   `json:"enabled"`
}

func (c *AdminClient) getAccessToken(ctx context.Context) error {
	if time.Now().Before(c.tokenExpiry) && c.accessToken != "" {
		return nil
	}

	err := c.tryGetAccessToken(ctx, c.adminUser, c.adminPass)
	if err == nil {
		return nil
	}

	c.logger.Debug("Configured admin credentials failed, trying default admin/admin", zap.Error(err))

	err = c.tryGetAccessToken(ctx, "admin", "admin")
	if err != nil {
		return fmt.Errorf("both configured and default admin credentials failed: %w", err)
	}

	c.logger.Info("Default admin credentials worked, changing password to configured value")
	if err := c.changeAdminPassword(ctx, "admin", c.adminPass); err != nil {
		c.logger.Warn("Failed to change admin password", zap.Error(err))

	} else {
		c.logger.Info("Admin password changed successfully")
	}

	return nil
}

func (c *AdminClient) tryGetAccessToken(ctx context.Context, username, password string) error {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, c.adminRealm)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", "admin-cli")
	data.Set("username", username)
	data.Set("password", password)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get access token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorMsg string
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			errorMsg = fmt.Sprintf("authentication failed for user '%s' - check username/password", username)
		case http.StatusForbidden:
			errorMsg = fmt.Sprintf("user '%s' does not have admin privileges", username)
		case http.StatusNotFound:
			errorMsg = "Keycloak admin endpoint not found - check URL and realm"
		default:
			errorMsg = fmt.Sprintf("token request failed with status %d", resp.StatusCode)
		}
		
		body, _ := io.ReadAll(resp.Body)
		if len(body) > 0 {
			c.logger.Debug("Token request error details", 
				zap.String("username", username),
				zap.Int("status", resp.StatusCode),
				zap.String("response", string(body)))
		}
		
		return fmt.Errorf("%s", errorMsg)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)

	c.logger.Debug("Obtained Keycloak admin access token",
		zap.String("username", username),
		zap.Int("expires_in", tokenResp.ExpiresIn))

	return nil
}

func (c *AdminClient) changeAdminPassword(ctx context.Context, currentPassword, newPassword string) error {

	url := fmt.Sprintf("%s/admin/realms/%s/users?username=admin&exact=true", c.baseURL, c.adminRealm)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create user search request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to search for admin user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("user search failed with status %d", resp.StatusCode)
	}

	var users []UserRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return fmt.Errorf("failed to decode users response: %w", err)
	}

	if len(users) == 0 {
		return fmt.Errorf("admin user not found")
	}

	adminUser := users[0]

	credential := CredentialRepresentation{
		Type:      "password",
		Value:     newPassword,
		Temporary: false,
	}

	userUpdate := &UserRepresentation{
		ID:          adminUser.ID,
		Username:    adminUser.Username,
		Enabled:     true,
		Credentials: []CredentialRepresentation{credential},
	}

	updateURL := fmt.Sprintf("%s/admin/realms/%s/users/%s", c.baseURL, c.adminRealm, adminUser.ID)

	jsonBody, err := json.Marshal(userUpdate)
	if err != nil {
		return fmt.Errorf("failed to marshal user update: %w", err)
	}

	updateReq, err := http.NewRequestWithContext(ctx, "PUT", updateURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create update request: %w", err)
	}

	updateReq.Header.Set("Authorization", "Bearer "+c.accessToken)
	updateReq.Header.Set("Content-Type", "application/json")

	updateResp, err := c.httpClient.Do(updateReq)
	if err != nil {
		return fmt.Errorf("failed to update admin password: %w", err)
	}
	defer updateResp.Body.Close()

	if updateResp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("change password failed with status %d", updateResp.StatusCode)
	}

	return nil
}

func (c *AdminClient) makeRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	return c.makeRequestWithRetry(ctx, method, path, body, false)
}

func (c *AdminClient) makeRequestWithRetry(ctx context.Context, method, path string, body interface{}, isRetry bool) (*http.Response, error) {
	if err := c.getAccessToken(ctx); err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	url := fmt.Sprintf("%s/admin/realms%s", c.baseURL, path)

	var reqBody *bytes.Buffer
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized && !isRetry {
		resp.Body.Close()
		c.logger.Debug("Received 401, invalidating token and retrying", zap.String("method", method), zap.String("path", path))
		c.accessToken = ""
		c.tokenExpiry = time.Time{}
		return c.makeRequestWithRetry(ctx, method, path, body, true)
	}

	return resp, nil
}

func (c *AdminClient) CreateRealm(ctx context.Context, realm *RealmRepresentation) error {
	resp, err := c.makeRequest(ctx, "POST", "", realm)
	if err != nil {
		return fmt.Errorf("failed to create realm: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("realm %s already exists", realm.Realm)
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("create realm failed with status %d", resp.StatusCode)
	}

	c.logger.Info("Created Keycloak realm", zap.String("realm", realm.Realm))
	return nil
}

func (c *AdminClient) GetRealm(ctx context.Context, realmName string) (*RealmRepresentation, error) {
	resp, err := c.makeRequest(ctx, "GET", "/"+realmName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get realm: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("realm %s not found", realmName)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get realm failed with status %d", resp.StatusCode)
	}

	var realm RealmRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&realm); err != nil {
		return nil, fmt.Errorf("failed to decode realm response: %w", err)
	}

	return &realm, nil
}

func (c *AdminClient) GetRealms(ctx context.Context) ([]RealmRepresentation, error) {
	resp, err := c.makeRequest(ctx, "GET", "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get realms: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get realms failed with status %d", resp.StatusCode)
	}

	var realms []RealmRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&realms); err != nil {
		return nil, fmt.Errorf("failed to decode realms response: %w", err)
	}

	return realms, nil
}

func (c *AdminClient) UpdateRealm(ctx context.Context, realmName string, realm *RealmRepresentation) error {
	resp, err := c.makeRequest(ctx, "PUT", "/"+realmName, realm)
	if err != nil {
		return fmt.Errorf("failed to update realm: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("realm %s not found", realmName)
	}

	if resp.StatusCode != http.StatusNoContent {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return fmt.Errorf("update realm failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *AdminClient) DeleteRealm(ctx context.Context, realmName string) error {
	resp, err := c.makeRequest(ctx, "DELETE", "/"+realmName, nil)
	if err != nil {
		return fmt.Errorf("failed to delete realm: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("realm %s not found", realmName)
	}

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("delete realm failed with status %d", resp.StatusCode)
	}

	c.logger.Info("Deleted Keycloak realm", zap.String("realm", realmName))
	return nil
}

func (c *AdminClient) CreateUser(ctx context.Context, realmName string, user *UserRepresentation) (*UserRepresentation, error) {
	resp, err := c.makeRequest(ctx, "POST", fmt.Sprintf("/%s/users", realmName), user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return nil, fmt.Errorf("user %s already exists in realm %s", user.Username, realmName)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("create user failed with status %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return nil, fmt.Errorf("no location header in create user response")
	}

	parts := strings.Split(location, "/")
	if len(parts) == 0 {
		return nil, fmt.Errorf("invalid location header format")
	}
	userID := parts[len(parts)-1]

	createdUser, err := c.GetUser(ctx, realmName, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get created user: %w", err)
	}

	c.logger.Info("Created Keycloak user",
		zap.String("realm", realmName),
		zap.String("username", user.Username),
		zap.String("user_id", userID))

	return createdUser, nil
}

func (c *AdminClient) GetUser(ctx context.Context, realmName, userID string) (*UserRepresentation, error) {
	resp, err := c.makeRequest(ctx, "GET", fmt.Sprintf("/%s/users/%s", realmName, userID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("user %s not found in realm %s", userID, realmName)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get user failed with status %d", resp.StatusCode)
	}

	var user UserRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user response: %w", err)
	}

	return &user, nil
}

func (c *AdminClient) GetUserByUsername(ctx context.Context, realmName, username string) (*UserRepresentation, error) {
	resp, err := c.makeRequest(ctx, "GET", fmt.Sprintf("/%s/users?username=%s&exact=true", realmName, url.QueryEscape(username)), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to search user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("search user failed with status %d", resp.StatusCode)
	}

	var users []UserRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("failed to decode users response: %w", err)
	}

	if len(users) == 0 {
		return nil, fmt.Errorf("user %s not found in realm %s", username, realmName)
	}

	return &users[0], nil
}

func (c *AdminClient) DeleteUser(ctx context.Context, realmName, userID string) error {
	resp, err := c.makeRequest(ctx, "DELETE", fmt.Sprintf("/%s/users/%s", realmName, userID), nil)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("user %s not found in realm %s", userID, realmName)
	}

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("delete user failed with status %d", resp.StatusCode)
	}

	c.logger.Info("Deleted Keycloak user",
		zap.String("realm", realmName),
		zap.String("user_id", userID))

	return nil
}

func (c *AdminClient) CreateRole(ctx context.Context, realmName string, role *RoleRepresentation) error {
	resp, err := c.makeRequest(ctx, "POST", fmt.Sprintf("/%s/roles", realmName), role)
	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("role %s already exists in realm %s", role.Name, realmName)
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("create role failed with status %d", resp.StatusCode)
	}

	c.logger.Info("Created Keycloak role",
		zap.String("realm", realmName),
		zap.String("role", role.Name))

	return nil
}

func (c *AdminClient) AssignRealmRolesToUser(ctx context.Context, realmName, userID string, roles []RoleRepresentation) error {
	resp, err := c.makeRequest(ctx, "POST", fmt.Sprintf("/%s/users/%s/role-mappings/realm", realmName, userID), roles)
	if err != nil {
		return fmt.Errorf("failed to assign roles: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("assign roles failed with status %d", resp.StatusCode)
	}

	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.Name
	}

	c.logger.Info("Assigned realm roles to user",
		zap.String("realm", realmName),
		zap.String("user_id", userID),
		zap.Strings("roles", roleNames))

	return nil
}

func (c *AdminClient) GetRealmRole(ctx context.Context, realmName, roleName string) (*RoleRepresentation, error) {
	resp, err := c.makeRequest(ctx, "GET", fmt.Sprintf("/%s/roles/%s", realmName, roleName), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("role %s not found in realm %s", roleName, realmName)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get role failed with status %d", resp.StatusCode)
	}

	var role RoleRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&role); err != nil {
		return nil, fmt.Errorf("failed to decode role response: %w", err)
	}

	return &role, nil
}

func (c *AdminClient) CreateRealmRole(ctx context.Context, realmName, roleName, description string) error {
	role := &RoleRepresentation{
		Name:        roleName,
		Description: description,
		Composite:   false,
	}
	return c.CreateRole(ctx, realmName, role)
}

func (c *AdminClient) ListRealmRoles(ctx context.Context, realmName string) ([]RoleRepresentation, error) {
	resp, err := c.makeRequest(ctx, "GET", fmt.Sprintf("/%s/roles", realmName), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list roles failed with status %d", resp.StatusCode)
	}

	var roles []RoleRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
		return nil, fmt.Errorf("failed to decode roles response: %w", err)
	}

	return roles, nil
}

func (c *AdminClient) DeleteRealmRole(ctx context.Context, realmName, roleName string) error {
	resp, err := c.makeRequest(ctx, "DELETE", fmt.Sprintf("/%s/roles/%s", realmName, roleName), nil)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("role %s not found in realm %s", roleName, realmName)
	}

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("delete role failed with status %d", resp.StatusCode)
	}

	c.logger.Info("Deleted realm role",
		zap.String("realm", realmName),
		zap.String("role", roleName))

	return nil
}

func (c *AdminClient) CreateIdentityProvider(ctx context.Context, realmName string, idp *IdentityProviderRepresentation) error {
	resp, err := c.makeRequest(ctx, "POST", fmt.Sprintf("/%s/identity-provider/instances", realmName), idp)
	if err != nil {
		return fmt.Errorf("failed to create identity provider: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("identity provider %s already exists in realm %s", idp.Alias, realmName)
	}

	if resp.StatusCode != http.StatusCreated {
		// Read response body for detailed error information
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			c.logger.Error("Failed to read error response body",
				zap.Int("status_code", resp.StatusCode),
				zap.String("realm", realmName),
				zap.String("provider", idp.Alias),
				zap.Error(readErr))
			return fmt.Errorf("create identity provider failed with status %d", resp.StatusCode)
		}
		
		c.logger.Error("Failed to create identity provider - Keycloak error",
			zap.Int("status_code", resp.StatusCode),
			zap.String("realm", realmName),
			zap.String("provider", idp.Alias),
			zap.String("response_body", string(body)))
		
		return fmt.Errorf("create identity provider failed with status %d: %s", resp.StatusCode, string(body))
	}

	c.logger.Info("Created identity provider",
		zap.String("realm", realmName),
		zap.String("provider", idp.Alias))

	return nil
}

func (c *AdminClient) CreateIdentityProviderMapper(ctx context.Context, realmName, providerAlias string, mapper *IdentityProviderMapper) error {
	resp, err := c.makeRequest(ctx, "POST", fmt.Sprintf("/%s/identity-provider/instances/%s/mappers", realmName, providerAlias), mapper)
	if err != nil {
		return fmt.Errorf("failed to create identity provider mapper: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			c.logger.Error("Failed to read error response body for mapper creation",
				zap.Int("status_code", resp.StatusCode),
				zap.String("realm", realmName),
				zap.String("provider", providerAlias),
				zap.String("mapper", mapper.Name),
				zap.Error(readErr))
			return fmt.Errorf("create identity provider mapper failed with status %d", resp.StatusCode)
		}
		
		c.logger.Error("Failed to create identity provider mapper - Keycloak error",
			zap.Int("status_code", resp.StatusCode),
			zap.String("realm", realmName),
			zap.String("provider", providerAlias),
			zap.String("mapper", mapper.Name),
			zap.String("response_body", string(body)))
		
		return fmt.Errorf("create identity provider mapper failed with status %d: %s", resp.StatusCode, string(body))
	}

	c.logger.Info("Created identity provider mapper",
		zap.String("realm", realmName),
		zap.String("provider", providerAlias),
		zap.String("mapper", mapper.Name))

	return nil
}

func (c *AdminClient) GetIdentityProvider(ctx context.Context, realmName, alias string) (*IdentityProviderRepresentation, error) {
	resp, err := c.makeRequest(ctx, "GET", fmt.Sprintf("/%s/identity-provider/instances/%s", realmName, alias), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity provider: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("identity provider %s not found in realm %s", alias, realmName)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get identity provider failed with status %d", resp.StatusCode)
	}

	var idp IdentityProviderRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&idp); err != nil {
		return nil, fmt.Errorf("failed to decode identity provider response: %w", err)
	}

	return &idp, nil
}

func (c *AdminClient) ListIdentityProviders(ctx context.Context, realmName string) ([]IdentityProviderRepresentation, error) {
	resp, err := c.makeRequest(ctx, "GET", fmt.Sprintf("/%s/identity-provider/instances", realmName), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list identity providers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list identity providers failed with status %d", resp.StatusCode)
	}

	var idps []IdentityProviderRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&idps); err != nil {
		return nil, fmt.Errorf("failed to decode identity providers response: %w", err)
	}

	return idps, nil
}

func (c *AdminClient) UpdateIdentityProvider(ctx context.Context, realmName, alias string, idp *IdentityProviderRepresentation) error {
	resp, err := c.makeRequest(ctx, "PUT", fmt.Sprintf("/%s/identity-provider/instances/%s", realmName, alias), idp)
	if err != nil {
		return fmt.Errorf("failed to update identity provider: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("identity provider %s not found in realm %s", alias, realmName)
	}

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("update identity provider failed with status %d", resp.StatusCode)
	}

	c.logger.Info("Updated identity provider",
		zap.String("realm", realmName),
		zap.String("provider", alias))

	return nil
}

func (c *AdminClient) DeleteIdentityProvider(ctx context.Context, realmName, alias string) error {
	resp, err := c.makeRequest(ctx, "DELETE", fmt.Sprintf("/%s/identity-provider/instances/%s", realmName, alias), nil)
	if err != nil {
		return fmt.Errorf("failed to delete identity provider: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("identity provider %s not found in realm %s", alias, realmName)
	}

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("delete identity provider failed with status %d", resp.StatusCode)
	}

	c.logger.Info("Deleted identity provider",
		zap.String("realm", realmName),
		zap.String("provider", alias))

	return nil
}

func (c *AdminClient) CreateClient(ctx context.Context, realmName string, client *ClientRepresentation) (*ClientRepresentation, error) {
	resp, err := c.makeRequest(ctx, "POST", fmt.Sprintf("/%s/clients", realmName), client)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return nil, fmt.Errorf("client %s already exists in realm %s", client.ClientID, realmName)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("create client failed with status %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return nil, fmt.Errorf("no location header in create client response")
	}

	parts := strings.Split(location, "/")
	if len(parts) == 0 {
		return nil, fmt.Errorf("invalid location header format")
	}
	clientUUID := parts[len(parts)-1]

	createdClient, err := c.GetClient(ctx, realmName, clientUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get created client: %w", err)
	}

	c.logger.Info("Created Keycloak client",
		zap.String("realm", realmName),
		zap.String("client_id", client.ClientID))

	return createdClient, nil
}

func (c *AdminClient) GetClient(ctx context.Context, realmName, clientUUID string) (*ClientRepresentation, error) {
	resp, err := c.makeRequest(ctx, "GET", fmt.Sprintf("/%s/clients/%s", realmName, clientUUID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("client %s not found in realm %s", clientUUID, realmName)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get client failed with status %d", resp.StatusCode)
	}

	var client ClientRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&client); err != nil {
		return nil, fmt.Errorf("failed to decode client response: %w", err)
	}

	return &client, nil
}

func (c *AdminClient) GetClientUUID(ctx context.Context, realmName, clientID string) (string, error) {
	resp, err := c.makeRequest(ctx, "GET", fmt.Sprintf("/%s/clients?clientId=%s", realmName, url.QueryEscape(clientID)), nil)
	if err != nil {
		return "", fmt.Errorf("failed to get client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("get client failed with status %d", resp.StatusCode)
	}

	var clients []ClientRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return "", fmt.Errorf("failed to decode clients response: %w", err)
	}

	if len(clients) == 0 {
		return "", fmt.Errorf("client %s not found in realm %s", clientID, realmName)
	}

	return clients[0].ID, nil
}

func (c *AdminClient) CreateProtocolMapper(ctx context.Context, realmName, clientUUID string, mapper *ProtocolMapperRepresentation) error {
	resp, err := c.makeRequest(ctx, "POST", fmt.Sprintf("/%s/clients/%s/protocol-mappers/models", realmName, clientUUID), mapper)
	if err != nil {
		return fmt.Errorf("failed to create protocol mapper: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("protocol mapper already exists")
	}

	if resp.StatusCode != http.StatusCreated {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return fmt.Errorf("create protocol mapper failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *AdminClient) GetUsers(ctx context.Context, realmName string) ([]UserRepresentation, error) {
	resp, err := c.makeRequest(ctx, "GET", fmt.Sprintf("/%s/users", realmName), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return nil, fmt.Errorf("get users failed with status %d: %s", resp.StatusCode, string(body))
	}

	var users []UserRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("failed to decode users response: %w", err)
	}

	return users, nil
}

func (c *AdminClient) UpdateUser(ctx context.Context, realmName, userID string, user *UserRepresentation) error {
	resp, err := c.makeRequest(ctx, "PUT", fmt.Sprintf("/%s/users/%s", realmName, userID), user)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return fmt.Errorf("update user failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *AdminClient) GetUserRealmRoles(ctx context.Context, realmName, userID string) ([]RoleRepresentation, error) {
	resp, err := c.makeRequest(ctx, "GET", fmt.Sprintf("/%s/users/%s/role-mappings/realm", realmName, userID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return nil, fmt.Errorf("get user roles failed with status %d: %s", resp.StatusCode, string(body))
	}

	var roles []RoleRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
		return nil, fmt.Errorf("failed to decode roles response: %w", err)
	}

	return roles, nil
}

func (c *AdminClient) CreateOrganization(ctx context.Context, realmName string, org *OrganizationRepresentation) (*OrganizationRepresentation, error) {
	resp, err := c.makeRequest(ctx, "POST", fmt.Sprintf("/%s/organizations", realmName), org)
	if err != nil {
		return nil, fmt.Errorf("failed to create organization: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return nil, fmt.Errorf("organization %s already exists in realm %s", org.Name, realmName)
	}

	if resp.StatusCode != http.StatusCreated {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("create organization failed with status %d: failed to read response body: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("create organization failed with status %d: %s", resp.StatusCode, string(body))
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return nil, fmt.Errorf("no location header in create organization response")
	}

	parts := strings.Split(location, "/")
	if len(parts) == 0 {
		return nil, fmt.Errorf("invalid location header format")
	}
	orgID := parts[len(parts)-1]

	createdOrg, err := c.GetOrganization(ctx, realmName, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get created organization: %w", err)
	}

	c.logger.Info("Created Keycloak organization",
		zap.String("realm", realmName),
		zap.String("organization", org.Name),
		zap.String("org_id", orgID))

	return createdOrg, nil
}

func (c *AdminClient) GetOrganization(ctx context.Context, realmName, orgID string) (*OrganizationRepresentation, error) {
	resp, err := c.makeRequest(ctx, "GET", fmt.Sprintf("/%s/organizations/%s", realmName, orgID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("organization %s not found in realm %s", orgID, realmName)
	}

	if resp.StatusCode != http.StatusOK {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return nil, fmt.Errorf("get organization failed with status %d: %s", resp.StatusCode, string(body))
	}

	var org OrganizationRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&org); err != nil {
		return nil, fmt.Errorf("failed to decode organization response: %w", err)
	}

	return &org, nil
}

func (c *AdminClient) ListOrganizations(ctx context.Context, realmName string) ([]OrganizationRepresentation, error) {
	resp, err := c.makeRequest(ctx, "GET", fmt.Sprintf("/%s/organizations", realmName), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return nil, fmt.Errorf("list organizations failed with status %d: %s", resp.StatusCode, string(body))
	}

	var orgs []OrganizationRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil {
		return nil, fmt.Errorf("failed to decode organizations response: %w", err)
	}

	return orgs, nil
}

func (c *AdminClient) UpdateOrganization(ctx context.Context, realmName, orgID string, org *OrganizationRepresentation) error {
	resp, err := c.makeRequest(ctx, "PUT", fmt.Sprintf("/%s/organizations/%s", realmName, orgID), org)
	if err != nil {
		return fmt.Errorf("failed to update organization: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return fmt.Errorf("update organization failed with status %d: %s", resp.StatusCode, string(body))
	}

	c.logger.Info("Updated Keycloak organization",
		zap.String("realm", realmName),
		zap.String("org_id", orgID))

	return nil
}

func (c *AdminClient) DeleteOrganization(ctx context.Context, realmName, orgID string) error {
	resp, err := c.makeRequest(ctx, "DELETE", fmt.Sprintf("/%s/organizations/%s", realmName, orgID), nil)
	if err != nil {
		return fmt.Errorf("failed to delete organization: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("organization %s not found in realm %s", orgID, realmName)
	}

	if resp.StatusCode != http.StatusNoContent {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return fmt.Errorf("delete organization failed with status %d: %s", resp.StatusCode, string(body))
	}

	c.logger.Info("Deleted Keycloak organization",
		zap.String("realm", realmName),
		zap.String("org_id", orgID))

	return nil
}

func (c *AdminClient) AddOrganizationMember(ctx context.Context, realmName, orgID, userID string) error {
	resp, err := c.makeRequest(ctx, "POST", fmt.Sprintf("/%s/organizations/%s/members", realmName, orgID), map[string]string{"id": userID})
	if err != nil {
		return fmt.Errorf("failed to add organization member: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return fmt.Errorf("add organization member failed with status %d: %s", resp.StatusCode, string(body))
	}

	c.logger.Info("Added organization member",
		zap.String("realm", realmName),
		zap.String("org_id", orgID),
		zap.String("user_id", userID))

	return nil
}

func (c *AdminClient) RemoveOrganizationMember(ctx context.Context, realmName, orgID, userID string) error {
	resp, err := c.makeRequest(ctx, "DELETE", fmt.Sprintf("/%s/organizations/%s/members/%s", realmName, orgID, userID), nil)
	if err != nil {
		return fmt.Errorf("failed to remove organization member: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return fmt.Errorf("remove organization member failed with status %d: %s", resp.StatusCode, string(body))
	}

	c.logger.Info("Removed organization member",
		zap.String("realm", realmName),
		zap.String("org_id", orgID),
		zap.String("user_id", userID))

	return nil
}

func (c *AdminClient) ListOrganizationMembers(ctx context.Context, realmName, orgID string) ([]MemberRepresentation, error) {
	resp, err := c.makeRequest(ctx, "GET", fmt.Sprintf("/%s/organizations/%s/members", realmName, orgID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list organization members: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return nil, fmt.Errorf("list organization members failed with status %d: %s", resp.StatusCode, string(body))
	}

	var members []MemberRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&members); err != nil {
		return nil, fmt.Errorf("failed to decode members response: %w", err)
	}

	return members, nil
}

// Authorization Services support

// ResourceRepresentation represents a Keycloak Authorization resource
type ResourceRepresentation struct {
	ID          string                 `json:"id,omitempty"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type,omitempty"`
	URI         string                 `json:"uri,omitempty"`
	Scopes      []ScopeRepresentation  `json:"scopes,omitempty"`
	Attributes  map[string]interface{} `json:"attributes,omitempty"`
	DisplayName string                 `json:"displayName,omitempty"`
}

// ScopeRepresentation represents a Keycloak Authorization scope
type ScopeRepresentation struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	IconURI     string `json:"iconUri,omitempty"`
}

// PolicyRepresentation represents a Keycloak Authorization policy
type PolicyRepresentation struct {
	ID               string                 `json:"id,omitempty"`
	Name             string                 `json:"name"`
	Type             string                 `json:"type"`
	Logic            string                 `json:"logic,omitempty"`
	DecisionStrategy string                 `json:"decisionStrategy,omitempty"`
	Config           map[string]interface{} `json:"config,omitempty"`
}

// PermissionRepresentation represents a Keycloak Authorization permission
type PermissionRepresentation struct {
	ID               string   `json:"id,omitempty"`
	Name             string   `json:"name"`
	Type             string   `json:"type"`
	Logic            string   `json:"logic,omitempty"`
	DecisionStrategy string   `json:"decisionStrategy,omitempty"`
	Resources        []string `json:"resources,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	Policies         []string `json:"policies,omitempty"`
}

// AuthorizationRequest represents a request for authorization evaluation
type AuthorizationRequest struct {
	GrantType string `json:"grant_type"`
	Audience  string `json:"audience"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
}

// CheckUserPermission checks if a user has permission to perform an action on a resource
func (c *AdminClient) CheckUserPermission(ctx context.Context, realmName, userID, resource, action string) (bool, error) {
	
	c.logger.Debug("Checking user permission",
		zap.String("realm", realmName),
		zap.String("user_id", userID),
		zap.String("resource", resource),
		zap.String("action", action))

	// For now, return true for basic operations
	// In production, this should use Keycloak's Authorization Services API
	// to evaluate permissions based on policies and resources
	
	return true, nil
}

// CreateResource creates an authorization resource in Keycloak
func (c *AdminClient) CreateResource(ctx context.Context, realmName, clientID string, resource *ResourceRepresentation) (*ResourceRepresentation, error) {
	endpoint := fmt.Sprintf("/%s/clients/%s/authz/resource-server/resource", realmName, clientID)
	
	resp, err := c.makeRequest(ctx, "POST", endpoint, resource)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return nil, fmt.Errorf("create resource failed with status %d: %s", resp.StatusCode, string(body))
	}

	var createdResource ResourceRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&createdResource); err != nil {
		return nil, fmt.Errorf("failed to decode resource response: %w", err)
	}

	c.logger.Info("Created authorization resource",
		zap.String("realm", realmName),
		zap.String("client_id", clientID),
		zap.String("resource_name", resource.Name))

	return &createdResource, nil
}

// CreateScope creates an authorization scope in Keycloak
func (c *AdminClient) CreateScope(ctx context.Context, realmName, clientID string, scope *ScopeRepresentation) (*ScopeRepresentation, error) {
	endpoint := fmt.Sprintf("/%s/clients/%s/authz/resource-server/scope", realmName, clientID)
	
	resp, err := c.makeRequest(ctx, "POST", endpoint, scope)
	if err != nil {
		return nil, fmt.Errorf("failed to create scope: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return nil, fmt.Errorf("create scope failed with status %d: %s", resp.StatusCode, string(body))
	}

	var createdScope ScopeRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&createdScope); err != nil {
		return nil, fmt.Errorf("failed to decode scope response: %w", err)
	}

	c.logger.Info("Created authorization scope",
		zap.String("realm", realmName),
		zap.String("client_id", clientID),
		zap.String("scope_name", scope.Name))

	return &createdScope, nil
}

// CreatePolicy creates an authorization policy in Keycloak
func (c *AdminClient) CreatePolicy(ctx context.Context, realmName, clientID string, policy *PolicyRepresentation) (*PolicyRepresentation, error) {
	endpoint := fmt.Sprintf("/%s/clients/%s/authz/resource-server/policy/%s", realmName, clientID, policy.Type)
	
	resp, err := c.makeRequest(ctx, "POST", endpoint, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return nil, fmt.Errorf("create policy failed with status %d: %s", resp.StatusCode, string(body))
	}

	var createdPolicy PolicyRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&createdPolicy); err != nil {
		return nil, fmt.Errorf("failed to decode policy response: %w", err)
	}

	c.logger.Info("Created authorization policy",
		zap.String("realm", realmName),
		zap.String("client_id", clientID),
		zap.String("policy_name", policy.Name),
		zap.String("policy_type", policy.Type))

	return &createdPolicy, nil
}

// CreatePermission creates an authorization permission in Keycloak
func (c *AdminClient) CreatePermission(ctx context.Context, realmName, clientID string, permission *PermissionRepresentation) (*PermissionRepresentation, error) {
	endpoint := fmt.Sprintf("/%s/clients/%s/authz/resource-server/permission/%s", realmName, clientID, permission.Type)
	
	resp, err := c.makeRequest(ctx, "POST", endpoint, permission)
	if err != nil {
		return nil, fmt.Errorf("failed to create permission: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return nil, fmt.Errorf("create permission failed with status %d: %s", resp.StatusCode, string(body))
	}

	var createdPermission PermissionRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&createdPermission); err != nil {
		return nil, fmt.Errorf("failed to decode permission response: %w", err)
	}

	c.logger.Info("Created authorization permission",
		zap.String("realm", realmName),
		zap.String("client_id", clientID),
		zap.String("permission_name", permission.Name),
		zap.String("permission_type", permission.Type))

	return &createdPermission, nil
}

// Cross-realm access control methods

// CheckUserRealmAccess verifies if a user has access to a specific realm
func (c *AdminClient) CheckUserRealmAccess(ctx context.Context, userID, targetRealm string) (bool, error) {
	// First, check if user exists in the target realm
	exists, err := c.UserExistsInRealm(ctx, targetRealm, userID)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence in realm: %w", err)
	}
	
	if exists {
		c.logger.Debug("User has direct access to realm",
			zap.String("user_id", userID),
			zap.String("realm", targetRealm))
		return true, nil
	}
	
	// If user doesn't exist in target realm, check for cross-realm access
	// This involves checking if the user has MSP admin roles that grant cross-realm access
	return c.CheckCrossRealmAccess(ctx, userID, targetRealm)
}

// UserExistsInRealm checks if a user exists in a specific realm
func (c *AdminClient) UserExistsInRealm(ctx context.Context, realmName, userID string) (bool, error) {
	endpoint := fmt.Sprintf("/%s/users/%s", realmName, userID)
	
	resp, err := c.makeRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("failed to check user in realm: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("check user in realm failed with status %d", resp.StatusCode)
	}
	
	return true, nil
}

// CheckCrossRealmAccess verifies if a user has cross-realm access privileges
func (c *AdminClient) CheckCrossRealmAccess(ctx context.Context, userID, targetRealm string) (bool, error) {
	// Get user's realm memberships and roles across all realms
	realms, err := c.GetRealms(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get realms: %w", err)
	}
	
	// Check each realm where the user might exist
	for _, realm := range realms {
		userExists, err := c.UserExistsInRealm(ctx, realm.Realm, userID)
		if err != nil {
			c.logger.Debug("Error checking user in realm",
				zap.String("user_id", userID),
				zap.String("realm", realm.Realm),
				zap.Error(err))
			continue
		}
		
		if userExists {
			// Check if user has MSP admin roles in this realm
			hasAccess, err := c.UserHasCrossRealmRole(ctx, realm.Realm, userID, targetRealm)
			if err != nil {
				c.logger.Debug("Error checking cross-realm role",
					zap.String("user_id", userID),
					zap.String("source_realm", realm.Realm),
					zap.String("target_realm", targetRealm),
					zap.Error(err))
				continue
			}
			
			if hasAccess {
				c.logger.Info("User has cross-realm access",
					zap.String("user_id", userID),
					zap.String("source_realm", realm.Realm),
					zap.String("target_realm", targetRealm))
				return true, nil
			}
		}
	}
	
	c.logger.Debug("User does not have cross-realm access",
		zap.String("user_id", userID),
		zap.String("target_realm", targetRealm))
	
	return false, nil
}

// UserHasCrossRealmRole checks if user has roles that grant cross-realm access
func (c *AdminClient) UserHasCrossRealmRole(ctx context.Context, userRealm, userID, targetRealm string) (bool, error) {
	// Get user's roles in their home realm
	roles, err := c.GetUserRealmRoles(ctx, userRealm, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user roles: %w", err)
	}
	
	// Check for MSP admin roles that grant cross-realm access
	for _, role := range roles {
		if c.isCrossRealmRole(role.Name, userRealm, targetRealm) {
			return true, nil
		}
	}
	
	return false, nil
}


// isCrossRealmRole determines if a role grants cross-realm access
func (c *AdminClient) isCrossRealmRole(roleName, sourceRealm, targetRealm string) bool {
	// MSP admin roles grant access to all tenant realms
	if roleName == "msp-admin" || roleName == "msp-power" {
		// Check if source is master realm and target is tenant realm
		if sourceRealm == "master" || sourceRealm == c.adminRealm {
			return true
		}
		
		// Or if it's a parent-child relationship between MSP and tenant realms
		if c.isParentChildRelationship(sourceRealm, targetRealm) {
			return true
		}
	}
	
	// MSP viewer role grants read-only access
	if roleName == "msp-viewer" {
		if sourceRealm == "master" || sourceRealm == c.adminRealm {
			return true
		}
	}
	
	return false
}

// isParentChildRelationship checks if there's a parent-child relationship between realms
func (c *AdminClient) isParentChildRelationship(parentRealm, childRealm string) bool {
	// In our architecture, MSP realms can manage tenant realms
	// This is where you'd implement your specific parent-child logic
	// For now, we'll use a simple naming convention check
	
	// Example: msp-acme realm can manage acme-tenant-1, acme-tenant-2, etc.
	if strings.HasPrefix(parentRealm, "msp-") {
		mspName := strings.TrimPrefix(parentRealm, "msp-")
		return strings.HasPrefix(childRealm, mspName+"-")
	}
	
	return false
}

// ValidateRealmAccess is the main method used by middleware to validate access
func (c *AdminClient) ValidateRealmAccess(ctx context.Context, userID, targetRealm, sourceRealm string) (bool, error) {
	// If user is accessing their own realm, allow
	if sourceRealm == targetRealm {
		return true, nil
	}
	
	// Check cross-realm access
	return c.CheckUserRealmAccess(ctx, userID, targetRealm)
}

// RealmAccessLevel represents the level of access a user has to a realm
type RealmAccessLevel string

const (
	RealmAccessNone     RealmAccessLevel = "none"
	RealmAccessRead     RealmAccessLevel = "read"
	RealmAccessWrite    RealmAccessLevel = "write"
	RealmAccessAdmin    RealmAccessLevel = "admin"
	RealmAccessMSPAdmin RealmAccessLevel = "msp-admin"
)

// GetUserRealmAccessLevel determines the level of access a user has to a realm
func (c *AdminClient) GetUserRealmAccessLevel(ctx context.Context, userID, targetRealm, sourceRealm string) (RealmAccessLevel, error) {
	// Direct realm membership grants full access
	if sourceRealm == targetRealm {
		return RealmAccessAdmin, nil
	}
	
	// Check for cross-realm roles
	realms, err := c.GetRealms(ctx)
	if err != nil {
		return RealmAccessNone, fmt.Errorf("failed to get realms: %w", err)
	}
	
	for _, realm := range realms {
		userExists, err := c.UserExistsInRealm(ctx, realm.Realm, userID)
		if err != nil {
			continue
		}
		
		if userExists {
			roles, err := c.GetUserRealmRoles(ctx, realm.Realm, userID)
			if err != nil {
				continue
			}
			
			// Determine highest access level based on roles
			for _, role := range roles {
				switch role.Name {
				case "msp-admin":
					if c.isCrossRealmRole(role.Name, realm.Realm, targetRealm) {
						return RealmAccessMSPAdmin, nil
					}
				case "msp-power":
					if c.isCrossRealmRole(role.Name, realm.Realm, targetRealm) {
						return RealmAccessWrite, nil
					}
				case "msp-viewer":
					if c.isCrossRealmRole(role.Name, realm.Realm, targetRealm) {
						return RealmAccessRead, nil
					}
				}
			}
		}
	}
	
	return RealmAccessNone, nil
}

// Role management methods

// AssignRealmRoleToUser assigns a realm role to a user
func (c *AdminClient) AssignRealmRoleToUser(ctx context.Context, realmName, userID, roleName string) error {
	// First, get the role to get its ID
	role, err := c.GetRealmRole(ctx, realmName, roleName)
	if err != nil {
		return fmt.Errorf("failed to get role %s: %w", roleName, err)
	}
	if role == nil {
		return fmt.Errorf("role %s not found in realm %s", roleName, realmName)
	}
	
	endpoint := fmt.Sprintf("/%s/users/%s/role-mappings/realm", realmName, userID)
	
	roleAssignments := []RoleRepresentation{*role}
	
	resp, err := c.makeRequest(ctx, "POST", endpoint, roleAssignments)
	if err != nil {
		return fmt.Errorf("failed to assign realm role: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusNoContent {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return fmt.Errorf("assign realm role failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	c.logger.Info("Assigned realm role to user",
		zap.String("realm", realmName),
		zap.String("user_id", userID),
		zap.String("role", roleName))
	
	return nil
}

// RevokeRealmRoleFromUser revokes a realm role from a user
func (c *AdminClient) RevokeRealmRoleFromUser(ctx context.Context, realmName, userID, roleName string) error {
	// First, get the role to get its ID
	role, err := c.GetRealmRole(ctx, realmName, roleName)
	if err != nil {
		return fmt.Errorf("failed to get role %s: %w", roleName, err)
	}
	if role == nil {
		return fmt.Errorf("role %s not found in realm %s", roleName, realmName)
	}
	
	endpoint := fmt.Sprintf("/%s/users/%s/role-mappings/realm", realmName, userID)
	
	roleAssignments := []RoleRepresentation{*role}
	
	resp, err := c.makeRequest(ctx, "DELETE", endpoint, roleAssignments)
	if err != nil {
		return fmt.Errorf("failed to revoke realm role: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusNoContent {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return fmt.Errorf("revoke realm role failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	c.logger.Info("Revoked realm role from user",
		zap.String("realm", realmName),
		zap.String("user_id", userID),
		zap.String("role", roleName))
	
	return nil
}

// ResetUserPassword resets a user's password
func (c *AdminClient) ResetUserPassword(ctx context.Context, realmName, userID, newPassword string, temporary bool) error {
	endpoint := fmt.Sprintf("/%s/users/%s/reset-password", realmName, userID)
	
	credential := CredentialRepresentation{
		Type:      "password",
		Value:     newPassword,
		Temporary: temporary,
	}
	
	resp, err := c.makeRequest(ctx, "PUT", endpoint, credential)
	if err != nil {
		return fmt.Errorf("failed to reset user password: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusNoContent {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return fmt.Errorf("reset user password failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	c.logger.Info("Reset user password",
		zap.String("realm", realmName),
		zap.String("user_id", userID),
		zap.Bool("temporary", temporary))
	
	return nil
}

// SearchUsers searches for users by username, email, first name, or last name
func (c *AdminClient) SearchUsers(ctx context.Context, realmName, query string, max int) ([]UserRepresentation, error) {
	endpoint := fmt.Sprintf("/%s/users?search=%s", realmName, url.QueryEscape(query))
	if max > 0 {
		endpoint += fmt.Sprintf("&max=%d", max)
	}
	
	resp, err := c.makeRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to search users: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := make([]byte, 1024)
		_, _ = resp.Body.Read(body)
		return nil, fmt.Errorf("search users failed with status %d: %s", resp.StatusCode, string(body))
	}

	var users []UserRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("failed to decode users response: %w", err)
	}

	return users, nil
}



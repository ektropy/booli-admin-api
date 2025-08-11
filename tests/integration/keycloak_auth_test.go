package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/booli/booli-admin-api/internal/auth"
	"github.com/booli/booli-admin-api/internal/constants"
	"github.com/booli/booli-admin-api/tests/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

type KeycloakAuthTestSuite struct {
	BaseIntegrationTestSuite

	adminToken       string
	mspAdminToken    string
	regularUserToken string

	oidcService *auth.OIDCService
	logger      *zap.Logger
}

func (suite *KeycloakAuthTestSuite) SetupTest() {
	suite.logger, _ = zap.NewDevelopment()

	keycloakURL := fmt.Sprintf("http://%s:%s", suite.keycloakHost, suite.keycloakPort)

	suite.oidcService = auth.NewOIDCService(suite.logger)

	err := helpers.SetupTestOIDCProviders(
		suite.oidcService,
		keycloakURL,
		fmt.Sprintf("http://%s:%s/auth/callback", suite.backendHost, suite.backendPort),
		suite.logger)
	if err != nil {
		suite.T().Fatalf("Failed to setup OIDC providers: %v", err)
	}

	suite.authenticateUsers()
}

func (suite *KeycloakAuthTestSuite) authenticateUsers() {
	suite.adminToken = suite.AuthenticateUser(
		suite.Config.KeycloakMasterRealm,
		"admin-cli", "",
		suite.Config.KeycloakAdminUser,
		suite.Config.KeycloakAdminPassword)

	suite.mspAdminToken = suite.AuthenticateUser(
		suite.Config.KeycloakMSPRealm,
		suite.Config.KeycloakClientID,
		suite.Config.KeycloakClientSecret,
		"msp-admin", "admin123")

	suite.regularUserToken = suite.AuthenticateUser(
		suite.Config.KeycloakMSPRealm,
		suite.Config.KeycloakClientID,
		suite.Config.KeycloakClientSecret,
		"test-user", "test123")

	suite.T().Logf("Admin token exists: %v", suite.adminToken != "")
	suite.T().Logf("MSP Admin token exists: %v", suite.mspAdminToken != "")
	suite.T().Logf("Regular user token exists: %v", suite.regularUserToken != "")
}

func (suite *KeycloakAuthTestSuite) TestKeycloakConnectivity() {
	url := fmt.Sprintf("http://%s:%s/health/ready", suite.keycloakHost, suite.keycloakMgmtPort)
	resp, err := http.Get(url)
	require.NoError(suite.T(), err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
}

func (suite *KeycloakAuthTestSuite) TestAdminAuthentication() {
	assert.NotEmpty(suite.T(), suite.adminToken, "Admin token should not be empty")
}

func (suite *KeycloakAuthTestSuite) TestMSPAdminAuthentication() {
	assert.NotEmpty(suite.T(), suite.mspAdminToken, "MSP Admin token should not be empty")
}

func (suite *KeycloakAuthTestSuite) TestRegularUserAuthentication() {
	assert.NotEmpty(suite.T(), suite.regularUserToken, "Regular user token should not be empty")
}

func (suite *KeycloakAuthTestSuite) TestTokenValidation() {
	if suite.mspAdminToken == "" {
		suite.T().Skip("MSP Admin token not available")
	}

	claims, err := suite.oidcService.ValidateToken(context.Background(), "keycloak", suite.mspAdminToken)
	require.NoError(suite.T(), err)
	assert.NotNil(suite.T(), claims, "Token claims should not be nil")
}

func (suite *KeycloakAuthTestSuite) TestTokenInfo() {
	if suite.mspAdminToken == "" {
		suite.T().Skip("MSP Admin token not available")
	}

	claims, err := suite.oidcService.ValidateToken(context.Background(), "keycloak", suite.mspAdminToken)
	require.NoError(suite.T(), err)
	assert.NotNil(suite.T(), claims, "Token claims should not be nil")
	assert.NotEmpty(suite.T(), claims.Subject, "Token subject should not be empty")
}

func (suite *KeycloakAuthTestSuite) TestUnauthorizedAccess() {
	resp, err := suite.MakeRequest("GET", constants.PathAdminTenants, nil, nil)
	require.NoError(suite.T(), err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(suite.T(), http.StatusUnauthorized, resp.StatusCode)
}

func (suite *KeycloakAuthTestSuite) TestAuthorizedAccess() {
	if suite.mspAdminToken == "" {
		suite.T().Skip("MSP Admin token not available")
	}

	resp, err := suite.MakeRequest("GET", constants.PathAdminTenants, map[string]string{
		"Authorization":   "Bearer " + suite.mspAdminToken,
		"X-Auth-Provider": "keycloak",
	}, nil)
	require.NoError(suite.T(), err)
	defer func() { _ = resp.Body.Close() }()

	assert.NotEqual(suite.T(), http.StatusUnauthorized, resp.StatusCode,
		"MSP admin should be authorized to access admin endpoints")
	assert.NotEqual(suite.T(), http.StatusForbidden, resp.StatusCode,
		"MSP admin should have permission to access admin endpoints")
}

func (suite *KeycloakAuthTestSuite) TestInvalidToken() {
	invalidToken := "invalid.jwt.token"

	resp, err := suite.MakeRequest("GET", constants.PathAdminTenants, map[string]string{
		"Authorization":   "Bearer " + invalidToken,
		"X-Auth-Provider": "keycloak",
	}, nil)
	require.NoError(suite.T(), err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(suite.T(), http.StatusUnauthorized, resp.StatusCode)
}

func (suite *KeycloakAuthTestSuite) TestExpiredToken() {
	expiredToken := "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJhYkJfX0dDVzNmTWNRdlBBdjJhQzZXeXhhc2tZYXlLdENPdlV4b2hYMTdJIn0.expired"

	resp, err := suite.MakeRequest("GET", constants.PathAdminTenants, map[string]string{
		"Authorization":   "Bearer " + expiredToken,
		"X-Auth-Provider": "keycloak",
	}, nil)
	require.NoError(suite.T(), err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(suite.T(), http.StatusUnauthorized, resp.StatusCode)
}

func (suite *KeycloakAuthTestSuite) TestRealmAccess() {
	if suite.mspAdminToken == "" {
		suite.T().Skip("MSP Admin token not available")
	}

	claims, err := suite.oidcService.ValidateToken(context.Background(), "keycloak", suite.mspAdminToken)
	require.NoError(suite.T(), err)

	assert.Contains(suite.T(), claims.RealmAccess.Roles, "msp-admin")
}

func (suite *KeycloakAuthTestSuite) TestRoleBasedAccess() {
	if suite.regularUserToken == "" {
		suite.T().Skip("Regular user token not available")
	}

	resp, err := suite.MakeRequest("GET", constants.PathAdminTenants, map[string]string{
		"Authorization":   "Bearer " + suite.regularUserToken,
		"X-Auth-Provider": "keycloak",
	}, nil)
	require.NoError(suite.T(), err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(suite.T(), http.StatusForbidden, resp.StatusCode)
}

func (suite *KeycloakAuthTestSuite) TestProviderValidation() {
	if suite.mspAdminToken == "" {
		suite.T().Skip("MSP Admin token not available")
	}

	resp, err := suite.MakeRequest("GET", constants.PathAdminTenants, map[string]string{
		"Authorization":   "Bearer " + suite.mspAdminToken,
		"X-Auth-Provider": "invalid-provider",
	}, nil)
	require.NoError(suite.T(), err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(suite.T(), http.StatusUnauthorized, resp.StatusCode)
}

func (suite *KeycloakAuthTestSuite) TestConcurrentTokenValidation() {
	if suite.mspAdminToken == "" {
		suite.T().Skip("MSP Admin token not available")
	}

	type result struct {
		valid bool
		err   error
	}
	results := make(chan result, 10)

	for i := 0; i < 10; i++ {
		go func() {
			claims, err := suite.oidcService.ValidateToken(context.Background(), "keycloak", suite.mspAdminToken)
			results <- result{valid: claims != nil && err == nil, err: err}
		}()
	}

	validCount := 0
	for i := 0; i < 10; i++ {
		select {
		case res := <-results:
			require.NoError(suite.T(), res.err)
			if res.valid {
				validCount++
			}
		case <-time.After(5 * time.Second):
			suite.T().Fatal("Timeout waiting for concurrent validation")
		}
	}

	assert.Equal(suite.T(), 10, validCount, "All token validations should succeed")
}

func (suite *KeycloakAuthTestSuite) TestTokenRefresh() {
	refreshToken := suite.getRefreshToken("admin", "admin123")
	if refreshToken == "" {
		suite.T().Skip("Refresh token not available")
	}

	newToken := suite.refreshAccessToken(refreshToken)
	assert.NotEmpty(suite.T(), newToken, "Refreshed token should not be empty")
	assert.NotEqual(suite.T(), suite.mspAdminToken, newToken, "Refreshed token should be different")
}

func (suite *KeycloakAuthTestSuite) getRefreshToken(username, password string) string {
	url := fmt.Sprintf("http://%s:%s/realms/%s/protocol/openid-connect/token",
		suite.keycloakHost, suite.keycloakPort, suite.Config.KeycloakMSPRealm)

	data := fmt.Sprintf("grant_type=password&client_id=%s&client_secret=%s&username=%s&password=%s",
		suite.Config.KeycloakClientID, suite.Config.KeycloakClientSecret, username, password)

	resp, err := http.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data))
	if err != nil {
		suite.T().Logf("Failed to get refresh token: %v", err)
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		suite.T().Logf("Failed to get refresh token, status: %d", resp.StatusCode)
		return ""
	}

	var tokenResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		suite.T().Logf("Failed to decode token response: %v", err)
		return ""
	}

	if refreshToken, ok := tokenResp["refresh_token"].(string); ok {
		return refreshToken
	}

	return ""
}

func (suite *KeycloakAuthTestSuite) refreshAccessToken(refreshToken string) string {
	url := fmt.Sprintf("http://%s:%s/realms/%s/protocol/openid-connect/token",
		suite.keycloakHost, suite.keycloakPort, suite.Config.KeycloakMSPRealm)

	data := fmt.Sprintf("grant_type=refresh_token&client_id=%s&client_secret=%s&refresh_token=%s",
		suite.Config.KeycloakClientID, suite.Config.KeycloakClientSecret, refreshToken)

	resp, err := http.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data))
	if err != nil {
		suite.T().Logf("Failed to refresh token: %v", err)
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		suite.T().Logf("Failed to refresh token, status: %d", resp.StatusCode)
		return ""
	}

	var tokenResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		suite.T().Logf("Failed to decode refresh response: %v", err)
		return ""
	}

	if accessToken, ok := tokenResp["access_token"].(string); ok {
		return accessToken
	}

	return ""
}

func TestKeycloakAuthTestSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}
	suite.Run(t, new(KeycloakAuthTestSuite))
}

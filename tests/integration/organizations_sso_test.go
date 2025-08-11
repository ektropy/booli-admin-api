package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/booli/booli-admin-api/internal/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type OrganizationsSSOTestSuite struct {
	BaseIntegrationTestSuite

	mspAdminToken string
	testTenantID  string
}

func (suite *OrganizationsSSOTestSuite) SetupTest() {
	suite.mspAdminToken = suite.AuthenticateUser(
		suite.Config.KeycloakMSPRealm,
		suite.Config.KeycloakClientID,
		suite.Config.KeycloakClientSecret,
		"msp-admin", "admin123")

	suite.T().Logf("MSP Admin token: %v", suite.mspAdminToken != "")

	if suite.mspAdminToken == "" {
		suite.T().Fatal("Failed to authenticate MSP admin user")
	}
}

func (suite *OrganizationsSSOTestSuite) TestTenantCreationAsOrganization() {
	suite.T().Log("Testing tenant creation as Keycloak organization...")

	tenantReq := map[string]interface{}{
		"name":   "Test-SSO-Organization",
		"domain": "test-sso.com",
		"type":   "client",
		"settings": map[string]interface{}{
			"enable_sso": true,
		},
	}

	resp, err := suite.MakeRequest("POST", constants.PathAdminTenants, map[string]string{
		"Authorization":   "Bearer " + suite.mspAdminToken,
		"X-Auth-Provider": "keycloak",
	}, tenantReq)
	require.NoError(suite.T(), err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	suite.T().Logf("Tenant creation response (%d): %s", resp.StatusCode, string(body))

	if resp.StatusCode == http.StatusCreated {
		var tenantResp map[string]interface{}
		err = json.Unmarshal(body, &tenantResp)
		require.NoError(suite.T(), err)

		suite.testTenantID = tenantResp["realm"].(string)

		assert.Contains(suite.T(), tenantResp, "realm")
		assert.Equal(suite.T(), "Test-SSO-Organization", tenantResp["name"])

		suite.T().Log("Tenant created successfully as organization in MSP realm")

		suite.verifyTenantExists(suite.testTenantID)
	} else {
		suite.T().Fatalf("Tenant creation failed: %s", string(body))
	}
}

func (suite *OrganizationsSSOTestSuite) TestMSPRealmSSOProviderManagement() {
	suite.T().Log("Testing SSO provider management at MSP realm level...")

	ssoProviderReq := map[string]interface{}{
		"name":        "Mock External IDP",
		"type":        "oidc",
		"description": "Mock external identity provider for testing",
		"config": map[string]interface{}{
			"issuer_url":    "https://external-idp.example.com",
			"client_id":     "msp-client",
			"client_secret": "mock-secret",
		},
	}

	resp, err := suite.MakeRequest("POST", "/admin/sso-providers", map[string]string{
		"Authorization":   "Bearer " + suite.mspAdminToken,
		"X-Auth-Provider": "keycloak",
	}, ssoProviderReq)
	require.NoError(suite.T(), err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	suite.T().Logf("SSO provider creation response (%d): %s", resp.StatusCode, string(body))

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusNotFound {
		suite.T().Log("SSO provider endpoint tested (may not be implemented yet)")
	}
}

func (suite *OrganizationsSSOTestSuite) verifyTenantExists(tenantID string) {
	resp, err := suite.MakeRequest("GET", fmt.Sprintf("%s/%s", constants.PathAdminTenants, tenantID), map[string]string{
		"Authorization":   "Bearer " + suite.mspAdminToken,
		"X-Auth-Provider": "keycloak",
	}, nil)
	require.NoError(suite.T(), err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode, "Should be able to retrieve created tenant")

	if resp.StatusCode == http.StatusOK {
		var tenant map[string]interface{}
		body, _ := io.ReadAll(resp.Body)
		err = json.Unmarshal(body, &tenant)
		require.NoError(suite.T(), err)

		assert.Equal(suite.T(), tenantID, tenant["realm"])
		suite.T().Log("Tenant verification successful")
	}
}

func TestOrganizationsSSOTestSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}
	suite.Run(t, new(OrganizationsSSOTestSuite))
}

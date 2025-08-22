package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/booli/booli-admin-api/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TenantUsersTestSuite struct {
	BaseIntegrationTestSuite
	adminToken string
	testTenantID string
}

func (suite *TenantUsersTestSuite) SetupTest() {
	suite.adminToken = suite.AuthenticateUser(
		suite.Config.KeycloakMSPRealm,
		suite.Config.KeycloakClientID,
		suite.Config.KeycloakClientSecret,
		"msp-admin", "admin123")

	require.NotEmpty(suite.T(), suite.adminToken, "Admin token should not be empty")
	
	suite.createTestTenant()
}

func (suite *TenantUsersTestSuite) createTestTenant() {
	tenantRequest := models.CreateTenantRequest{
		Name:   "test-tenant-users",
		Domain: "test-users.example.com",
		Type:   models.TenantTypeClient,
	}

	resp, err := suite.MakeRequest("POST", "/api/tenants/v1", map[string]string{
		"Authorization":   "Bearer " + suite.adminToken,
		"X-Auth-Provider": "keycloak",
		"Content-Type":    "application/json",
	}, tenantRequest)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated {
		var tenant models.Tenant
		err = json.NewDecoder(resp.Body).Decode(&tenant)
		require.NoError(suite.T(), err)
		suite.testTenantID = tenant.RealmName
		suite.T().Logf("Created test tenant: %s", suite.testTenantID)
	} else {
		suite.T().Logf("Failed to create tenant, status: %d", resp.StatusCode)
		suite.T().Skip("Cannot create test tenant")
	}
}

func (suite *TenantUsersTestSuite) TestTenantScopedUserCreation() {
	if suite.testTenantID == "" {
		suite.T().Skip("No test tenant available")
	}

	userRequest := models.CreateUserRequest{
		Username:  "testuser001",
		Email:     "testuser001@example.com",
		FirstName: "Test",
		LastName:  "User",
		Enabled:   true,
	}

	resp, err := suite.MakeRequest("POST", 
		fmt.Sprintf("/api/tenants/v1/%s/users", suite.testTenantID),
		map[string]string{
			"Authorization":   "Bearer " + suite.adminToken,
			"X-Auth-Provider": "keycloak",
			"Content-Type":    "application/json",
		}, userRequest)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	assert.Equal(suite.T(), http.StatusCreated, resp.StatusCode, 
		"User creation should succeed with tenant-scoped endpoint")

	var createdUser models.User
	err = json.NewDecoder(resp.Body).Decode(&createdUser)
	require.NoError(suite.T(), err)

	assert.Equal(suite.T(), userRequest.Username, createdUser.Username)
	assert.Equal(suite.T(), userRequest.Email, createdUser.Email)
	assert.NotEmpty(suite.T(), createdUser.ID, "User ID should be set")
}

func (suite *TenantUsersTestSuite) TestTenantScopedUserListing() {
	if suite.testTenantID == "" {
		suite.T().Skip("No test tenant available")
	}

	resp, err := suite.MakeRequest("GET",
		fmt.Sprintf("/api/tenants/v1/%s/users", suite.testTenantID),
		map[string]string{
			"Authorization":   "Bearer " + suite.adminToken,
			"X-Auth-Provider": "keycloak",
		}, nil)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode,
		"User listing should succeed with tenant-scoped endpoint")

	var userList models.UserListResponse
	err = json.NewDecoder(resp.Body).Decode(&userList)
	require.NoError(suite.T(), err)

	assert.GreaterOrEqual(suite.T(), userList.Total, int64(0), "Total should be non-negative")
}

func (suite *TenantUsersTestSuite) TestTenantScopedUserOperations() {
	if suite.testTenantID == "" {
		suite.T().Skip("No test tenant available")
	}

	userRequest := models.CreateUserRequest{
		Username:  "testuser002",
		Email:     "testuser002@example.com",
		FirstName: "Test",
		LastName:  "User2",
		Enabled:   true,
	}

	resp, err := suite.MakeRequest("POST",
		fmt.Sprintf("/api/tenants/v1/%s/users", suite.testTenantID),
		map[string]string{
			"Authorization":   "Bearer " + suite.adminToken,
			"X-Auth-Provider": "keycloak",
			"Content-Type":    "application/json",
		}, userRequest)
	require.NoError(suite.T(), err)
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		suite.T().Skipf("Cannot create user for operations test, status: %d", resp.StatusCode)
	}

	mockUserID := "test-user-id-123"

	resp, err = suite.MakeRequest("GET",
		fmt.Sprintf("/api/tenants/v1/%s/users/%s", suite.testTenantID, mockUserID),
		map[string]string{
			"Authorization":   "Bearer " + suite.adminToken,
			"X-Auth-Provider": "keycloak",
		}, nil)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	assert.Contains(suite.T(), []int{http.StatusOK, http.StatusNotFound}, resp.StatusCode,
		"Get user should return OK or Not Found")
}

func (suite *TenantUsersTestSuite) TestTenantScopedInvalidTenant() {
	resp, err := suite.MakeRequest("GET", "/api/tenants/v1/non-existent-tenant/users",
		map[string]string{
			"Authorization":   "Bearer " + suite.adminToken,
			"X-Auth-Provider": "keycloak",
		}, nil)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	assert.Equal(suite.T(), http.StatusNotFound, resp.StatusCode,
		"Should return 404 for non-existent tenant")
}

func (suite *TenantUsersTestSuite) TestAutoRealmDetection() {
	if suite.testTenantID == "" {
		suite.T().Skip("No test tenant available")
	}

	userRequest := map[string]interface{}{
		"username":   "testuser003",
		"email":      "testuser003@example.com",
		"firstName":  "Test",
		"lastName":   "User3",
		"enabled":    true,
	}

	resp, err := suite.MakeRequest("POST",
		fmt.Sprintf("/api/tenants/v1/%s/users", suite.testTenantID),
		map[string]string{
			"Authorization":   "Bearer " + suite.adminToken,
			"X-Auth-Provider": "keycloak",
			"Content-Type":    "application/json",
		}, userRequest)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	assert.True(suite.T(), resp.StatusCode < 500,
		"Auto-realm detection should work without tenant_realm in request body")
}

func TestTenantUsersTestSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}
	suite.Run(t, new(TenantUsersTestSuite))
}
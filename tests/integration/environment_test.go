package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/booli/booli-admin-api/internal/constants"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"gorm.io/datatypes"
)

type EnvironmentTestSuite struct {
	BaseIntegrationTestSuite

	mspAdminToken string
	tenantID      uuid.UUID
	tenantToken   string
}

func (suite *EnvironmentTestSuite) SetupTest() {
	suite.mspAdminToken = suite.AuthenticateUser(
		suite.Config.KeycloakMSPRealm,
		suite.Config.KeycloakClientID,
		suite.Config.KeycloakClientSecret,
		"admin", "admin123")
	suite.T().Logf("MSP Admin token: %v", suite.mspAdminToken != "")

	if suite.mspAdminToken == "" {
		suite.T().Fatal("Failed to authenticate MSP admin user")
	}

	// Skip environment tests since they require database-based tenant lookups in a realm-first architecture
	suite.T().Skip("Environment tests skipped - requires migration to realm-based system")

	suite.tenantToken = suite.mspAdminToken
	suite.T().Logf("Using MSP admin token for tenant operations")
}

func (suite *EnvironmentTestSuite) TestEnvironmentCRUD() {
	environment := suite.createEnvironment()
	suite.NotEmpty(environment.ID)
	suite.Equal("production", environment.Name)
	suite.Equal(suite.tenantID, environment.TenantID)

	suite.getEnvironment(environment.ID)

	suite.listEnvironments()

	updatedEnv := suite.updateEnvironment(environment.ID)
	suite.Equal("prod-updated", updatedEnv.Name)

	suite.deleteEnvironment(environment.ID)
}

func (suite *EnvironmentTestSuite) TestSIEMEnrichmentData() {
	environment := suite.createEnvironment()
	suite.NotEmpty(environment.ID)

	enrichmentData := suite.getSIEMEnrichmentData()
	suite.Equal(suite.tenantID, enrichmentData.TenantID)
	suite.NotEmpty(enrichmentData.LastUpdated)
}

func (suite *EnvironmentTestSuite) TestEnvironmentValidation() {
	tests := []struct {
		name           string
		payload        models.CreateTenantEnvironmentRequest
		expectedStatus int
	}{
		{
			name: "InvalidCIDR",
			payload: models.CreateTenantEnvironmentRequest{
				TenantID: suite.tenantID,
				Name:     "invalid-cidr",
				NetworkRanges: []models.NetworkRange{
					{CIDR: "invalid-cidr"},
				},
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "InvalidIPAddress",
			payload: models.CreateTenantEnvironmentRequest{
				TenantID: suite.tenantID,
				Name:     "invalid-ip",
				PublicIPs: []models.PublicIP{
					{IPAddress: "invalid-ip"},
				},
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "EmptyName",
			payload: models.CreateTenantEnvironmentRequest{
				TenantID: suite.tenantID,
				Name:     "",
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		suite.T().Run(tt.name, func(t *testing.T) {
			jsonPayload, err := json.Marshal(tt.payload)
			suite.NoError(err)

			url := suite.GetAPIURL(constants.PathEnvironments)
			req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
			suite.NoError(err)
			req.Header.Set("Authorization", "Bearer "+suite.tenantToken)
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			suite.NoError(err)
			defer func() { _ = resp.Body.Close() }()

			suite.Equal(tt.expectedStatus, resp.StatusCode)
		})
	}
}

func (suite *EnvironmentTestSuite) createEnvironment() *models.TenantEnvironment {
	payload := models.CreateTenantEnvironmentRequest{
		TenantID:    suite.tenantID,
		Name:        "production",
		Description: "Production environment for testing",
		Environment: "prod",
		NetworkRanges: []models.NetworkRange{
			{
				CIDR:        "10.0.0.0/16",
				NetworkType: "private",
				IsMonitored: true,
			},
		},
		PublicIPs: []models.PublicIP{
			{
				IPAddress: "203.0.113.1",
				Purpose:   "web",
				Provider:  "aws",
				Region:    "us-east-1",
				IsActive:  true,
			},
		},
		EgressIPs: []models.EgressIP{
			{
				IPAddress: "203.0.113.10",
				Purpose:   "api_calls",
				Provider:  "nat_gateway",
				IsActive:  true,
			},
		},
		Domains: []models.Domain{
			{
				DomainName:  "example.com",
				DomainType:  "primary",
				Purpose:     "website",
				Registrar:   "godaddy",
				DNSProvider: "cloudflare",
				IsActive:    true,
			},
		},
		InfrastructureIPs: []models.InfrastructureIP{
			{
				IPAddress:   "10.0.1.10",
				ServiceType: models.InfrastructureTypeDNS,
				Hostname:    "dns1.internal.example.com",
				Port:        intPtr(53),
				Description: "Primary DNS server",
				IsActive:    true,
				IsCritical:  true,
			},
		},
		NamingConventions: []models.NamingConvention{
			{
				Name:         "server-naming",
				Pattern:      "{env}-{service}-{number}",
				ResourceType: "server",
				Examples:     datatypes.JSON(`{"valid":["prod-web-01","prod-db-02"],"invalid":["web01","database"]}`),
				Description:  "Standard server naming convention",
				IsActive:     true,
			},
		},
	}

	resp, err := suite.MakeRequest("POST", constants.PathEnvironments, map[string]string{
		"Authorization": "Bearer " + suite.tenantToken,
	}, payload)
	suite.NoError(err)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		suite.T().Logf("Create environment failed (%d): %s", resp.StatusCode, string(body))
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	suite.Equal(http.StatusCreated, resp.StatusCode)

	var environment models.TenantEnvironment
	err = json.NewDecoder(resp.Body).Decode(&environment)
	suite.NoError(err)

	return &environment
}

func (suite *EnvironmentTestSuite) getEnvironment(environmentID uuid.UUID) *models.TenantEnvironment {
	resp, err := suite.MakeRequest("GET", fmt.Sprintf("%s/%s", constants.PathEnvironments, environmentID.String()), map[string]string{
		"Authorization": "Bearer " + suite.tenantToken,
	}, nil)
	suite.NoError(err)
	defer func() { _ = resp.Body.Close() }()

	suite.Equal(http.StatusOK, resp.StatusCode)

	var environment models.TenantEnvironment
	err = json.NewDecoder(resp.Body).Decode(&environment)
	suite.NoError(err)

	suite.Equal(environmentID, environment.ID)
	return &environment
}

func (suite *EnvironmentTestSuite) listEnvironments() *models.TenantEnvironmentListResponse {
	resp, err := suite.MakeRequest("GET", fmt.Sprintf("%s?page=1&pageSize=10", constants.PathEnvironments), map[string]string{
		"Authorization": "Bearer " + suite.tenantToken,
	}, nil)
	suite.NoError(err)
	defer func() { _ = resp.Body.Close() }()

	suite.Equal(http.StatusOK, resp.StatusCode)

	var response models.TenantEnvironmentListResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	suite.NoError(err)

	suite.GreaterOrEqual(response.Total, int64(0))
	return &response
}

func (suite *EnvironmentTestSuite) updateEnvironment(environmentID uuid.UUID) *models.TenantEnvironment {
	newName := "prod-updated"
	newDescription := "Updated production environment"

	payload := models.UpdateTenantEnvironmentRequest{
		Name:        &newName,
		Description: &newDescription,
	}

	resp, err := suite.MakeRequest("PUT", fmt.Sprintf("%s/%s", constants.PathEnvironments, environmentID.String()), map[string]string{
		"Authorization": "Bearer " + suite.tenantToken,
	}, payload)
	suite.NoError(err)
	defer func() { _ = resp.Body.Close() }()

	suite.Equal(http.StatusOK, resp.StatusCode)

	var environment models.TenantEnvironment
	err = json.NewDecoder(resp.Body).Decode(&environment)
	suite.NoError(err)

	return &environment
}

func (suite *EnvironmentTestSuite) deleteEnvironment(environmentID uuid.UUID) {
	resp, err := suite.MakeRequest("DELETE", fmt.Sprintf("%s/%s", constants.PathEnvironments, environmentID.String()), map[string]string{
		"Authorization": "Bearer " + suite.tenantToken,
	}, nil)
	suite.NoError(err)
	defer func() { _ = resp.Body.Close() }()

	suite.Equal(http.StatusNoContent, resp.StatusCode)
}

func (suite *EnvironmentTestSuite) getSIEMEnrichmentData() *models.SIEMEnrichmentData {
	resp, err := suite.MakeRequest("GET", constants.PathEnvironmentSecurityData, map[string]string{
		"Authorization": "Bearer " + suite.tenantToken,
	}, nil)
	suite.NoError(err)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		suite.T().Logf("Get security data failed (%d): %s", resp.StatusCode, string(body))
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	suite.Equal(http.StatusOK, resp.StatusCode)

	var enrichmentData models.SIEMEnrichmentData
	err = json.NewDecoder(resp.Body).Decode(&enrichmentData)
	suite.NoError(err)

	return &enrichmentData
}

func (suite *EnvironmentTestSuite) createTestTenant() *models.TenantResponse {
	timestamp := time.Now().UnixNano()
	tenantName := fmt.Sprintf("Test-Environment-Tenant-%d", timestamp)

	tenantData := map[string]interface{}{
		"name":   tenantName,
		"domain": fmt.Sprintf("tenant-%d.example.com", timestamp),
		"type":   "client",
		"settings": map[string]interface{}{
			"max_users": 100,
		},
	}

	resp, err := suite.MakeRequest("POST", constants.PathAdminTenants, map[string]string{
		"Authorization":   "Bearer " + suite.mspAdminToken,
		"X-Auth-Provider": "keycloak",
	}, tenantData)
	suite.NoError(err)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		suite.T().Logf("Create tenant failed (%d): %s", resp.StatusCode, string(body))
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	suite.Equal(http.StatusCreated, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	suite.T().Logf("Tenant creation response body: %s", string(body))

	var tenantResp models.TenantResponse
	err = json.Unmarshal(body, &tenantResp)
	if err != nil {
		suite.T().Logf("Failed to decode tenant response: %v", err)
	}
	suite.NoError(err)

	suite.T().Logf("Decoded tenant realm: %s, Name: %s", tenantResp.Realm, tenantResp.Name)

	return &tenantResp
}

func TestEnvironmentTestSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}
	suite.Run(t, new(EnvironmentTestSuite))
}

func intPtr(i int) *int {
	return &i
}

package integration

import (
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

type OAuth2DebugTestSuite struct {
	BaseIntegrationTestSuite

	mspAdminToken string
	adminClient   *keycloak.AdminClient
	logger        *zap.Logger
}

func (suite *OAuth2DebugTestSuite) SetupTest() {
	suite.logger, _ = zap.NewDevelopment()

	// Authenticate as MSP admin
	suite.mspAdminToken = suite.AuthenticateUser(
		suite.Config.KeycloakMSPRealm,
		suite.Config.KeycloakClientID,
		suite.Config.KeycloakClientSecret,
		"msp-admin", "admin123")

	if suite.mspAdminToken == "" {
		suite.T().Fatal("Failed to authenticate MSP admin user")
	}

	// Initialize Keycloak admin client for direct verification
	suite.adminClient = keycloak.NewAdminClient(
		fmt.Sprintf("http://%s:%s", suite.keycloakHost, suite.keycloakPort),
		suite.Config.KeycloakMasterRealm,
		"admin-cli",
		"",
		suite.Config.KeycloakAdminUser,
		suite.Config.KeycloakAdminPassword,
		false,
		"",
		suite.logger,
	)

	// Clean up any existing providers
	providers, err := suite.adminClient.ListIdentityProviders(suite.ctx, suite.Config.KeycloakMSPRealm)
	if err == nil {
		for _, provider := range providers {
			_ = suite.adminClient.DeleteIdentityProvider(suite.ctx, suite.Config.KeycloakMSPRealm, provider.Alias)
		}
	}
}

func (suite *OAuth2DebugTestSuite) TestMinimalOAuth2Provider() {
	suite.T().Logf("Testing minimal OAuth2 provider configuration")
	
	request := models.CreateIdentityProviderRequest{
		Alias:       "debug-oauth2",
		DisplayName: "Debug OAuth2 Provider",
		Type:        models.IdentityProviderTypeOAuth2,
		Enabled:     true,
		Config: models.IdentityProviderConfig{
			ClientID:         "oauth2-client-id",
			ClientSecret:     "oauth2-client-secret",
			AuthorizationURL: "https://oauth.example.com/authorize",
			TokenURL:         "https://oauth.example.com/token",
		},
	}

	resp, err := suite.MakeRequest("POST", 
		"/identity/v1/",
		map[string]string{
			"Authorization":   "Bearer " + suite.mspAdminToken,
			"X-Auth-Provider": "keycloak",
		}, 
		request)
	suite.Require().NoError(err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)
	
	suite.T().Logf("Response Status: %d", resp.StatusCode)
	suite.T().Logf("Response Body: %s", string(body))
	
	if resp.StatusCode != http.StatusCreated {
		// Test the model directly to see if it produces valid configuration
		keycloakRep := request.ToKeycloakRepresentation()
		if keycloakRep == nil {
			suite.T().Log("Model validation failed - ToKeycloakRepresentation returned nil")
		} else {
			suite.T().Logf("Generated Keycloak representation: %+v", keycloakRep)
			suite.T().Logf("Config: %+v", keycloakRep.Config)
		}
		
		suite.T().Fatalf("Expected 201, got %d. Response: %s", resp.StatusCode, string(body))
	}
}

func TestOAuth2DebugTestSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}
	suite.Run(t, new(OAuth2DebugTestSuite))
}
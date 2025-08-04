package initialization

import (
	"fmt"
	"os"
	"testing"

	"github.com/booli/booli-admin-api/internal/auth"
	"github.com/booli/booli-admin-api/internal/config"
	"github.com/booli/booli-admin-api/internal/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestParseConfigFromEnv(t *testing.T) {

	originalEnv := make(map[string]string)
	envVars := []string{
		"KEYCLOAK_MSP_REALM",
		"KEYCLOAK_MSP_REALM_ENABLED",
		"KEYCLOAK_MSP_REALM_DISPLAY_NAME",
		"KEYCLOAK_MSP_CLIENT_ID",
		"KEYCLOAK_MSP_CLIENT_SECRET",
	}

	for _, env := range envVars {
		originalEnv[env] = os.Getenv(env)
		os.Unsetenv(env)
	}

	defer func() {
		for _, env := range envVars {
			if val, exists := originalEnv[env]; exists {
				os.Setenv(env, val)
			} else {
				os.Unsetenv(env)
			}
		}
	}()

	t.Run("Empty environment returns default config", func(t *testing.T) {
		config, err := ParseConfigFromEnv()
		assert.NoError(t, err)
		assert.NotNil(t, config)
		assert.Len(t, config.Realms, 1)
		assert.Equal(t, "msp", config.Realms[0].Name)
		assert.Len(t, config.Clients, 1)
		assert.Equal(t, "msp-client", config.Clients[0].ClientID)
		assert.Len(t, config.Roles, 3)
		assert.Len(t, config.Users, 1)
		assert.Equal(t, "admin", config.Users[0].Username)
		assert.Len(t, config.OIDCProviders, 1)
		assert.Equal(t, "keycloak", config.OIDCProviders[0].Name)
	})

	t.Run("MSP realm configuration", func(t *testing.T) {
		os.Setenv("KEYCLOAK_MSP_REALM", "msp")
		os.Setenv("KEYCLOAK_MSP_REALM_ENABLED", "true")
		os.Setenv("KEYCLOAK_MSP_REALM_DISPLAY_NAME", "MSP Realm")
		os.Setenv("KEYCLOAK_MSP_CLIENT_ID", "msp-client")
		os.Setenv("KEYCLOAK_MSP_CLIENT_SECRET", "test-secret")

		defer func() {
			for _, env := range envVars {
				os.Unsetenv(env)
			}
		}()

		config, err := ParseConfigFromEnv()
		require.NoError(t, err)
		require.NotNil(t, config)

		assert.Len(t, config.Realms, 1)
		realm := config.Realms[0]
		assert.Equal(t, "msp", realm.Name)
		assert.Equal(t, "MSP Realm", realm.DisplayName)
		assert.True(t, realm.Enabled)

		assert.Len(t, config.Clients, 1)
		client := config.Clients[0]
		assert.Equal(t, "msp", client.RealmName)
		assert.Equal(t, "msp-client", client.ClientID)
		assert.Equal(t, "test-secret", client.Secret)
		assert.Equal(t, "booli-admin-api", client.APIAudience)

		assert.Len(t, config.Roles, 3)
		roleNames := make([]string, len(config.Roles))
		for i, role := range config.Roles {
			roleNames[i] = role.Name
			assert.Equal(t, "msp", role.RealmName)
		}
		assert.Contains(t, roleNames, "msp-admin")
		assert.Contains(t, roleNames, "msp-power")
		assert.Contains(t, roleNames, "msp-basic")
	})

	t.Run("MSP realm disabled", func(t *testing.T) {
		os.Setenv("KEYCLOAK_MSP_REALM", "msp")
		os.Setenv("KEYCLOAK_MSP_REALM_ENABLED", "false")
		os.Setenv("KEYCLOAK_MSP_CLIENT_ID", "msp-client")

		defer func() {
			for _, env := range envVars {
				os.Unsetenv(env)
			}
		}()

		config, err := ParseConfigFromEnv()
		require.NoError(t, err)
		require.NotNil(t, config)

		assert.Len(t, config.Realms, 0)
		assert.Len(t, config.Clients, 1)
		assert.Len(t, config.Roles, 3)
	})

	t.Run("Client with default realm", func(t *testing.T) {
		os.Setenv("KEYCLOAK_MSP_CLIENT_ID", "test-client")
		os.Setenv("KEYCLOAK_MSP_CLIENT_SECRET", "test-secret")

		defer func() {
			for _, env := range envVars {
				os.Unsetenv(env)
			}
		}()

		config, err := ParseConfigFromEnv()
		require.NoError(t, err)
		require.NotNil(t, config)

		assert.Len(t, config.Clients, 1)
		client := config.Clients[0]
		assert.Equal(t, "msp", client.RealmName)
		assert.Equal(t, "test-client", client.ClientID)
	})
}

func TestRealmConfig(t *testing.T) {
	config := RealmConfig{
		Name:        "test-realm",
		DisplayName: "Test Realm",
		Enabled:     true,
	}

	assert.Equal(t, "test-realm", config.Name)
	assert.Equal(t, "Test Realm", config.DisplayName)
	assert.True(t, config.Enabled)
}

func TestClientConfig(t *testing.T) {
	config := ClientConfig{
		RealmName:                 "msp",
		ClientID:                  "msp-client",
		Secret:                    "secret123",
		RedirectURIs:              []string{"https://app.example.com/callback"},
		WebOrigins:                []string{"https://app.example.com"},
		StandardFlowEnabled:       true,
		ServiceAccountsEnabled:    true,
		DirectAccessGrantsEnabled: true,
		ImplicitFlowEnabled:       false,
		PublicClient:              false,
		APIAudience:               "api-audience",
	}

	assert.Equal(t, "msp", config.RealmName)
	assert.Equal(t, "msp-client", config.ClientID)
	assert.Equal(t, "secret123", config.Secret)
	assert.True(t, config.StandardFlowEnabled)
	assert.True(t, config.ServiceAccountsEnabled)
	assert.False(t, config.ImplicitFlowEnabled)
	assert.False(t, config.PublicClient)
	assert.Equal(t, "api-audience", config.APIAudience)
}

func TestRoleConfig(t *testing.T) {
	config := RoleConfig{
		RealmName:   "msp",
		Name:        "msp-admin",
		Description: "MSP Administrator",
	}

	assert.Equal(t, "msp", config.RealmName)
	assert.Equal(t, "msp-admin", config.Name)
	assert.Equal(t, "MSP Administrator", config.Description)
}

func TestOIDCProviderConfig(t *testing.T) {
	config := OIDCProviderConfig{
		Name:         "keycloak",
		RealmName:    "msp",
		ClientID:     "msp-client",
		ClientSecret: "secret",
		CallbackURL:  "https://app.example.com/callback",
	}

	assert.Equal(t, "keycloak", config.Name)
	assert.Equal(t, "msp", config.RealmName)
	assert.Equal(t, "msp-client", config.ClientID)
	assert.Equal(t, "secret", config.ClientSecret)
	assert.Equal(t, "https://app.example.com/callback", config.CallbackURL)
}

func TestInitializationConfig(t *testing.T) {
	config := &InitializationConfig{
		Realms: []RealmConfig{
			{Name: "realm1", DisplayName: "Realm 1", Enabled: true},
			{Name: "realm2", DisplayName: "Realm 2", Enabled: false},
		},
		Clients: []ClientConfig{
			{RealmName: "realm1", ClientID: "client1"},
			{RealmName: "realm2", ClientID: "client2"},
		},
		Roles: []RoleConfig{
			{RealmName: "realm1", Name: "role1"},
			{RealmName: "realm1", Name: "role2"},
		},
		OIDCProviders: []OIDCProviderConfig{
			{Name: "provider1", RealmName: "realm1"},
		},
	}

	assert.Len(t, config.Realms, 2)
	assert.Len(t, config.Clients, 2)
	assert.Len(t, config.Roles, 2)
	assert.Len(t, config.OIDCProviders, 1)
}

func TestNewKeycloakInitializer(t *testing.T) {
	logger := zaptest.NewLogger(t)
	oidcService := auth.NewOIDCService(logger)
	cfg := &config.Config{
		Keycloak: config.KeycloakConfig{
			URL:         "https://keycloak.example.com",
			MSPRealm:    "msp",
			ClientID:    "msp-client",
			AdminUser:   "admin",
			AdminPass:   "admin-pass",
			MasterRealm: "master",
		},
	}

	initializer := NewKeycloakInitializer(nil, oidcService, cfg, logger)

	assert.NotNil(t, initializer)
	assert.Equal(t, oidcService, initializer.oidcService)
	assert.Equal(t, cfg, initializer.config)
	assert.Equal(t, logger, initializer.logger)
}

func TestGetDefaultTestConfig(t *testing.T) {
	keycloakURL := "https://keycloak.example.com"
	callbackURL := "https://app.example.com/callback"

	config := GetDefaultTestConfig(keycloakURL, callbackURL)

	require.NotNil(t, config)

	assert.Len(t, config.Realms, 1)
	realm := config.Realms[0]
	assert.Equal(t, "msp", realm.Name)
	assert.Equal(t, "MSP Realm", realm.DisplayName)
	assert.True(t, realm.Enabled)

	assert.Len(t, config.Clients, 1)
	client := config.Clients[0]
	assert.Equal(t, "msp", client.RealmName)
	assert.Equal(t, "msp-client", client.ClientID)
	assert.Equal(t, "msp-secret", client.Secret)
	assert.Equal(t, "booli-admin-api", client.APIAudience)

	assert.Len(t, config.OIDCProviders, 1)
	provider := config.OIDCProviders[0]
	assert.Equal(t, "keycloak-msp", provider.Name)
	assert.Equal(t, "msp", provider.RealmName)
	assert.Equal(t, callbackURL, provider.CallbackURL)
}

func TestGetDefaultTestConfig_DefaultCallbackURL(t *testing.T) {
	config := GetDefaultTestConfig("https://keycloak.example.com", "")

	require.NotNil(t, config)
	assert.Len(t, config.OIDCProviders, 1)

	provider := config.OIDCProviders[0]
	assert.Equal(t, "http://localhost:8081"+constants.PathAuthCallback, provider.CallbackURL)
}

func TestMSPRoleDefinitions(t *testing.T) {

	os.Setenv("KEYCLOAK_MSP_REALM", "test-realm")
	os.Setenv("KEYCLOAK_MSP_REALM_ENABLED", "true")
	os.Setenv("KEYCLOAK_MSP_CLIENT_ID", "test-client")

	defer func() {
		os.Unsetenv("KEYCLOAK_MSP_REALM")
		os.Unsetenv("KEYCLOAK_MSP_REALM_ENABLED")
		os.Unsetenv("KEYCLOAK_MSP_CLIENT_ID")
	}()

	config, err := ParseConfigFromEnv()
	require.NoError(t, err)
	require.NotNil(t, config)

	expectedRoles := map[string]string{
		"msp-admin": "MSP Administrator - Cross-organization management",
		"msp-power": "MSP Power User - Advanced MSP features",
		"msp-basic": "MSP Basic User - Standard MSP features",
	}

	assert.Len(t, config.Roles, len(expectedRoles))

	for _, role := range config.Roles {
		expectedDesc, exists := expectedRoles[role.Name]
		assert.True(t, exists, fmt.Sprintf("Unexpected role: %s", role.Name))
		assert.Equal(t, expectedDesc, role.Description)
		assert.Equal(t, "test-realm", role.RealmName)
	}
}

func TestOrganizationsArchitecture_SingleRealmConfig(t *testing.T) {

	os.Setenv("KEYCLOAK_MSP_REALM", "msp")
	os.Setenv("KEYCLOAK_MSP_REALM_ENABLED", "true")
	os.Setenv("KEYCLOAK_MSP_CLIENT_ID", "msp-client")

	defer func() {
		os.Unsetenv("KEYCLOAK_MSP_REALM")
		os.Unsetenv("KEYCLOAK_MSP_REALM_ENABLED")
		os.Unsetenv("KEYCLOAK_MSP_CLIENT_ID")
	}()

	config, err := ParseConfigFromEnv()
	require.NoError(t, err)
	require.NotNil(t, config)

	assert.Len(t, config.Realms, 1)
	assert.Equal(t, "msp", config.Realms[0].Name)

	assert.Len(t, config.Clients, 1)
	assert.Equal(t, "msp", config.Clients[0].RealmName)
	assert.Equal(t, "msp-client", config.Clients[0].ClientID)

	assert.Len(t, config.Roles, 3)
	for _, role := range config.Roles {
		assert.Equal(t, "msp", role.RealmName)
	}
}

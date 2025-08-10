package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
	"golang.org/x/oauth2"
)

func TestOIDCService_AddProvider(t *testing.T) {
	logger := zaptest.NewLogger(t)
	service := NewOIDCService(logger)

	provider := &OIDCProvider{
		Name:         "test-provider",
		IssuerURL:    "https://test.example.com",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "https://app.example.com/callback",
		Scopes:       []string{"openid", "profile", "email"},
		RealmName:    "test-realm",
	}

	t.Run("Add provider to service", func(t *testing.T) {

		service.providers["test-provider"] = provider

		retrievedProvider, err := service.GetProvider("test-provider")
		assert.NoError(t, err)
		assert.Equal(t, provider.Name, retrievedProvider.Name)
		assert.Equal(t, provider.ClientID, retrievedProvider.ClientID)
		assert.Equal(t, provider.RealmName, retrievedProvider.RealmName)
	})

	t.Run("Provider names list", func(t *testing.T) {
		names := service.GetProviderNames()
		assert.Contains(t, names, "test-provider")
	})
}

func TestOIDCService_GetProvider(t *testing.T) {
	logger := zaptest.NewLogger(t)
	service := NewOIDCService(logger)

	provider := &OIDCProvider{
		Name:      "existing-provider",
		IssuerURL: "https://existing.example.com",
		ClientID:  "existing-client",
	}

	service.providers["existing-provider"] = provider

	t.Run("Get existing provider", func(t *testing.T) {
		retrievedProvider, err := service.GetProvider("existing-provider")
		assert.NoError(t, err)
		assert.Equal(t, provider.Name, retrievedProvider.Name)
	})

	t.Run("Get non-existent provider", func(t *testing.T) {
		_, err := service.GetProvider("non-existent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "OIDC provider 'non-existent' not found")
	})
}

func TestCreateKeycloakProvider(t *testing.T) {
	tests := []struct {
		name         string
		providerName string
		baseURL      string
		realm        string
		clientID     string
		clientSecret string
		redirectURL  string
		expectedURL  string
	}{
		{
			name:         "Standard Keycloak provider",
			providerName: "keycloak",
			baseURL:      "https://auth.example.com",
			realm:        "msp-platform",
			clientID:     "msp-client",
			clientSecret: "secret123",
			redirectURL:  "https://app.example.com/callback",
			expectedURL:  "https://auth.example.com/realms/msp-platform",
		},
		{
			name:         "BaseURL with trailing slash",
			providerName: "keycloak",
			baseURL:      "https://auth.example.com/",
			realm:        "test-realm",
			clientID:     "test-client",
			clientSecret: "secret",
			redirectURL:  "https://app.example.com/callback",
			expectedURL:  "https://auth.example.com/realms/test-realm",
		},
		{
			name:         "Localhost development",
			providerName: "keycloak-dev",
			baseURL:      "http://localhost:8080",
			realm:        "master",
			clientID:     "admin-cli",
			clientSecret: "",
			redirectURL:  "http://localhost:3000/callback",
			expectedURL:  "http://localhost:8080/realms/master",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := CreateKeycloakProvider(
				tt.providerName,
				tt.baseURL,
				tt.realm,
				tt.clientID,
				tt.clientSecret,
				tt.redirectURL,
				"booli-admin-api",
				false,
				"",
			)

			assert.Equal(t, tt.providerName, provider.Name)
			assert.Equal(t, tt.expectedURL, provider.IssuerURL)
			assert.Equal(t, tt.clientID, provider.ClientID)
			assert.Equal(t, tt.clientSecret, provider.ClientSecret)
			assert.Equal(t, tt.redirectURL, provider.RedirectURL)
			assert.Equal(t, tt.realm, provider.RealmName)
			assert.False(t, provider.IsAzureAD)

			expectedScopes := []string{"openid", "profile", "email", "roles"}
			assert.Equal(t, expectedScopes, provider.Scopes)
		})
	}
}

func TestOIDCClaims_RealmAccess(t *testing.T) {
	claims := &OIDCClaims{
		Subject: "user123",
		Email:   "test@example.com",
		RealmAccess: struct {
			Roles []string `json:"roles"`
		}{
			Roles: []string{"msp-admin", "admin", "user"},
		},
	}

	assert.Equal(t, "user123", claims.Subject)
	assert.Equal(t, "test@example.com", claims.Email)
	assert.Contains(t, claims.RealmAccess.Roles, "msp-admin")
	assert.Contains(t, claims.RealmAccess.Roles, "admin")
	assert.Contains(t, claims.RealmAccess.Roles, "user")
}

func TestOIDCProvider_Configuration(t *testing.T) {
	provider := &OIDCProvider{
		Name:         "test-keycloak",
		IssuerURL:    "https://keycloak.example.com/realms/test",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "https://app.example.com/auth/callback",
		Scopes:       []string{"openid", "profile", "email", "roles"},
		RealmName:    "test",
		IsAzureAD:    false,
	}

	assert.Equal(t, "test-keycloak", provider.Name)
	assert.Equal(t, "test", provider.RealmName)
	assert.False(t, provider.IsAzureAD)
	assert.Contains(t, provider.Scopes, "openid")
	assert.Contains(t, provider.Scopes, "roles")
}

func TestOIDCService_ProviderManagement(t *testing.T) {
	logger := zaptest.NewLogger(t)
	service := NewOIDCService(logger)

	providers := []*OIDCProvider{
		{
			Name:      "keycloak-msp",
			IssuerURL: "https://auth.example.com/realms/msp-platform",
			ClientID:  "msp-client",
			RealmName: "msp-platform",
		},
		{
			Name:      "keycloak-tenant1",
			IssuerURL: "https://auth.example.com/realms/tenant1",
			ClientID:  "tenant1-client",
			RealmName: "tenant1",
		},
		{
			Name:      "azure-ad",
			IssuerURL: "https://login.microsoftonline.com/tenant-id/v2.0",
			ClientID:  "azure-client",
			IsAzureAD: true,
		},
	}

	for _, provider := range providers {
		service.providers[provider.Name] = provider
	}

	t.Run("Get all provider names", func(t *testing.T) {
		names := service.GetProviderNames()
		assert.Len(t, names, 3)
		assert.Contains(t, names, "keycloak-msp")
		assert.Contains(t, names, "keycloak-tenant1")
		assert.Contains(t, names, "azure-ad")
	})

	t.Run("Get each provider", func(t *testing.T) {
		for _, expectedProvider := range providers {
			provider, err := service.GetProvider(expectedProvider.Name)
			assert.NoError(t, err)
			assert.Equal(t, expectedProvider.Name, provider.Name)
			assert.Equal(t, expectedProvider.ClientID, provider.ClientID)
			assert.Equal(t, expectedProvider.IsAzureAD, provider.IsAzureAD)
		}
	})
}

func TestOIDCProvider_MSPPlatformConfiguration(t *testing.T) {

	provider := CreateKeycloakProvider(
		"keycloak",
		"https://keycloak.example.com",
		"msp-platform",
		"msp-platform-client",
		"platform-secret",
		"https://admin.example.com/auth/callback",
		"booli-admin-api",
		false,
		"",
	)

	assert.Equal(t, "keycloak", provider.Name)
	assert.Equal(t, "https://keycloak.example.com/realms/msp-platform", provider.IssuerURL)
	assert.Equal(t, "msp-platform-client", provider.ClientID)
	assert.Equal(t, "msp-platform", provider.RealmName)
	assert.False(t, provider.IsAzureAD)

	expectedScopes := []string{"openid", "profile", "email", "roles"}
	assert.Equal(t, expectedScopes, provider.Scopes)
}

func TestGenerateRandomState(t *testing.T) {
	state1 := generateRandomState()
	state2 := generateRandomState()

	assert.NotEqual(t, state1, state2)

	assert.NotEmpty(t, state1)
	assert.NotEmpty(t, state2)

	assert.Greater(t, len(state1), 20)
	assert.Greater(t, len(state2), 20)
}

func TestNewOIDCService(t *testing.T) {
	logger := zaptest.NewLogger(t)
	service := NewOIDCService(logger)
	
	assert.NotNil(t, service)
	assert.NotNil(t, service.providers)
	assert.Equal(t, logger, service.logger)
	assert.Empty(t, service.providers)
}

func TestCreateKeycloakMSPProvider(t *testing.T) {
	provider := CreateKeycloakMSPProvider(
		"https://keycloak.example.com",
		"msp-realm",
		"client-id",
		"client-secret",
		"https://app.example.com/callback",
		"booli-admin-api",
		true,
		"/path/to/ca.crt",
	)
	
	assert.NotNil(t, provider)
	assert.Equal(t, "keycloak-msp-realm", provider.Name)
	assert.Equal(t, "https://keycloak.example.com/realms/msp-realm", provider.IssuerURL)
	assert.Equal(t, "msp-realm", provider.RealmName)
	assert.True(t, provider.SkipTLSVerify)
	assert.Equal(t, "/path/to/ca.crt", provider.CACertPath)
	assert.False(t, provider.IsAzureAD)
}

func TestCreateAzureADProvider(t *testing.T) {
	provider := CreateAzureADProvider(
		"azure-ad",
		"tenant-id-123",
		"client-id",
		"client-secret",
		"https://app.example.com/callback",
	)
	
	assert.NotNil(t, provider)
	assert.Equal(t, "azure-ad", provider.Name)
	assert.Equal(t, "https://login.microsoftonline.com/tenant-id-123/v2.0", provider.IssuerURL)
	assert.Equal(t, "client-id", provider.ClientID)
	assert.Equal(t, "client-secret", provider.ClientSecret)
	assert.Equal(t, "https://app.example.com/callback", provider.RedirectURL)
	assert.True(t, provider.IsAzureAD)
	assert.Equal(t, "tenant-id-123", provider.TenantID)
	assert.Contains(t, provider.Scopes, "profile")
	assert.Contains(t, provider.Scopes, "email")
	assert.Contains(t, provider.Scopes, "User.Read")
}

func TestOIDCProvider_GenerateAuthURL(t *testing.T) {
	provider := CreateKeycloakProvider(
		"test-keycloak",
		"https://keycloak.example.com",
		"test-realm",
		"client-id",
		"client-secret",
		"https://app.example.com/callback",
		"booli-admin-api",
		false,
		"",
	)
	
	// Mock the oauth2Config for testing
	provider.oauth2Config = &oauth2.Config{
		ClientID:    provider.ClientID,
		RedirectURL: provider.RedirectURL,
		Scopes:      provider.Scopes,
	}
	
	// Test with empty state (should generate random)
	url := provider.GenerateAuthURL("")
	assert.Contains(t, url, "client_id=client-id")
	assert.Contains(t, url, "redirect_uri=")
	assert.Contains(t, url, "state=")
	
	// Test with provided state
	url = provider.GenerateAuthURL("test-state-123")
	assert.Contains(t, url, "state=test-state-123")
}

func TestOIDCProvider_MapAzureADClaims(t *testing.T) {
	provider := CreateAzureADProvider(
		"azure-ad",
		"tenant-id-123",
		"client-id",
		"client-secret",
		"https://app.example.com/callback",
	)
	
	claims := &OIDCClaims{
		Subject:  "user-123",
		Email:    "user@example.com",
		Roles:    []string{"admin", "user"},
		TenantID: "azure-tenant-123",
	}
	
	provider.mapAzureADClaims(claims)
	
	// Should map roles to realm access
	assert.Contains(t, claims.RealmAccess.Roles, "admin")
	assert.Contains(t, claims.RealmAccess.Roles, "user")
	
	// Should map tenant ID to tenant context
	assert.Equal(t, "azure-tenant-123", claims.TenantContext)
}

func TestOIDCProvider_MapAzureADClaims_EmptyValues(t *testing.T) {
	provider := CreateAzureADProvider(
		"azure-ad",
		"tenant-id-123",
		"client-id",
		"client-secret",
		"https://app.example.com/callback",
	)
	
	claims := &OIDCClaims{
		Subject: "user-123",
		Email:   "user@example.com",
	}
	
	provider.mapAzureADClaims(claims)
	
	// Should handle empty values gracefully
	assert.Empty(t, claims.RealmAccess.Roles)
	assert.Empty(t, claims.TenantContext)
}

func TestOIDCProvider_SecurityConfiguration(t *testing.T) {
	tests := []struct {
		name           string
		skipTLSVerify  bool
		caCertPath     string
		expectedSkip   bool
		expectedCAPath string
	}{
		{
			name:           "Skip TLS verification",
			skipTLSVerify:  true,
			caCertPath:     "",
			expectedSkip:   true,
			expectedCAPath: "",
		},
		{
			name:           "Use CA certificate",
			skipTLSVerify:  false,
			caCertPath:     "/path/to/ca.crt",
			expectedSkip:   false,
			expectedCAPath: "/path/to/ca.crt",
		},
		{
			name:           "Default secure configuration",
			skipTLSVerify:  false,
			caCertPath:     "",
			expectedSkip:   false,
			expectedCAPath: "",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := CreateKeycloakProvider(
				"test-keycloak",
				"https://keycloak.example.com",
				"test-realm",
				"client-id",
				"client-secret",
				"https://app.example.com/callback",
				"booli-admin-api",
				tt.skipTLSVerify,
				tt.caCertPath,
			)
			
			assert.Equal(t, tt.expectedSkip, provider.SkipTLSVerify)
			assert.Equal(t, tt.expectedCAPath, provider.CACertPath)
		})
	}
}

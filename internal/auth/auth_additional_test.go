package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
)

func TestCreateKeycloakMSPProvider_EdgeCases(t *testing.T) {
	testCases := []struct {
		name          string
		baseURL       string
		realm         string
		clientID      string
		clientSecret  string
		redirectURL   string
		apiAudience   string
		skipTLSVerify bool
		caCertPath    string
		expectedName  string
	}{
		{
			name:          "basic provider",
			baseURL:       "https://keycloak.example.com",
			realm:         "test-realm",
			clientID:      "test-client",
			clientSecret:  "test-secret",
			redirectURL:   "https://app.example.com/callback",
			apiAudience:   "test-api",
			skipTLSVerify: false,
			caCertPath:    "",
			expectedName:  "keycloak-test-realm",
		},
		{
			name:          "provider with TLS skip",
			baseURL:       "http://localhost:8080",
			realm:         "dev-realm",
			clientID:      "dev-client",
			clientSecret:  "",
			redirectURL:   "http://localhost:3000/callback",
			apiAudience:   "dev-api",
			skipTLSVerify: true,
			caCertPath:    "",
			expectedName:  "keycloak-dev-realm",
		},
		{
			name:          "provider with CA cert",
			baseURL:       "https://secure.example.com",
			realm:         "secure-realm",
			clientID:      "secure-client",
			clientSecret:  "secure-secret",
			redirectURL:   "https://app.example.com/auth",
			apiAudience:   "secure-api",
			skipTLSVerify: false,
			caCertPath:    "/path/to/ca.crt",
			expectedName:  "keycloak-secure-realm",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := CreateKeycloakMSPProvider(
				tc.baseURL,
				tc.realm,
				tc.clientID,
				tc.clientSecret,
				tc.redirectURL,
				tc.apiAudience,
				tc.skipTLSVerify,
				tc.caCertPath,
			)

			assert.NotNil(t, provider)
			assert.Equal(t, tc.expectedName, provider.Name)
			assert.Equal(t, tc.realm, provider.RealmName)
			assert.Equal(t, tc.clientID, provider.ClientID)
			assert.Equal(t, tc.clientSecret, provider.ClientSecret)
			assert.Equal(t, tc.redirectURL, provider.RedirectURL)
			assert.Equal(t, tc.skipTLSVerify, provider.SkipTLSVerify)
			assert.Equal(t, tc.caCertPath, provider.CACertPath)
			assert.Contains(t, provider.Scopes, "openid")
			assert.Contains(t, provider.Scopes, "profile")
			assert.Contains(t, provider.Scopes, "email")
			assert.Contains(t, provider.Scopes, "roles")
		})
	}
}

func TestBuildAzureADIssuerURL_EdgeCases(t *testing.T) {
	testCases := []struct {
		name      string
		authority string
		tenantID  string
		expected  string
	}{
		{
			name:      "empty authority defaults to Microsoft",
			authority: "",
			tenantID:  "tenant-123",
			expected:  "https://login.microsoftonline.com/tenant-123/v2.0",
		},
		{
			name:      "custom authority",
			authority: "https://login.microsoftonline.us",
			tenantID:  "gov-tenant",
			expected:  "https://login.microsoftonline.us/gov-tenant/v2.0",
		},
		{
			name:      "authority with multiple trailing slashes",
			authority: "https://login.microsoftonline.com///",
			tenantID:  "tenant-456",
			expected:  "https://login.microsoftonline.com/tenant-456/v2.0",
		},
		{
			name:      "tenant ID with multiple leading/trailing slashes",
			authority: "https://custom.authority.com",
			tenantID:  "///tenant-789///",
			expected:  "https://custom.authority.com/tenant-789/v2.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := buildAzureADIssuerURL(tc.authority, tc.tenantID)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestOIDCService_GetProviderNames_EdgeCases(t *testing.T) {
	logger := zaptest.NewLogger(t)
	service := NewOIDCService(logger)

	t.Run("empty service has no provider names", func(t *testing.T) {
		names := service.GetProviderNames()
		assert.Empty(t, names)
	})

	t.Run("service with multiple providers", func(t *testing.T) {
		provider1 := &OIDCProvider{Name: "provider1"}
		provider2 := &OIDCProvider{Name: "provider2"}
		provider3 := &OIDCProvider{Name: "provider3"}

		service.providers["provider1"] = provider1
		service.providers["provider2"] = provider2
		service.providers["provider3"] = provider3

		names := service.GetProviderNames()
		assert.Len(t, names, 3)
		assert.Contains(t, names, "provider1")
		assert.Contains(t, names, "provider2")
		assert.Contains(t, names, "provider3")
	})
}

func TestGenerateRandomState_Properties(t *testing.T) {
	t.Run("generates different states", func(t *testing.T) {
		states := make(map[string]bool)
		for i := 0; i < 100; i++ {
			state := generateRandomState()
			assert.NotEmpty(t, state)
			assert.False(t, states[state], "Generated duplicate state: %s", state)
			states[state] = true
		}
	})

	t.Run("generates states of sufficient length", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			state := generateRandomState()
			assert.Greater(t, len(state), 20, "Generated state too short: %s", state)
		}
	})
}
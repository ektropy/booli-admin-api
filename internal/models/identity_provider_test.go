package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateIdentityProviderRequest_ToKeycloakRepresentation_OIDC(t *testing.T) {
	req := &CreateIdentityProviderRequest{
		Alias:       "test-oidc",
		DisplayName: "Test OIDC Provider",
		Type:        IdentityProviderTypeOIDC,
		Enabled:     true,
		Config: IdentityProviderConfig{
			ClientID:         "test-client-id",
			ClientSecret:     "test-client-secret",
			IssuerURL:        "https://provider.example.com",
			AuthorizationURL: "https://provider.example.com/auth",
			TokenURL:         "https://provider.example.com/token",
			UserInfoURL:      "https://provider.example.com/userinfo",
			JWKSURL:          "https://provider.example.com/keys",
			DefaultScopes:    []string{"openid", "profile", "email"},
			TrustEmail:       true,
			StoreToken:       false,
		},
	}

	keycloakRep := req.ToKeycloakRepresentation()

	assert.Equal(t, "test-oidc", keycloakRep.Alias)
	assert.Equal(t, "Test OIDC Provider", keycloakRep.DisplayName)
	assert.Equal(t, "oidc", keycloakRep.ProviderId)
	assert.True(t, keycloakRep.Enabled)
	assert.True(t, keycloakRep.TrustEmail)
	assert.False(t, keycloakRep.StoreToken)

	// Check config values
	assert.Equal(t, "test-client-id", keycloakRep.Config["clientId"])
	assert.Equal(t, "test-client-secret", keycloakRep.Config["clientSecret"])
	assert.Equal(t, "https://provider.example.com", keycloakRep.Config["issuer"])
	assert.Equal(t, "https://provider.example.com/auth", keycloakRep.Config["authorizationUrl"])
	assert.Equal(t, "https://provider.example.com/token", keycloakRep.Config["tokenUrl"])
	assert.Equal(t, "https://provider.example.com/userinfo", keycloakRep.Config["userInfoUrl"])
	assert.Equal(t, "https://provider.example.com/keys", keycloakRep.Config["jwksUrl"])
	assert.Equal(t, "openid profile email", keycloakRep.Config["defaultScope"])
	assert.Equal(t, "true", keycloakRep.Config["validateSignature"])
	assert.Equal(t, "true", keycloakRep.Config["useJwksUrl"])
}

func TestCreateIdentityProviderRequest_ToKeycloakRepresentation_OAuth2(t *testing.T) {
	req := &CreateIdentityProviderRequest{
		Alias:       "test-oauth2",
		DisplayName: "Test OAuth2 Provider",
		Type:        IdentityProviderTypeOAuth2,
		Enabled:     true,
		Config: IdentityProviderConfig{
			ClientID:         "oauth-client-id",
			ClientSecret:     "oauth-client-secret",
			AuthorizationURL: "https://oauth.example.com/authorize",
			TokenURL:         "https://oauth.example.com/token",
			UserInfoURL:      "https://oauth.example.com/userinfo",
			DefaultScopes:    []string{"read", "write"},
			TrustEmail:       false,
			StoreToken:       true,
		},
	}

	keycloakRep := req.ToKeycloakRepresentation()

	assert.Equal(t, "test-oauth2", keycloakRep.Alias)
	assert.Equal(t, "Test OAuth2 Provider", keycloakRep.DisplayName)
	assert.Equal(t, "oauth", keycloakRep.ProviderId)
	assert.True(t, keycloakRep.Enabled)
	assert.False(t, keycloakRep.TrustEmail)
	assert.True(t, keycloakRep.StoreToken)

	// Check config values
	assert.Equal(t, "oauth-client-id", keycloakRep.Config["clientId"])
	assert.Equal(t, "oauth-client-secret", keycloakRep.Config["clientSecret"])
	assert.Equal(t, "https://oauth.example.com/authorize", keycloakRep.Config["authorizationUrl"])
	assert.Equal(t, "https://oauth.example.com/token", keycloakRep.Config["tokenUrl"])
	assert.Equal(t, "https://oauth.example.com/userinfo", keycloakRep.Config["userInfoUrl"])
	assert.Equal(t, "read write", keycloakRep.Config["defaultScope"])
}

func TestCreateIdentityProviderRequest_ToKeycloakRepresentation_SAML(t *testing.T) {
	req := &CreateIdentityProviderRequest{
		Alias:       "test-saml",
		DisplayName: "Test SAML Provider",
		Type:        IdentityProviderTypeSAML,
		Enabled:     true,
		Config: IdentityProviderConfig{
			SSOServiceURL:      "https://saml.example.com/sso",
			EntityID:           "https://saml.example.com/metadata",
			SigningCertificate: "MIICert...",
			ValidateSignature:  true,
			TrustEmail:         true,
			StoreToken:         false,
		},
	}

	keycloakRep := req.ToKeycloakRepresentation()

	assert.Equal(t, "test-saml", keycloakRep.Alias)
	assert.Equal(t, "Test SAML Provider", keycloakRep.DisplayName)
	assert.Equal(t, "saml", keycloakRep.ProviderId)
	assert.True(t, keycloakRep.Enabled)
	assert.True(t, keycloakRep.TrustEmail)
	assert.False(t, keycloakRep.StoreToken)

	// Check config values
	assert.Equal(t, "https://saml.example.com/sso", keycloakRep.Config["singleSignOnServiceUrl"])
	assert.Equal(t, "https://saml.example.com/metadata", keycloakRep.Config["entityId"])
	assert.Equal(t, "MIICert...", keycloakRep.Config["signingCertificate"])
	assert.Equal(t, "true", keycloakRep.Config["validateSignature"])
	assert.Equal(t, "true", keycloakRep.Config["postBindingResponse"])
	assert.Equal(t, "true", keycloakRep.Config["postBindingAuthnRequest"])
	assert.Equal(t, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", keycloakRep.Config["nameIDPolicyFormat"])
}

func TestCreateIdentityProviderRequest_ToKeycloakRepresentation_Microsoft(t *testing.T) {
	req := &CreateIdentityProviderRequest{
		Alias:       "test-microsoft",
		DisplayName: "Test Microsoft Provider",
		Type:        IdentityProviderTypeMicrosoft,
		Enabled:     true,
		Config: IdentityProviderConfig{
			ClientID:       "azure-client-id",
			ClientSecret:   "azure-client-secret",
			AzureTenantID:  "tenant-123",
			AzureAuthority: "https://login.microsoftonline.com",
			TrustEmail:     true,
			StoreToken:     true,
		},
	}

	keycloakRep := req.ToKeycloakRepresentation()

	assert.Equal(t, "test-microsoft", keycloakRep.Alias)
	assert.Equal(t, "Test Microsoft Provider", keycloakRep.DisplayName)
	assert.Equal(t, "oidc", keycloakRep.ProviderId) // Microsoft uses OIDC under the hood
	assert.True(t, keycloakRep.Enabled)
	assert.True(t, keycloakRep.TrustEmail)
	assert.True(t, keycloakRep.StoreToken)

	// Check that Azure endpoints are properly constructed
	assert.Equal(t, "azure-client-id", keycloakRep.Config["clientId"])
	assert.Equal(t, "azure-client-secret", keycloakRep.Config["clientSecret"])
	assert.Contains(t, keycloakRep.Config["authorizationUrl"], "login.microsoftonline.com/tenant-123/oauth2/v2.0/authorize")
	assert.Contains(t, keycloakRep.Config["tokenUrl"], "login.microsoftonline.com/tenant-123/oauth2/v2.0/token")
	assert.Contains(t, keycloakRep.Config["issuer"], "login.microsoftonline.com/tenant-123/v2.0")
	assert.Equal(t, "openid profile email", keycloakRep.Config["defaultScope"])
	assert.Equal(t, "true", keycloakRep.Config["validateSignature"])
	assert.Equal(t, "true", keycloakRep.Config["useJwksUrl"])
}

func TestCreateIdentityProviderRequest_BuildAttributeMappers(t *testing.T) {
	req := &CreateIdentityProviderRequest{
		Alias:       "test-provider",
		DisplayName: "Test Provider with Mappers",
		Type:        IdentityProviderTypeOIDC,
		Enabled:     true,
		Config: IdentityProviderConfig{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			AttributeMappings: []AttributeMapping{
				{
					Name:          "email-mapper",
					UserAttribute: "email",
					ClaimName:     "email",
					SyncMode:      "INHERIT",
				},
				{
					Name:          "name-mapper",
					UserAttribute: "name",
					ClaimName:     "name",
					SyncMode:      "FORCE",
				},
				{
					Name:          "custom-mapper",
					UserAttribute: "department",
					Template:      "${CLAIM.dept}",
					SyncMode:      "LEGACY",
				},
			},
		},
	}

	keycloakRep := req.ToKeycloakRepresentation()

	require.Len(t, keycloakRep.Mappers, 3)

	// Check email mapper
	emailMapper := keycloakRep.Mappers[0]
	assert.Equal(t, "email-mapper", emailMapper.Name)
	assert.Equal(t, "oidc-user-attribute-idp-mapper", emailMapper.IdentityProviderMapper)
	assert.Equal(t, "email", emailMapper.Config["user.attribute"])
	assert.Equal(t, "email", emailMapper.Config["claim"])
	assert.Equal(t, "INHERIT", emailMapper.Config["syncMode"])

	// Check name mapper
	nameMapper := keycloakRep.Mappers[1]
	assert.Equal(t, "name-mapper", nameMapper.Name)
	assert.Equal(t, "oidc-user-attribute-idp-mapper", nameMapper.IdentityProviderMapper)
	assert.Equal(t, "name", nameMapper.Config["user.attribute"])
	assert.Equal(t, "name", nameMapper.Config["claim"])
	assert.Equal(t, "FORCE", nameMapper.Config["syncMode"])

	// Check custom template mapper
	customMapper := keycloakRep.Mappers[2]
	assert.Equal(t, "custom-mapper", customMapper.Name)
	assert.Equal(t, "oidc-user-attribute-idp-mapper", customMapper.IdentityProviderMapper)
	assert.Equal(t, "department", customMapper.Config["user.attribute"])
	assert.Equal(t, "${CLAIM.dept}", customMapper.Config["template"])
	assert.Equal(t, "LEGACY", customMapper.Config["syncMode"])
}

func TestIdentityProviderTypeConstants(t *testing.T) {
	assert.Equal(t, IdentityProviderType("oidc"), IdentityProviderTypeOIDC)
	assert.Equal(t, IdentityProviderType("oauth"), IdentityProviderTypeOAuth2)
	assert.Equal(t, IdentityProviderType("saml"), IdentityProviderTypeSAML)
	assert.Equal(t, IdentityProviderType("microsoft"), IdentityProviderTypeMicrosoft)
}

func TestJoinScopes(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		expected string
	}{
		{
			name:     "single scope",
			scopes:   []string{"openid"},
			expected: "openid",
		},
		{
			name:     "multiple scopes",
			scopes:   []string{"openid", "profile", "email"},
			expected: "openid profile email",
		},
		{
			name:     "empty scopes",
			scopes:   []string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := joinScopes(tt.scopes)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBoolToString(t *testing.T) {
	assert.Equal(t, "true", boolToString(true))
	assert.Equal(t, "false", boolToString(false))
}

func TestGetMapperType(t *testing.T) {
	tests := []struct {
		name     string
		mapping  AttributeMapping
		expected string
	}{
		{
			name: "template mapper",
			mapping: AttributeMapping{
				Template: "${CLAIM.custom}",
			},
			expected: "oidc-user-attribute-idp-mapper",
		},
		{
			name: "claim mapper",
			mapping: AttributeMapping{
				ClaimName: "email",
			},
			expected: "oidc-user-attribute-idp-mapper",
		},
		{
			name: "saml attribute mapper",
			mapping: AttributeMapping{
				AttributeName: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			},
			expected: "saml-user-attribute-idp-mapper",
		},
		{
			name:     "default mapper",
			mapping:  AttributeMapping{},
			expected: "oidc-user-attribute-idp-mapper",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getMapperType(tt.mapping)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetSyncMode(t *testing.T) {
	tests := []struct {
		name     string
		syncMode string
		expected string
	}{
		{
			name:     "inherit mode",
			syncMode: "INHERIT",
			expected: "INHERIT",
		},
		{
			name:     "force mode",
			syncMode: "FORCE",
			expected: "FORCE",
		},
		{
			name:     "empty mode defaults to inherit",
			syncMode: "",
			expected: "INHERIT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getSyncMode(tt.syncMode)
			assert.Equal(t, tt.expected, result)
		})
	}
}
package models

import (
	"fmt"
	
	"github.com/booli/booli-admin-api/internal/auth"
	"github.com/booli/booli-admin-api/internal/keycloak"
)

type IdentityProviderType string

const (
	IdentityProviderTypeOIDC   IdentityProviderType = "oidc"
	IdentityProviderTypeOAuth2 IdentityProviderType = "oauth"
	IdentityProviderTypeSAML   IdentityProviderType = "saml"
	IdentityProviderTypeMicrosoft IdentityProviderType = "microsoft"
)

type CreateIdentityProviderRequest struct {
	Alias       string               `json:"alias" validate:"required" example:"my-oidc-provider"`
	DisplayName string               `json:"display_name,omitempty" example:"My OIDC Provider"`
	Type        IdentityProviderType `json:"type" validate:"required,oneof=oidc oauth saml microsoft" example:"oidc"`
	Enabled     bool                 `json:"enabled" example:"true"`
	Config      IdentityProviderConfig `json:"config" validate:"required"`
}

type IdentityProviderConfig struct {
	ClientID     string `json:"client_id" validate:"required" example:"my-client-id"`
	ClientSecret string `json:"client_secret" validate:"required" example:"my-client-secret"`
	
	// OIDC/OAuth2 specific fields
	AuthorizationURL string `json:"authorization_url,omitempty" example:"https://auth.example.com/oauth2/authorize"`
	TokenURL         string `json:"token_url,omitempty" example:"https://auth.example.com/oauth2/token"`
	UserInfoURL      string `json:"user_info_url,omitempty" example:"https://auth.example.com/oauth2/userinfo"`
	IssuerURL        string `json:"issuer_url,omitempty" example:"https://auth.example.com"`
	JWKSURL          string `json:"jwks_url,omitempty" example:"https://auth.example.com/.well-known/jwks.json"`
	
	// SAML specific fields
	SSOServiceURL        string `json:"sso_service_url,omitempty" example:"https://saml.example.com/sso"`
	EntityID             string `json:"entity_id,omitempty" example:"https://saml.example.com/metadata"`
	SigningCertificate   string `json:"signing_certificate,omitempty" example:"MIICertificateData..."`
	ValidateSignature    bool   `json:"validate_signature,omitempty" example:"true"`
	
	// Microsoft specific fields
	AzureTenantID string `json:"azure_tenant_id,omitempty" example:"12345678-1234-1234-1234-123456789012"`
	AzureAuthority string `json:"azure_authority,omitempty" example:"https://login.microsoftonline.com/"`
	
	// Common configuration
	DefaultScopes    []string `json:"default_scopes,omitempty" example:"[\"openid\", \"profile\", \"email\"]"`
	TrustEmail       bool     `json:"trust_email,omitempty" example:"false"`
	StoreToken       bool     `json:"store_token,omitempty" example:"true"`
	LinkOnly         bool     `json:"link_only,omitempty"`
	
	AttributeMappings []AttributeMapping `json:"attribute_mappings,omitempty"`
}

type AttributeMapping struct {
	Name           string `json:"name" validate:"required" example:"email-mapper"`
	UserAttribute  string `json:"user_attribute" validate:"required" example:"email"`
	ClaimName      string `json:"claim_name,omitempty" example:"email"`
	AttributeName  string `json:"attribute_name,omitempty" example:"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"`
	Template       string `json:"template,omitempty" example:"${ATTRIBUTE.email}"`
	SyncMode       string `json:"sync_mode,omitempty" example:"INHERIT"`
}

type IdentityProviderResponse struct {
	Alias       string                 `json:"alias" example:"my-oidc-provider"`
	DisplayName string                 `json:"display_name,omitempty" example:"My OIDC Provider"`
	Type        IdentityProviderType   `json:"type" example:"oidc"`
	Enabled     bool                   `json:"enabled" example:"true"`
	Config      map[string]string      `json:"config" example:"{\"client_id\":\"my-client-id\",\"client_secret\":\"**********\",\"issuer_url\":\"https://auth.example.com\"}"`
	Mappers     []AttributeMappingResponse `json:"mappers,omitempty"`
	CreatedAt   string                 `json:"created_at,omitempty" example:"2025-08-18T10:30:00Z"`
	UpdatedAt   string                 `json:"updated_at,omitempty" example:"2025-08-18T10:30:00Z"`
}

type AttributeMappingResponse struct {
	ID         string            `json:"id" example:"12345678-1234-1234-1234-123456789012"`
	Name       string            `json:"name" example:"email-mapper"`
	Type       string            `json:"type" example:"oidc-user-attribute-idp-mapper"`
	Config     map[string]string `json:"config" example:"{\"user.attribute\":\"email\",\"claim\":\"email\",\"syncMode\":\"INHERIT\"}"`
}

func (req *CreateIdentityProviderRequest) ToKeycloakRepresentation() *keycloak.IdentityProviderRepresentation {
	config := make(map[string]string)
	
	switch req.Type {
	case IdentityProviderTypeOIDC:
		return req.buildOIDCProvider(config)
	case IdentityProviderTypeOAuth2:
		return req.buildOAuth2Provider(config)
	case IdentityProviderTypeSAML:
		return req.buildSAMLProvider(config)
	case IdentityProviderTypeMicrosoft:
		return req.buildMicrosoftProvider(config)
	default:
		// Invalid provider type - return nil to trigger 400 Bad Request
		return nil
	}
}

// ValidateConfiguration validates the configuration for the specific provider type
func (req *CreateIdentityProviderRequest) ValidateConfiguration() error {
	switch req.Type {
	case IdentityProviderTypeOAuth2:
		if req.Config.AuthorizationURL == "" {
			return fmt.Errorf("OAuth2 provider requires authorization_url")
		}
		if req.Config.TokenURL == "" {
			return fmt.Errorf("OAuth2 provider requires token_url")
		}
	case IdentityProviderTypeSAML:
		if req.Config.SSOServiceURL == "" {
			return fmt.Errorf("SAML provider requires sso_service_url")
		}
		if req.Config.EntityID == "" {
			return fmt.Errorf("SAML provider requires entity_id")
		}
	case IdentityProviderTypeMicrosoft:
		if req.Config.AzureTenantID == "" {
			return fmt.Errorf("Microsoft provider requires azure_tenant_id")
		}
	}
	return nil
}

func (req *CreateIdentityProviderRequest) buildOIDCProvider(config map[string]string) *keycloak.IdentityProviderRepresentation {
	config["clientId"] = req.Config.ClientID
	config["clientSecret"] = req.Config.ClientSecret
	
	if req.Config.IssuerURL != "" {
		config["issuer"] = req.Config.IssuerURL
	}
	if req.Config.AuthorizationURL != "" {
		config["authorizationUrl"] = req.Config.AuthorizationURL
	}
	if req.Config.TokenURL != "" {
		config["tokenUrl"] = req.Config.TokenURL
	}
	if req.Config.UserInfoURL != "" {
		config["userInfoUrl"] = req.Config.UserInfoURL
	}
	if req.Config.JWKSURL != "" {
		config["jwksUrl"] = req.Config.JWKSURL
	}
	
	if len(req.Config.DefaultScopes) > 0 {
		config["defaultScope"] = joinScopes(req.Config.DefaultScopes)
	} else {
		config["defaultScope"] = "openid profile email"
	}
	
	config["validateSignature"] = "true"
	config["useJwksUrl"] = "true"
	
	return &keycloak.IdentityProviderRepresentation{
		Alias:       req.Alias,
		DisplayName: req.DisplayName,
		ProviderId:  "oidc",
		Enabled:     req.Enabled,
		TrustEmail:  req.Config.TrustEmail,
		StoreToken:  req.Config.StoreToken,
		LinkOnly:    req.Config.LinkOnly,
		Config:      config,
		// Don't include Mappers here - they need to be created separately after the identity provider
	}
}

func (req *CreateIdentityProviderRequest) buildOAuth2Provider(config map[string]string) *keycloak.IdentityProviderRepresentation {
	config["clientId"] = req.Config.ClientID
	config["clientSecret"] = req.Config.ClientSecret
	
	// OAuth2 requires authorization and token URLs
	if req.Config.AuthorizationURL == "" {
		return nil // Invalid configuration
	}
	if req.Config.TokenURL == "" {
		return nil // Invalid configuration
	}
	
	config["authorizationUrl"] = req.Config.AuthorizationURL
	config["tokenUrl"] = req.Config.TokenURL
	
	// UserInfo URL is required for OAuth2 providers in Keycloak
	if req.Config.UserInfoURL != "" {
		config["userInfoUrl"] = req.Config.UserInfoURL
	} else {
		// Provide a default userinfo endpoint if not specified
		config["userInfoUrl"] = req.Config.AuthorizationURL + "/userinfo"
	}
	
	if len(req.Config.DefaultScopes) > 0 {
		config["defaultScope"] = joinScopes(req.Config.DefaultScopes)
	}
	
	// OAuth2-specific settings required by Keycloak
	config["syncMode"] = "LEGACY"
	config["clientAuthMethod"] = "client_secret_post"
	config["pkceEnabled"] = "false"
	
	return &keycloak.IdentityProviderRepresentation{
		Alias:       req.Alias,
		DisplayName: req.DisplayName,
		ProviderId:  "oidc", // Use oidc provider type for OAuth2 in Keycloak
		Enabled:     req.Enabled,
		TrustEmail:  req.Config.TrustEmail,
		StoreToken:  req.Config.StoreToken,
		LinkOnly:    req.Config.LinkOnly,
		Config:      config,
		// Don't include Mappers here - they need to be created separately after the identity provider
	}
}

func (req *CreateIdentityProviderRequest) buildSAMLProvider(config map[string]string) *keycloak.IdentityProviderRepresentation {
	// SAML requires SSO service URL and Entity ID
	if req.Config.SSOServiceURL == "" {
		return nil // Invalid configuration
	}
	if req.Config.EntityID == "" {
		return nil // Invalid configuration
	}
	
	config["singleSignOnServiceUrl"] = req.Config.SSOServiceURL
	config["entityId"] = req.Config.EntityID
	
	if req.Config.SigningCertificate != "" {
		config["signingCertificate"] = req.Config.SigningCertificate
	}
	
	config["validateSignature"] = boolToString(req.Config.ValidateSignature)
	config["postBindingResponse"] = "true"
	config["postBindingAuthnRequest"] = "true"
	config["nameIDPolicyFormat"] = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	config["syncMode"] = "LEGACY"
	
	// Additional SAML settings for better compatibility
	config["wantAssertionsSigned"] = "false"
	config["wantAssertionsEncrypted"] = "false"
	config["forceAuthn"] = "false"
	
	return &keycloak.IdentityProviderRepresentation{
		Alias:       req.Alias,
		DisplayName: req.DisplayName,
		ProviderId:  "saml",
		Enabled:     req.Enabled,
		TrustEmail:  req.Config.TrustEmail,
		StoreToken:  req.Config.StoreToken,
		LinkOnly:    req.Config.LinkOnly,
		Config:      config,
		// Don't include Mappers here - they need to be created separately after the identity provider
	}
}

func (req *CreateIdentityProviderRequest) buildMicrosoftProvider(config map[string]string) *keycloak.IdentityProviderRepresentation {
	if req.Config.AzureTenantID != "" {
		endpoints := auth.BuildAzureADEndpoints(req.Config.AzureAuthority, req.Config.AzureTenantID)
		
		config["clientId"] = req.Config.ClientID
		config["clientSecret"] = req.Config.ClientSecret
		config["authorizationUrl"] = endpoints.AuthorizationURL
		config["tokenUrl"] = endpoints.TokenURL
		config["userInfoUrl"] = endpoints.UserInfoURL
		config["issuer"] = endpoints.IssuerURL
		config["jwksUrl"] = endpoints.JWKSURL
		config["defaultScope"] = "openid profile email"
		config["validateSignature"] = "true"
		config["useJwksUrl"] = "true"
	}
	
	return &keycloak.IdentityProviderRepresentation{
		Alias:       req.Alias,
		DisplayName: req.DisplayName,
		ProviderId:  "oidc",
		Enabled:     req.Enabled,
		TrustEmail:  req.Config.TrustEmail,
		StoreToken:  req.Config.StoreToken,
		LinkOnly:    req.Config.LinkOnly,
		Config:      config,
		// Don't include Mappers here - they need to be created separately after the identity provider
	}
}

func (req *CreateIdentityProviderRequest) BuildAttributeMappers() []keycloak.IdentityProviderMapper {
	var mappers []keycloak.IdentityProviderMapper
	
	for _, mapping := range req.Config.AttributeMappings {
		mapper := keycloak.IdentityProviderMapper{
			Name:                   mapping.Name,
			IdentityProviderMapper: getMapperType(mapping),
			Config: map[string]string{
				"user.attribute": mapping.UserAttribute,
				"syncMode":       getSyncMode(mapping.SyncMode),
			},
		}
		
		if mapping.ClaimName != "" {
			mapper.Config["claim"] = mapping.ClaimName
		}
		if mapping.AttributeName != "" {
			mapper.Config["attribute.name"] = mapping.AttributeName
		}
		if mapping.Template != "" {
			mapper.Config["template"] = mapping.Template
		}
		
		mappers = append(mappers, mapper)
	}
	
	return mappers
}

func getMapperType(mapping AttributeMapping) string {
	if mapping.Template != "" {
		return "oidc-user-attribute-idp-mapper"
	}
	if mapping.ClaimName != "" {
		return "oidc-user-attribute-idp-mapper"
	}
	if mapping.AttributeName != "" {
		return "saml-user-attribute-idp-mapper"
	}
	return "oidc-user-attribute-idp-mapper"
}

func getSyncMode(syncMode string) string {
	if syncMode == "" {
		return "INHERIT"
	}
	return syncMode
}

func joinScopes(scopes []string) string {
	result := ""
	for i, scope := range scopes {
		if i > 0 {
			result += " "
		}
		result += scope
	}
	return result
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
package models

import "time"

type SSOProvider struct {
	ID           string                 `json:"id"`            // Keycloak Identity Provider ID
	Alias        string                 `json:"alias"`         // Identity Provider alias
	DisplayName  string                 `json:"display_name"`  // Display name
	ProviderType SSOProviderType        `json:"provider_type"` // saml or oidc
	Enabled      bool                   `json:"enabled"`       // Whether the provider is enabled
	Config       map[string]interface{} `json:"config"`        // Keycloak Identity Provider config
	RealmName    string                 `json:"realm_name"`    // Which realm this provider belongs to
}

type SSOProviderType string

const (
	SSOProviderTypeSAML SSOProviderType = "saml"
	SSOProviderTypeOIDC SSOProviderType = "oidc"
)

type CreateSSOProviderRequest struct {
	Alias        string                 `json:"alias" validate:"required,min=1,max=255"`
	DisplayName  string                 `json:"display_name" validate:"max=255"`
	ProviderType SSOProviderType        `json:"provider_type" validate:"required,oneof=saml oidc"`
	Config       map[string]interface{} `json:"config" validate:"required"`
}

type UpdateSSOProviderRequest struct {
	DisplayName *string                 `json:"display_name,omitempty"`
	Enabled     *bool                   `json:"enabled,omitempty"`
	Config      *map[string]interface{} `json:"config,omitempty"`
}

type SSOProviderResponse struct {
	ID           string                 `json:"id"`
	Alias        string                 `json:"alias"`
	DisplayName  string                 `json:"display_name"`
	ProviderType SSOProviderType        `json:"provider_type"`
	Enabled      bool                   `json:"enabled"`
	Config       map[string]interface{} `json:"config"`
	RealmName    string                 `json:"realm_name"`
}

type SSOProviderListResponse struct {
	Providers  []SSOProviderResponse `json:"providers"`
	Total      int64                 `json:"total"`
	Page       int                   `json:"page"`
	PageSize   int                   `json:"page_size"`
	TotalPages int                   `json:"total_pages"`
}

func (s *SSOProvider) ToResponse() *SSOProviderResponse {
	return &SSOProviderResponse{
		ID:           s.ID,
		Alias:        s.Alias,
		DisplayName:  s.DisplayName,
		ProviderType: s.ProviderType,
		Enabled:      s.Enabled,
		Config:       s.Config,
		RealmName:    s.RealmName,
	}
}

type TestSSOProviderRequest struct {
	TestUser string `json:"test_user,omitempty"`
}

type SSOTestResult struct {
	Success      bool      `json:"success"`
	Error        string    `json:"error,omitempty"`
	TestedAt     time.Time `json:"tested_at"`
	ResponseTime int64     `json:"response_time_ms"`
}
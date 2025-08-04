package models

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type SSOProvider struct {
	ID            uuid.UUID       `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID      uuid.UUID       `gorm:"type:uuid;not null;index;uniqueIndex:idx_tenant_sso_provider_name" json:"tenant_id"`
	ProviderType  SSOProviderType `gorm:"not null;size:50;check:provider_type IN ('saml','oidc')" json:"provider_type" validate:"required,oneof=saml oidc"`
	ProviderName  string          `gorm:"not null;size:255;uniqueIndex:idx_tenant_sso_provider_name" json:"provider_name" validate:"required,min=1,max=255"`
	DisplayName   string          `gorm:"size:255" json:"display_name"`
	Configuration datatypes.JSON  `gorm:"type:jsonb" json:"configuration"`
	Status        SSOStatus       `gorm:"default:'inactive';check:status IN ('active','inactive','testing','error')" json:"status"`
	IsDefault     bool            `gorm:"default:false" json:"is_default"`
	Priority      int             `gorm:"default:0" json:"priority"`
	LastTested    *time.Time      `json:"last_tested,omitempty"`
	TestResult    datatypes.JSON  `gorm:"type:jsonb" json:"test_result,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	DeletedAt     gorm.DeletedAt  `gorm:"index" json:"deleted_at,omitempty"`

	Tenant Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`
}

type SSOProviderType string

const (
	SSOProviderTypeSAML SSOProviderType = "saml"
	SSOProviderTypeOIDC SSOProviderType = "oidc"
)

type SSOStatus string

const (
	SSOStatusActive   SSOStatus = "active"
	SSOStatusInactive SSOStatus = "inactive"
	SSOStatusTesting  SSOStatus = "testing"
	SSOStatusError    SSOStatus = "error"
)

type SSOConfiguration struct {
	SAML *SAMLConfig `json:"saml,omitempty"`
	OIDC *OIDCConfig `json:"oidc,omitempty"`
}

type SAMLConfig struct {
	EntityID             string   `json:"entity_id" validate:"required"`
	SSOServiceURL        string   `json:"sso_service_url" validate:"required,url"`
	SLOServiceURL        string   `json:"slo_service_url,omitempty" validate:"omitempty,url"`
	X509Certificate      string   `json:"x509_certificate" validate:"required"`
	X509CertificateMulti []string `json:"x509_certificate_multi,omitempty"`

	SPEntityID    string `json:"sp_entity_id,omitempty"`
	ACSServiceURL string `json:"acs_service_url,omitempty"`

	NameIDFormat         string `json:"name_id_format"`
	SignAssertions       bool   `json:"sign_assertions"`
	SignRequests         bool   `json:"sign_requests"`
	EncryptAssertions    bool   `json:"encrypt_assertions"`
	WantAssertionsSigned bool   `json:"want_assertions_signed"`
	ForceAuthentication  bool   `json:"force_authentication"`

	AttributeMapping AttributeMapping `json:"attribute_mapping"`

	AllowedClockSkew      int    `json:"allowed_clock_skew,omitempty"`
	SigningCertificate    string `json:"signing_certificate,omitempty"`
	EncryptionCertificate string `json:"encryption_certificate,omitempty"`
}

type OIDCConfig struct {
	IssuerURL        string `json:"issuer_url" validate:"required,url"`
	AuthorizationURL string `json:"authorization_url" validate:"required,url"`
	TokenURL         string `json:"token_url" validate:"required,url"`
	UserInfoURL      string `json:"userinfo_url" validate:"required,url"`
	JWKSURL          string `json:"jwks_url" validate:"required,url"`

	ClientID     string `json:"client_id" validate:"required"`
	ClientSecret string `json:"client_secret" validate:"required"`

	Scopes        []string         `json:"scopes"`
	ClaimsMapping AttributeMapping `json:"claims_mapping"`

	ResponseType string `json:"response_type"`
	ResponseMode string `json:"response_mode,omitempty"`
	GrantType    string `json:"grant_type"`
	PKCEMethod   string `json:"pkce_method,omitempty"`

	TokenValidation TokenValidationConfig `json:"token_validation"`
}

type AttributeMapping struct {
	Email       string `json:"email" validate:"required"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	Username    string `json:"username"`
	Groups      string `json:"groups,omitempty"`
	Department  string `json:"department,omitempty"`
	JobTitle    string `json:"job_title,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
	Location    string `json:"location,omitempty"`
	Manager     string `json:"manager,omitempty"`

	CustomMappings map[string]string `json:"custom_mappings,omitempty"`
}

type TokenValidationConfig struct {
	ValidateIssuer     bool     `json:"validate_issuer"`
	ValidateAudience   bool     `json:"validate_audience"`
	ValidateSignature  bool     `json:"validate_signature"`
	ValidateExpiration bool     `json:"validate_expiration"`
	ClockSkewSeconds   int      `json:"clock_skew_seconds"`
	RequiredClaims     []string `json:"required_claims,omitempty"`
}

type SSOTestResult struct {
	Success      bool      `json:"success"`
	Error        string    `json:"error,omitempty"`
	Details      string    `json:"details,omitempty"`
	TestedAt     time.Time `json:"tested_at"`
	ResponseTime int64     `json:"response_time_ms"`

	ConnectionSuccess bool `json:"connection_success"`
	AuthSuccess       bool `json:"auth_success"`
	UserInfoSuccess   bool `json:"user_info_success"`
	AttributeMapping  bool `json:"attribute_mapping_success"`
}

func (s *SSOProvider) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}

	if s.DisplayName == "" {
		s.DisplayName = s.ProviderName
	}

	return nil
}

func (s *SSOProvider) IsActive() bool {
	return s.Status == SSOStatusActive
}

func (s *SSOProvider) GetConfiguration() interface{} {
	var config SSOConfiguration
	if len(s.Configuration) > 0 {
		_ = json.Unmarshal(s.Configuration, &config)
	}

	switch s.ProviderType {
	case SSOProviderTypeSAML:
		return config.SAML
	case SSOProviderTypeOIDC:
		return config.OIDC
	default:
		return nil
	}
}

func (s *SSOProvider) ValidateConfiguration() error {
	var config SSOConfiguration
	if len(s.Configuration) > 0 {
		_ = json.Unmarshal(s.Configuration, &config)
	}

	switch s.ProviderType {
	case SSOProviderTypeSAML:
		if config.SAML == nil {
			return fmt.Errorf("SAML configuration is required")
		}
		return config.SAML.Validate()
	case SSOProviderTypeOIDC:
		if config.OIDC == nil {
			return fmt.Errorf("OIDC configuration is required")
		}
		return config.OIDC.Validate()
	default:
		return fmt.Errorf("unsupported provider type: %s", s.ProviderType)
	}
}

func (c *SAMLConfig) Validate() error {
	if c.EntityID == "" {
		return fmt.Errorf("entity_id is required")
	}
	if c.SSOServiceURL == "" {
		return fmt.Errorf("sso_service_url is required")
	}
	if c.X509Certificate == "" {
		return fmt.Errorf("x509_certificate is required")
	}
	return nil
}

func (c *OIDCConfig) Validate() error {
	if c.IssuerURL == "" {
		return fmt.Errorf("issuer_url is required")
	}
	if c.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("client_secret is required")
	}
	return nil
}

type CreateSSOProviderRequest struct {
	ProviderType  SSOProviderType `json:"provider_type" validate:"required,oneof=saml oidc"`
	ProviderName  string          `json:"provider_name" validate:"required,min=1,max=255"`
	DisplayName   string          `json:"display_name" validate:"max=255"`
	Configuration datatypes.JSON  `json:"configuration"`
	IsDefault     bool            `json:"is_default"`
	Priority      int             `json:"priority"`
}

type UpdateSSOProviderRequest struct {
	ProviderName  *string         `json:"provider_name,omitempty" validate:"omitempty,min=1,max=255"`
	DisplayName   *string         `json:"display_name,omitempty" validate:"omitempty,max=255"`
	Configuration *datatypes.JSON `json:"configuration,omitempty"`
	Status        *SSOStatus      `json:"status,omitempty"`
	IsDefault     *bool           `json:"is_default,omitempty"`
	Priority      *int            `json:"priority,omitempty"`
}

type SSOProviderResponse struct {
	ID            uuid.UUID        `json:"id"`
	ProviderType  SSOProviderType  `json:"provider_type"`
	ProviderName  string           `json:"provider_name"`
	DisplayName   string           `json:"display_name"`
	Configuration SSOConfiguration `json:"configuration"`
	Status        SSOStatus        `json:"status"`
	IsDefault     bool             `json:"is_default"`
	Priority      int              `json:"priority"`
	LastTested    *time.Time       `json:"last_tested,omitempty"`
	TestResult    *SSOTestResult   `json:"test_result,omitempty"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

type SSOProviderListResponse struct {
	Providers  []SSOProviderResponse `json:"providers"`
	Total      int64                 `json:"total"`
	Page       int                   `json:"page"`
	PageSize   int                   `json:"page_size"`
	TotalPages int                   `json:"total_pages"`
}

func (s *SSOProvider) ToResponse() *SSOProviderResponse {
	var testResult *SSOTestResult
	if s.TestResult != nil {
		var result SSOTestResult
		if err := json.Unmarshal(s.TestResult, &result); err == nil {
			testResult = &result
		}
	}

	var config SSOConfiguration
	if len(s.Configuration) > 0 {
		_ = json.Unmarshal(s.Configuration, &config)
	}

	return &SSOProviderResponse{
		ID:            s.ID,
		ProviderType:  s.ProviderType,
		ProviderName:  s.ProviderName,
		DisplayName:   s.DisplayName,
		Configuration: config,
		Status:        s.Status,
		IsDefault:     s.IsDefault,
		Priority:      s.Priority,
		LastTested:    s.LastTested,
		TestResult:    testResult,
		CreatedAt:     s.CreatedAt,
		UpdatedAt:     s.UpdatedAt,
	}
}

type TestSSOProviderRequest struct {
	TestUser     string `json:"test_user,omitempty"`
	TestPassword string `json:"test_password,omitempty"`
}

type SSOMetadataResponse struct {
	Metadata      string `json:"metadata"`
	EntityID      string `json:"entity_id"`
	ACSServiceURL string `json:"acs_service_url"`
}

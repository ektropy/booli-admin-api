package models

import (
	"encoding/json"
	"strings"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type TenantType string

const (
	TenantTypeClient TenantType = "client"
	TenantTypeMSP    TenantType = "msp"
)

type Tenant struct {
	RealmName     string         `gorm:"primaryKey;size:255" json:"realm"`
	Name          string         `gorm:"not null;size:255" json:"name" validate:"required,min=1,max=255"`
	Domain        string         `gorm:"unique;size:255" json:"domain" validate:"omitempty,fqdn"`
	Type          TenantType     `gorm:"default:'client'" json:"type"`
	Active        bool           `gorm:"default:true" json:"active"`
	ParentMSP     string         `gorm:"index;size:255" json:"parent_msp,omitempty"`
	Settings      datatypes.JSON `gorm:"type:jsonb" json:"settings"`
	AdminPassword string         `gorm:"-" json:"admin_password,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}


type TenantSettings struct {
	LogoURL        string `json:"logo_url,omitempty"`
	PrimaryColor   string `json:"primary_color,omitempty"`
	SecondaryColor string `json:"secondary_color,omitempty"`
	ThemeMode      string `json:"theme_mode,omitempty"`

	EnableSSO   bool `json:"enable_sso"`
	EnableMFA   bool `json:"enable_mfa"`
	EnableAudit bool `json:"enable_audit"`

	MSPSSOEnabled  bool                   `json:"msp_sso_enabled"`
	MSPSSOProvider string                 `json:"msp_sso_provider,omitempty"`
	MSPSSOConfig   map[string]interface{} `json:"msp_sso_config,omitempty"`
	MSPSSODomains  []string               `json:"msp_sso_domains,omitempty"`

	MaxUsers        int `json:"max_users,omitempty"`
	MaxRoles        int `json:"max_roles,omitempty"`
	MaxSSOProviders int `json:"max_sso_providers,omitempty"`

	NotificationEmail string   `json:"notification_email,omitempty"`
	AlertWebhooks     []string `json:"alert_webhooks,omitempty"`

	DataRetentionDays int      `json:"data_retention_days,omitempty"`
	ComplianceFlags   []string `json:"compliance_flags,omitempty"`
}


func (t *Tenant) IsActive() bool {
	return t.Active
}

func (t *Tenant) CanProvisionUsers(currentUserCount int) bool {
	var settings TenantSettings
	if len(t.Settings) > 0 {
		_ = json.Unmarshal(t.Settings, &settings)
	}
	if settings.MaxUsers <= 0 {
		return true
	}
	return currentUserCount < settings.MaxUsers
}

func (t *Tenant) CanCreateRoles(currentRoleCount int) bool {
	var settings TenantSettings
	if len(t.Settings) > 0 {
		_ = json.Unmarshal(t.Settings, &settings)
	}
	if settings.MaxRoles <= 0 {
		return true
	}
	return currentRoleCount < settings.MaxRoles
}

func (t *Tenant) CanCreateSSOProviders(currentProviderCount int) bool {
	var settings TenantSettings
	if len(t.Settings) > 0 {
		_ = json.Unmarshal(t.Settings, &settings)
	}
	if settings.MaxSSOProviders <= 0 {
		return true
	}
	return currentProviderCount < settings.MaxSSOProviders
}

func (t *Tenant) IsMSP() bool {
	return t.Type == TenantTypeMSP
}

func (t *Tenant) IsClientTenant() bool {
	return t.Type == TenantTypeClient
}

func (t *Tenant) HasParentMSP() bool {
	return t.Type == TenantTypeClient && t.ParentMSP != ""
}

func (t *Tenant) CanManageChildTenants() bool {
	return t.IsMSP() && t.Active
}

func (t *Tenant) HasMSPSSO() bool {
	var settings TenantSettings
	if len(t.Settings) > 0 {
		_ = json.Unmarshal(t.Settings, &settings)
	}
	return t.IsMSP() && settings.MSPSSOEnabled && settings.MSPSSOProvider != ""
}

func (t *Tenant) CanAccessAdminPanel() bool {
	return t.IsMSP() && t.Active
}

func (t *Tenant) IsEmailDomainAllowed(email string) bool {
	if !t.HasMSPSSO() {
		return false
	}

	var settings TenantSettings
	if len(t.Settings) > 0 {
		_ = json.Unmarshal(t.Settings, &settings)
	}

	if len(settings.MSPSSODomains) == 0 {
		return true
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	domain := strings.ToLower(parts[1])

	for _, allowedDomain := range settings.MSPSSODomains {
		if strings.ToLower(allowedDomain) == domain {
			return true
		}
	}

	return false
}

type CreateTenantRequest struct {
	Name     string         `json:"name" validate:"required,min=1,max=255"`
	Domain   string         `json:"domain" validate:"omitempty,fqdn"`
	Type     TenantType     `json:"type" validate:"omitempty,oneof=client msp"`
	Settings datatypes.JSON `json:"settings"`
}

type UpdateTenantRequest struct {
	Name     *string         `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Domain   *string         `json:"domain,omitempty" validate:"omitempty,fqdn"`
	Active   *bool           `json:"active,omitempty"`
	Settings *datatypes.JSON `json:"settings,omitempty"`
}

type TenantResponse struct {
	Realm            string         `json:"realm"`
	Name             string         `json:"name"`
	Domain           string         `json:"domain"`
	Type             TenantType     `json:"type"`
	Active           bool           `json:"active"`
	Settings         TenantSettings `json:"settings"`
	AdminPassword    string         `json:"admin_password,omitempty"`
	UserCount        int            `json:"user_count,omitempty"`
	RoleCount        int            `json:"role_count,omitempty"`
	SSOProviderCount int            `json:"sso_provider_count,omitempty"`
	ChildTenantCount int            `json:"child_tenant_count,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

type TenantListResponse struct {
	Tenants    []TenantResponse `json:"tenants"`
	Total      int64            `json:"total"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
	TotalPages int              `json:"total_pages"`
}

func (t *Tenant) ToResponse() *TenantResponse {
	var settings TenantSettings
	if len(t.Settings) > 0 {
		_ = json.Unmarshal(t.Settings, &settings)
	}

	return &TenantResponse{
		Realm:         t.RealmName,
		Name:          t.Name,
		Domain:        t.Domain,
		Type:          t.Type,
		Active:        t.Active,
		Settings:      settings,
		AdminPassword: t.AdminPassword,
		CreatedAt:     t.CreatedAt,
		UpdatedAt:     t.UpdatedAt,
	}
}

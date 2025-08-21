package models

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type MSPStatus string

const (
	MSPStatusActive      MSPStatus = "active"
	MSPStatusInactive    MSPStatus = "inactive"
	MSPStatusSuspended   MSPStatus = "suspended"
	MSPStatusTerminated  MSPStatus = "terminated"
)

type MSP struct {
	RealmName     string         `gorm:"primaryKey;size:255" json:"realm_name" validate:"required,min=1,max=255"`
	Name          string         `gorm:"not null;size:255" json:"name" validate:"required,min=1,max=255"`
	Domain        string         `gorm:"size:255" json:"domain,omitempty" validate:"omitempty,fqdn"`
	ClientPattern string         `gorm:"not null;size:255" json:"client_pattern" validate:"required"`
	Status        MSPStatus      `gorm:"default:'active'" json:"status"`
	Settings      datatypes.JSON `gorm:"type:jsonb" json:"settings,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

type MSPSettings struct {
	MaxClientTenants  int      `json:"max_client_tenants,omitempty"`
	MaxAdminUsers     int      `json:"max_admin_users,omitempty"`
	MaxPowerUsers     int      `json:"max_power_users,omitempty"`
	EnabledFeatures   []string `json:"enabled_features,omitempty"`
	BillingContact    string   `json:"billing_contact,omitempty"`
	SupportContact    string   `json:"support_contact,omitempty"`
	TechnicalContact  string   `json:"technical_contact,omitempty"`
	NotificationEmail string   `json:"notification_email,omitempty"`
	Timezone          string   `json:"timezone,omitempty"`
	Region            string   `json:"region,omitempty"`
}

type CreateMSPRequest struct {
	Name          string      `json:"name" validate:"required,min=1,max=255"`
	RealmName     string      `json:"realm_name" validate:"required,min=1,max=255"`
	Domain        string      `json:"domain,omitempty" validate:"omitempty,fqdn"`
	AdminEmail    string      `json:"admin_email" validate:"required,email"`
	ClientPattern string      `json:"client_realm_pattern,omitempty"`
	Settings      MSPSettings `json:"settings,omitempty"`
}

type UpdateMSPRequest struct {
	Name     string      `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Domain   string      `json:"domain,omitempty" validate:"omitempty,fqdn"`
	Status   MSPStatus   `json:"status,omitempty"`
	Settings MSPSettings `json:"settings,omitempty"`
}

type MSPStaffMember struct {
	UserID    string   `json:"user_id"`
	Username  string   `json:"username"`
	Email     string   `json:"email"`
	FirstName string   `json:"first_name,omitempty"`
	LastName  string   `json:"last_name,omitempty"`
	Roles     []string `json:"roles"`
	Status    string   `json:"status"`
	CreatedAt string   `json:"created_at"`
}

type AddMSPStaffRequest struct {
	Username  string   `json:"username" validate:"required,min=1,max=255"`
	Email     string   `json:"email" validate:"required,email"`
	FirstName string   `json:"first_name,omitempty" validate:"omitempty,max=255"`
	LastName  string   `json:"last_name,omitempty" validate:"omitempty,max=255"`
	Role      string   `json:"role" validate:"required,oneof=msp-admin msp-power msp-viewer"`
	Password  string   `json:"password,omitempty" validate:"omitempty,min=8"`
	Temporary bool     `json:"temporary,omitempty"`
}

type UpdateMSPStaffRolesRequest struct {
	Roles []string `json:"roles" validate:"required,min=1"`
}

type CreateClientTenantRequest struct {
	Name     string         `json:"name" validate:"required,min=1,max=255"`
	Domain   string         `json:"domain,omitempty" validate:"omitempty,fqdn"`
	Settings TenantSettings `json:"settings,omitempty"`
}

type MSPListResponse struct {
	MSPs       []MSP `json:"msps"`
	TotalCount int   `json:"total_count"`
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
}

type MSPStaffListResponse struct {
	Staff      []MSPStaffMember `json:"staff"`
	TotalCount int              `json:"total_count"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
}

type ClientTenantListResponse struct {
	Tenants    []Tenant `json:"tenants"`
	TotalCount int      `json:"total_count"`
	Page       int      `json:"page"`
	PageSize   int      `json:"page_size"`
}

func (m *MSP) IsActive() bool {
	return m.Status == MSPStatusActive
}

func (m *MSP) CanManageClients() bool {
	return m.IsActive()
}

func (m *MSP) GetClientRealmPrefix() string {
	if m.ClientPattern != "" {
		return m.ClientPattern
	}
	
	// Default pattern based on MSP realm name
	if len(m.RealmName) > 4 && m.RealmName[:4] == "msp-" {
		mspName := m.RealmName[4:]
		return mspName + "-client-"
	}
	
	return m.RealmName + "-client-"
}

func (m *MSP) IsClientRealm(realmName string) bool {
	prefix := m.GetClientRealmPrefix()
	return len(realmName) > len(prefix) && realmName[:len(prefix)] == prefix
}
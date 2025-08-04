package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type Role struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID    uuid.UUID      `gorm:"type:uuid;not null;index;uniqueIndex:idx_tenant_role_name" json:"tenant_id"`
	Name        string         `gorm:"not null;size:255;uniqueIndex:idx_tenant_role_name" json:"name" validate:"required,min=1,max=255"`
	Description string         `gorm:"size:1000" json:"description"`
	Permissions datatypes.JSON `gorm:"type:jsonb" json:"permissions"`
	IsSystem    bool           `gorm:"default:false" json:"is_system"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	Tenant Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`
}

type Permissions struct {
	UserCreate bool `json:"user_create"`
	UserRead   bool `json:"user_read"`
	UserUpdate bool `json:"user_update"`
	UserDelete bool `json:"user_delete"`
	UserList   bool `json:"user_list"`

	RoleCreate bool `json:"role_create"`
	RoleRead   bool `json:"role_read"`
	RoleUpdate bool `json:"role_update"`
	RoleDelete bool `json:"role_delete"`
	RoleList   bool `json:"role_list"`
	RoleAssign bool `json:"role_assign"`

	SSOCreate bool `json:"sso_create"`
	SSORead   bool `json:"sso_read"`
	SSOUpdate bool `json:"sso_update"`
	SSODelete bool `json:"sso_delete"`
	SSOTest   bool `json:"sso_test"`

	AuditRead   bool `json:"audit_read"`
	AuditExport bool `json:"audit_export"`

	TenantCreate bool `json:"tenant_create"`
	TenantRead   bool `json:"tenant_read"`
	TenantUpdate bool `json:"tenant_update"`
	TenantDelete bool `json:"tenant_delete"`
	TenantList   bool `json:"tenant_list"`

	SystemConfig   bool `json:"system_config"`
	SystemMonitor  bool `json:"system_monitor"`
	SystemMaintain bool `json:"system_maintain"`

	CustomPermissions map[string]bool `json:"custom_permissions,omitempty"`
}

func (r *Role) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}

func (r *Role) IsSystemRole() bool {
	return r.IsSystem
}

func (r *Role) HasPermission(permission string) bool {
	var permissions Permissions
	if len(r.Permissions) > 0 {
		_ = json.Unmarshal(r.Permissions, &permissions)
	}

	switch permission {
	case "user:create":
		return permissions.UserCreate
	case "user:read":
		return permissions.UserRead
	case "user:update":
		return permissions.UserUpdate
	case "user:delete":
		return permissions.UserDelete
	case "user:list":
		return permissions.UserList
	case "role:create":
		return permissions.RoleCreate
	case "role:read":
		return permissions.RoleRead
	case "role:update":
		return permissions.RoleUpdate
	case "role:delete":
		return permissions.RoleDelete
	case "role:list":
		return permissions.RoleList
	case "role:assign":
		return permissions.RoleAssign
	case "sso:create":
		return permissions.SSOCreate
	case "sso:read":
		return permissions.SSORead
	case "sso:update":
		return permissions.SSOUpdate
	case "sso:delete":
		return permissions.SSODelete
	case "sso:test":
		return permissions.SSOTest
	case "audit:read":
		return permissions.AuditRead
	case "audit:export":
		return permissions.AuditExport
	case "tenant:create":
		return permissions.TenantCreate
	case "tenant:read":
		return permissions.TenantRead
	case "tenant:update":
		return permissions.TenantUpdate
	case "tenant:delete":
		return permissions.TenantDelete
	case "tenant:list":
		return permissions.TenantList
	case "system:config":
		return permissions.SystemConfig
	case "system:monitor":
		return permissions.SystemMonitor
	case "system:maintain":
		return permissions.SystemMaintain
	default:
		if permissions.CustomPermissions != nil {
			return permissions.CustomPermissions[permission]
		}
		return false
	}
}

func (r *Role) GetAllPermissions() []string {
	var permissions []string
	var perms Permissions
	if len(r.Permissions) > 0 {
		_ = json.Unmarshal(r.Permissions, &perms)
	}

	if perms.UserCreate {
		permissions = append(permissions, "user:create")
	}
	if perms.UserRead {
		permissions = append(permissions, "user:read")
	}
	if perms.UserUpdate {
		permissions = append(permissions, "user:update")
	}
	if perms.UserDelete {
		permissions = append(permissions, "user:delete")
	}
	if perms.UserList {
		permissions = append(permissions, "user:list")
	}
	if perms.RoleCreate {
		permissions = append(permissions, "role:create")
	}
	if perms.RoleRead {
		permissions = append(permissions, "role:read")
	}
	if perms.RoleUpdate {
		permissions = append(permissions, "role:update")
	}
	if perms.RoleDelete {
		permissions = append(permissions, "role:delete")
	}
	if perms.RoleList {
		permissions = append(permissions, "role:list")
	}
	if perms.RoleAssign {
		permissions = append(permissions, "role:assign")
	}
	if perms.SSOCreate {
		permissions = append(permissions, "sso:create")
	}
	if perms.SSORead {
		permissions = append(permissions, "sso:read")
	}
	if perms.SSOUpdate {
		permissions = append(permissions, "sso:update")
	}
	if perms.SSODelete {
		permissions = append(permissions, "sso:delete")
	}
	if perms.SSOTest {
		permissions = append(permissions, "sso:test")
	}
	if perms.AuditRead {
		permissions = append(permissions, "audit:read")
	}
	if perms.AuditExport {
		permissions = append(permissions, "audit:export")
	}
	if perms.TenantCreate {
		permissions = append(permissions, "tenant:create")
	}
	if perms.TenantRead {
		permissions = append(permissions, "tenant:read")
	}
	if perms.TenantUpdate {
		permissions = append(permissions, "tenant:update")
	}
	if perms.TenantDelete {
		permissions = append(permissions, "tenant:delete")
	}
	if perms.TenantList {
		permissions = append(permissions, "tenant:list")
	}
	if perms.SystemConfig {
		permissions = append(permissions, "system:config")
	}
	if perms.SystemMonitor {
		permissions = append(permissions, "system:monitor")
	}
	if perms.SystemMaintain {
		permissions = append(permissions, "system:maintain")
	}

	for permission, granted := range perms.CustomPermissions {
		if granted {
			permissions = append(permissions, permission)
		}
	}

	return permissions
}

type CreateRoleRequest struct {
	Name        string      `json:"name" validate:"required,min=1,max=255"`
	Description string      `json:"description" validate:"max=1000"`
	Permissions Permissions `json:"permissions"`
}

type UpdateRoleRequest struct {
	Name        *string      `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Description *string      `json:"description,omitempty" validate:"omitempty,max=1000"`
	Permissions *Permissions `json:"permissions,omitempty"`
}

type RoleResponse struct {
	ID          uuid.UUID   `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Permissions Permissions `json:"permissions"`
	IsSystem    bool        `json:"is_system"`
	UserCount   int         `json:"user_count,omitempty"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

type RoleListResponse struct {
	Roles      []RoleResponse `json:"roles"`
	Total      int64          `json:"total"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	TotalPages int            `json:"total_pages"`
}

func (r *Role) ToResponse() *RoleResponse {
	var permissions Permissions
	if len(r.Permissions) > 0 {
		_ = json.Unmarshal(r.Permissions, &permissions)
	}

	return &RoleResponse{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Permissions: permissions,
		IsSystem:    r.IsSystem,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

type RoleType string

const (
	RoleTypeAdmin RoleType = "admin"
	RoleTypeBasic RoleType = "basic"
	RoleTypePower RoleType = "power"
	RoleTypeMSP   RoleType = "msp"
)

var DefaultRoles = map[string]Permissions{
	"tenant-admin": {
		UserCreate: true, UserRead: true, UserUpdate: true, UserDelete: true, UserList: true,
		RoleCreate: true, RoleRead: true, RoleUpdate: true, RoleDelete: true, RoleList: true, RoleAssign: true,
		SSOCreate: true, SSORead: true, SSOUpdate: true, SSODelete: true, SSOTest: true,
		AuditRead: true, AuditExport: true,
	},
	"tenant-power": {
		UserRead: true, UserUpdate: true, UserList: true,
		RoleRead: true, RoleList: true,
		SSOCreate: true, SSORead: true, SSOUpdate: true, SSODelete: true, SSOTest: true,
		AuditRead: true, AuditExport: true,
	},
	"tenant-basic": {
		UserRead: true, UserList: true,
		RoleRead: true, RoleList: true,
		SSORead:   true,
		AuditRead: true,
	},
}

var MSPRoles = map[string]Permissions{
	"msp-admin": {
		UserCreate: true, UserRead: true, UserUpdate: true, UserDelete: true, UserList: true,
		RoleCreate: true, RoleRead: true, RoleUpdate: true, RoleDelete: true, RoleList: true, RoleAssign: true,
		SSOCreate: true, SSORead: true, SSOUpdate: true, SSODelete: true, SSOTest: true,
		AuditRead: true, AuditExport: true,
		TenantCreate: true, TenantRead: true, TenantUpdate: true, TenantDelete: true, TenantList: true,
		SystemConfig: true, SystemMonitor: true, SystemMaintain: true,
	},
	"msp-power": {
		UserRead: true, UserUpdate: true, UserList: true,
		RoleRead: true, RoleList: true,
		SSORead: true, SSOUpdate: true, SSOTest: true,
		AuditRead: true, AuditExport: true,
		TenantRead: true, TenantUpdate: true, TenantList: true,
		SystemMonitor: true,
	},
	"msp-basic": {
		UserRead: true, UserList: true,
		RoleRead: true, RoleList: true,
		SSORead:    true,
		AuditRead:  true,
		TenantRead: true, TenantList: true,
		SystemMonitor: true,
	},
}

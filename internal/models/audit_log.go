package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

type AuditLog struct {
	ID              string         `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	RealmName       string         `gorm:"not null;index" json:"realm_name"`
	KeycloakUserID  *string        `gorm:"index" json:"keycloak_user_id,omitempty"`
	Action       string         `gorm:"not null;size:255" json:"action" validate:"required"`
	ResourceType string         `gorm:"size:255" json:"resource_type"`
	ResourceID   string         `gorm:"size:255" json:"resource_id"`
	Details      AuditDetails   `gorm:"type:jsonb" json:"details"`
	IPAddress    string         `gorm:"size:45" json:"ip_address"`
	UserAgent    string         `gorm:"size:1000" json:"user_agent"`
	SessionID    string         `gorm:"size:255" json:"session_id"`
	Severity     AuditSeverity  `gorm:"default:'info'" json:"severity"`
	Status       AuditStatus    `gorm:"default:'success'" json:"status"`
	CreatedAt    time.Time      `json:"created_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

}

type AuditSeverity string

const (
	AuditSeverityInfo     AuditSeverity = "info"
	AuditSeverityWarning  AuditSeverity = "warning"
	AuditSeverityError    AuditSeverity = "error"
	AuditSeverityCritical AuditSeverity = "critical"
)

type AuditStatus string

const (
	AuditStatusSuccess AuditStatus = "success"
	AuditStatusFailure AuditStatus = "failure"
	AuditStatusPartial AuditStatus = "partial"
)

type AuditDetails struct {
	Method  string                 `json:"method,omitempty"`
	Path    string                 `json:"path,omitempty"`
	Query   map[string]string      `json:"query,omitempty"`
	Headers map[string]string      `json:"headers,omitempty"`
	Body    map[string]interface{} `json:"body,omitempty"`

	StatusCode int                    `json:"status_code,omitempty"`
	Response   map[string]interface{} `json:"response,omitempty"`

	OldValues map[string]interface{} `json:"old_values,omitempty"`
	NewValues map[string]interface{} `json:"new_values,omitempty"`
	Changes   []string               `json:"changes,omitempty"`

	Error      string `json:"error,omitempty"`
	StackTrace string `json:"stack_trace,omitempty"`

	Permissions []string `json:"permissions,omitempty"`
	Roles       []string `json:"roles,omitempty"`

	Duration int64                  `json:"duration_ms,omitempty"`
	Size     int64                  `json:"size_bytes,omitempty"`
	Tags     []string               `json:"tags,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

func (ad AuditDetails) Value() (driver.Value, error) {
	return json.Marshal(ad)
}

func (ad *AuditDetails) Scan(value interface{}) error {
	if value == nil {
		*ad = AuditDetails{}
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("cannot scan %T into AuditDetails", value)
	}

	return json.Unmarshal(bytes, ad)
}


func (a *AuditLog) IsSecurityEvent() bool {
	securityActions := []string{
		"user.login", "user.logout", "user.login_failed",
		"user.password_changed", "user.mfa_enabled", "user.mfa_disabled",
		"user.created", "user.deleted", "user.suspended",
		"role.assigned", "role.revoked", "role.created", "role.deleted",
		"sso.configured", "sso.test_failed", "sso.activated",
		"tenant.created", "tenant.deleted", "tenant.suspended",
		"permission.granted", "permission.revoked",
		"admin.access", "system.config_changed",
	}

	for _, secAction := range securityActions {
		if a.Action == secAction {
			return true
		}
	}

	return a.Severity == AuditSeverityError || a.Severity == AuditSeverityCritical
}

func (a *AuditLog) IsFailure() bool {
	return a.Status == AuditStatusFailure
}

func (a *AuditLog) GetUserEmail() string {
	return ""
}

type CreateAuditLogRequest struct {
	KeycloakUserID *string       `json:"keycloak_user_id,omitempty"`
	Action       string        `json:"action" validate:"required"`
	ResourceType string        `json:"resource_type,omitempty"`
	ResourceID   string        `json:"resource_id,omitempty"`
	Details      AuditDetails  `json:"details"`
	IPAddress    string        `json:"ip_address"`
	UserAgent    string        `json:"user_agent"`
	SessionID    string        `json:"session_id"`
	Severity     AuditSeverity `json:"severity"`
	Status       AuditStatus   `json:"status"`
}

type AuditLogResponse struct {
	ID             string      `json:"id"`
	RealmName      string      `json:"realm_name"`
	KeycloakUserID *string     `json:"keycloak_user_id,omitempty"`
	UserEmail      string      `json:"user_email,omitempty"`
	Action       string        `json:"action"`
	ResourceType string        `json:"resource_type"`
	ResourceID   string        `json:"resource_id"`
	Details      AuditDetails  `json:"details"`
	IPAddress    string        `json:"ip_address"`
	UserAgent    string        `json:"user_agent"`
	SessionID    string        `json:"session_id"`
	Severity     AuditSeverity `json:"severity"`
	Status       AuditStatus   `json:"status"`
	CreatedAt    time.Time     `json:"created_at"`
}

type AuditLogListResponse struct {
	Logs       []AuditLogResponse `json:"logs"`
	Total      int64              `json:"total"`
	Page       int                `json:"page"`
	PageSize   int                `json:"page_size"`
	TotalPages int                `json:"total_pages"`
}

type AuditLogSearchRequest struct {
	KeycloakUserID *string        `json:"keycloak_user_id,omitempty"`
	RealmName      string         `json:"realm_name,omitempty"`
	Action       string         `json:"action,omitempty"`
	ResourceType string         `json:"resource_type,omitempty"`
	ResourceID   string         `json:"resource_id,omitempty"`
	Severity     *AuditSeverity `json:"severity,omitempty"`
	Status       *AuditStatus   `json:"status,omitempty"`
	IPAddress    string         `json:"ip_address,omitempty"`
	DateFrom     *time.Time     `json:"date_from,omitempty"`
	DateTo       *time.Time     `json:"date_to,omitempty"`
	Page         int            `json:"page" validate:"min=1"`
	PageSize     int            `json:"page_size" validate:"min=1,max=1000"`
	SortBy       string         `json:"sort_by,omitempty"`
	SortOrder    string         `json:"sort_order,omitempty" validate:"omitempty,oneof=asc desc"`
}

type AuditLogStatsResponse struct {
	TotalEvents       int64                   `json:"total_events"`
	SecurityEvents    int64                   `json:"security_events"`
	FailedEvents      int64                   `json:"failed_events"`
	RecentEvents      int64                   `json:"recent_events_24h"`
	TopActions        []ActionCount           `json:"top_actions"`
	TopUsers          []UserActivityCount     `json:"top_users"`
	SeverityBreakdown map[AuditSeverity]int64 `json:"severity_breakdown"`
	StatusBreakdown   map[AuditStatus]int64   `json:"status_breakdown"`
	Timeline          []TimelinePoint         `json:"timeline"`
}

type ActionCount struct {
	Action string `json:"action"`
	Count  int64  `json:"count"`
}

type UserActivityCount struct {
	KeycloakUserID string `json:"keycloak_user_id"`
	UserEmail      string `json:"user_email"`
	Count          int64  `json:"count"`
}

type TimelinePoint struct {
	Timestamp time.Time `json:"timestamp"`
	Count     int64     `json:"count"`
}

func (a *AuditLog) ToResponse() *AuditLogResponse {
	response := &AuditLogResponse{
		ID:             a.ID,
		RealmName:      a.RealmName,
		KeycloakUserID: a.KeycloakUserID,
		Action:       a.Action,
		ResourceType: a.ResourceType,
		ResourceID:   a.ResourceID,
		Details:      a.Details,
		IPAddress:    a.IPAddress,
		UserAgent:    a.UserAgent,
		SessionID:    a.SessionID,
		Severity:     a.Severity,
		Status:       a.Status,
		CreatedAt:    a.CreatedAt,
	}

	return response
}

var AuditActions = struct {
	UserLogin           string
	UserLogout          string
	UserLoginFailed     string
	UserCreated         string
	UserUpdated         string
	UserDeleted         string
	UserSuspended       string
	UserActivated       string
	UserPasswordChanged string
	UserMFAEnabled      string
	UserMFADisabled     string

	RoleCreated  string
	RoleUpdated  string
	RoleDeleted  string
	RoleAssigned string
	RoleRevoked  string

	SSOConfigured  string
	SSOUpdated     string
	SSODeleted     string
	SSOTested      string
	SSOTestFailed  string
	SSOActivated   string
	SSODeactivated string

	TenantCreated   string
	TenantUpdated   string
	TenantDeleted   string
	TenantSuspended string
	TenantActivated string

	SystemConfigChanged string
	AdminAccess         string
	APIKeyCreated       string
	APIKeyDeleted       string

	DataExported string
	DataImported string
	DataBackedUp string
	DataRestored string
}{
	UserLogin:           "user.login",
	UserLogout:          "user.logout",
	UserLoginFailed:     "user.login_failed",
	UserCreated:         "user.created",
	UserUpdated:         "user.updated",
	UserDeleted:         "user.deleted",
	UserSuspended:       "user.suspended",
	UserActivated:       "user.activated",
	UserPasswordChanged: "user.password_changed",
	UserMFAEnabled:      "user.mfa_enabled",
	UserMFADisabled:     "user.mfa_disabled",

	RoleCreated:  "role.created",
	RoleUpdated:  "role.updated",
	RoleDeleted:  "role.deleted",
	RoleAssigned: "role.assigned",
	RoleRevoked:  "role.revoked",

	SSOConfigured:  "sso.configured",
	SSOUpdated:     "sso.updated",
	SSODeleted:     "sso.deleted",
	SSOTested:      "sso.tested",
	SSOTestFailed:  "sso.test_failed",
	SSOActivated:   "sso.activated",
	SSODeactivated: "sso.deactivated",

	TenantCreated:   "tenant.created",
	TenantUpdated:   "tenant.updated",
	TenantDeleted:   "tenant.deleted",
	TenantSuspended: "tenant.suspended",
	TenantActivated: "tenant.activated",

	SystemConfigChanged: "system.config_changed",
	AdminAccess:         "admin.access",
	APIKeyCreated:       "api_key.created",
	APIKeyDeleted:       "api_key.deleted",

	DataExported: "data.exported",
	DataImported: "data.imported",
	DataBackedUp: "data.backed_up",
	DataRestored: "data.restored",
}

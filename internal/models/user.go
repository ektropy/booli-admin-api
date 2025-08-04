package models

import (
	"time"

	"github.com/google/uuid"
)

type UserType string

const (
	UserTypeTenant UserType = "tenant"
	UserTypeMSP    UserType = "msp"
)

type User struct {
	ID                   string         `json:"id"`
	TenantID             uuid.UUID      `json:"tenant_id"`
	KeycloakOrganization string         `json:"-"`
	Email                string         `json:"email" validate:"required,email"`
	FirstName            string         `json:"first_name" validate:"required,min=1,max=255"`
	LastName             string         `json:"last_name" validate:"required,min=1,max=255"`
	Username             string         `json:"username"`
	Enabled              bool           `json:"enabled"`
	EmailVerified        bool           `json:"email_verified"`
	Attributes           UserAttributes `gorm:"-" json:"attributes"`
	Roles                []string       `gorm:"-" json:"roles,omitempty"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
}

type UserAttributes struct {
	Department   string            `json:"department,omitempty"`
	JobTitle     string            `json:"job_title,omitempty"`
	PhoneNumber  string            `json:"phone_number,omitempty"`
	Location     string            `json:"location,omitempty"`
	Manager      string            `json:"manager,omitempty"`
	CostCenter   string            `json:"cost_center,omitempty"`
	CustomFields map[string]string `gorm:"-" json:"custom_fields,omitempty"`
}

func (u *User) IsUserActive() bool {
	return u.Enabled
}

func (u *User) GetFullName() string {
	return u.FirstName + " " + u.LastName
}

type CreateUserRequest struct {
	TenantID          uuid.UUID       `json:"tenant_id,omitempty"`
	TenantName        string          `json:"tenant_name,omitempty"`
	TenantDomain      string          `json:"tenant_domain,omitempty"`
	Email             string          `json:"email" validate:"required,email"`
	FirstName         string          `json:"first_name" validate:"required,min=1,max=255"`
	LastName          string          `json:"last_name" validate:"required,min=1,max=255"`
	Username          string          `json:"username,omitempty" validate:"omitempty,min=1,max=255"`
	Password          string          `json:"password,omitempty" validate:"omitempty,min=8"`
	TemporaryPassword bool            `json:"temporary_password"`
	Enabled           bool            `json:"enabled"`
	Attributes        *UserAttributes `json:"attributes,omitempty"`
	Roles             []string        `json:"roles,omitempty"`
	SendInvite        bool            `json:"send_invite"`
}

type UpdateUserRequest struct {
	Email             *string         `json:"email,omitempty" validate:"omitempty,email"`
	FirstName         *string         `json:"first_name,omitempty" validate:"omitempty,min=1,max=255"`
	LastName          *string         `json:"last_name,omitempty" validate:"omitempty,min=1,max=255"`
	Username          *string         `json:"username,omitempty" validate:"omitempty,min=1,max=255"`
	Password          *string         `json:"password,omitempty" validate:"omitempty,min=8"`
	TemporaryPassword *bool           `json:"temporary_password,omitempty"`
	Enabled           *bool           `json:"enabled,omitempty"`
	Attributes        *UserAttributes `json:"attributes,omitempty"`
	Roles             *[]string       `json:"roles,omitempty"`
}

type BulkCreateUserRequest struct {
	Users            []CreateUserRequest `json:"users" validate:"required,min=1,max=1000"`
	SendInvite       bool                `json:"send_invite"`
	DefaultRoleNames []string            `json:"default_role_names,omitempty"`
}

type UserResponse struct {
	ID            string         `json:"id"`
	Email         string         `json:"email"`
	FirstName     string         `json:"first_name"`
	LastName      string         `json:"last_name"`
	Username      string         `json:"username"`
	Enabled       bool           `json:"enabled"`
	EmailVerified bool           `json:"email_verified"`
	Attributes    UserAttributes `gorm:"-" json:"attributes"`
	Roles         []string       `gorm:"-" json:"roles,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

type UserListResponse struct {
	Users      []User `json:"users"`
	Total      int64  `json:"total"`
	Page       int    `json:"page"`
	PageSize   int    `json:"page_size"`
	TotalPages int    `json:"total_pages"`
}

type UserSearchRequest struct {
	SearchTerm string `json:"search_term,omitempty"`
	Status     string `json:"status,omitempty"`
	Department string `json:"department,omitempty"`
	Role       string `json:"role,omitempty"`
	Page       int    `json:"page" validate:"min=1"`
	PageSize   int    `json:"page_size" validate:"min=1,max=100"`
	SortBy     string `json:"sort_by,omitempty"`
	SortOrder  string `json:"sort_order,omitempty" validate:"omitempty,oneof=asc desc"`
}

func (u *User) ToResponse() *UserResponse {
	return &UserResponse{
		ID:            u.ID,
		Email:         u.Email,
		FirstName:     u.FirstName,
		LastName:      u.LastName,
		Username:      u.Username,
		Enabled:       u.Enabled,
		EmailVerified: u.EmailVerified,
		Attributes:    u.Attributes,
		Roles:         u.Roles,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}
}

type AssignRoleRequest struct {
	RoleName string `json:"role_name" validate:"required"`
}

type RevokeRoleRequest struct {
	RoleName string `json:"role_name" validate:"required"`
}

type CSVImportResult struct {
	SuccessfulUsers []User     `json:"successful_users"`
	FailedUsers     []CSVError `json:"failed_users"`
	TotalProcessed  int        `json:"total_processed"`
	SuccessCount    int        `json:"success_count"`
	ErrorCount      int        `json:"error_count"`
}

type CSVError struct {
	Row     int    `json:"row"`
	Email   string `json:"email"`
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

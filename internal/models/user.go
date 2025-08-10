package models

import (
	"github.com/google/uuid"
)

type User struct {
	ID        string   `json:"id"`
	Username  string   `json:"username"`
	Email     string   `json:"email"`
	FirstName string   `json:"first_name"`
	LastName  string   `json:"last_name"`
	Enabled   bool     `json:"enabled"`
	Roles     []string `json:"roles,omitempty"`
}

type CreateUserRequest struct {
	TenantID          uuid.UUID `json:"tenant_id,omitempty"`
	TenantName        string    `json:"tenant_name,omitempty"`
	TenantDomain      string    `json:"tenant_domain,omitempty"`
	Username          string    `json:"username" validate:"required,min=3,max=50"`
	Email             string    `json:"email" validate:"required,email"`
	FirstName         string    `json:"first_name" validate:"required,min=1,max=50"`
	LastName          string    `json:"last_name" validate:"required,min=1,max=50"`
	Password          string    `json:"password,omitempty"`
	TemporaryPassword bool      `json:"temporary_password,omitempty"`
	Enabled           bool      `json:"enabled"`
	Roles             []string  `json:"roles,omitempty"`
	DefaultRole       string    `json:"default_role,omitempty"`
	Attributes        map[string][]string `json:"attributes,omitempty"`
	SendInvite        bool      `json:"send_invite,omitempty"`
}

type UpdateUserRequest struct {
	Email             *string  `json:"email,omitempty" validate:"omitempty,email"`
	FirstName         *string  `json:"first_name,omitempty" validate:"omitempty,min=1,max=50"`
	LastName          *string  `json:"last_name,omitempty" validate:"omitempty,min=1,max=50"`
	Enabled           *bool    `json:"enabled,omitempty"`
	Password          *string  `json:"password,omitempty"`
	TemporaryPassword *bool    `json:"temporary_password,omitempty"`
	Roles             *[]string `json:"roles,omitempty"`
}

type UserSearchRequest struct {
	Search     string `json:"search,omitempty"`
	SearchTerm string `json:"search_term,omitempty"`
	Status     string `json:"status,omitempty"`
	Role       string `json:"role,omitempty"`
	Enabled    *bool  `json:"enabled,omitempty"`
	Page       int    `json:"page"`
	PageSize   int    `json:"page_size"`
}

type BulkCreateUserRequest struct {
	Users            []CreateUserRequest `json:"users" validate:"required,min=1,max=100"`
	DefaultRoleNames []string           `json:"default_role_names,omitempty"`
	SendInvite       bool               `json:"send_invite,omitempty"`
}

type UserListResponse struct {
	Users      []User `json:"users"`
	Total      int64  `json:"total"`
	Page       int    `json:"page"`
	PageSize   int    `json:"page_size"`
	TotalPages int    `json:"total_pages"`
}

type UserResponse struct {
	ID        string   `json:"id"`
	Username  string   `json:"username"`
	Email     string   `json:"email"`
	FirstName string   `json:"first_name"`
	LastName  string   `json:"last_name"`
	Enabled   bool     `json:"enabled"`
	Roles     []string `json:"roles,omitempty"`
}

type BulkCreateResult struct {
	TotalProcessed int           `json:"total_processed"`
	SuccessCount   int           `json:"success_count"`
	FailureCount   int           `json:"failure_count"`
	Successful     []*User       `json:"successful,omitempty"`
	Failed         []BulkError   `json:"failed,omitempty"`
}

type BulkError struct {
	Row   int    `json:"row,omitempty"`
	Email string `json:"email,omitempty"`
	Error string `json:"error"`
}

type CSVImportResult struct {
	TotalProcessed  int         `json:"total_processed"`
	SuccessCount    int         `json:"success_count"`
	ErrorCount      int         `json:"error_count"`
	SuccessfulUsers []User      `json:"successful_users,omitempty"`
	FailedUsers     []CSVError  `json:"failed_users,omitempty"`
	ParseErrors     []CSVError  `json:"parse_errors,omitempty"`
}

type CSVError struct {
	Row   int    `json:"row"`
	Email string `json:"email,omitempty"`
	Error string `json:"error"`
}

func (u *User) ToResponse() *UserResponse {
	return &UserResponse{
		ID:        u.ID,
		Username:  u.Username,
		Email:     u.Email,
		FirstName: u.FirstName,
		LastName:  u.LastName,
		Enabled:   u.Enabled,
		Roles:     u.Roles,
	}
}
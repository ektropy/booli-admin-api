package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/booli/booli-admin-api/internal/config"
	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type UserService struct {
	db            *gorm.DB
	redis         *redis.Client
	keycloakAdmin *keycloak.AdminClient
	logger        *zap.Logger
	config        *config.Config
}

func NewUserService(db *gorm.DB, redis *redis.Client, keycloakAdmin *keycloak.AdminClient, logger *zap.Logger, cfg *config.Config) *UserService {
	return &UserService{
		db:            db,
		redis:         redis,
		keycloakAdmin: keycloakAdmin,
		logger:        logger,
		config:        cfg,
	}
}

func (s *UserService) ListUsers(ctx context.Context, tenantID uuid.UUID, req *models.UserSearchRequest) ([]models.User, int64, error) {
	var tenant models.Tenant
	if err := s.db.WithContext(ctx).Where("id = ?", tenantID).First(&tenant).Error; err != nil {
		return nil, 0, fmt.Errorf("tenant not found: %w", err)
	}

	if tenant.KeycloakOrganizationID == "" {
		return nil, 0, fmt.Errorf("tenant has no Keycloak organization")
	}

	members, err := s.keycloakAdmin.ListOrganizationMembers(ctx, s.config.Keycloak.MSPRealm, tenant.KeycloakOrganizationID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get organization members from Keycloak: %w", err)
	}

	var users []models.User
	for _, member := range members {
		user := models.User{
			ID:                   member.ID,
			Username:             member.Username,
			Email:                member.Email,
			FirstName:            member.FirstName,
			LastName:             member.LastName,
			Enabled:              member.Enabled,
			KeycloakOrganization: tenant.KeycloakOrganizationID,
		}
		users = append(users, user)
	}

	filteredUsers := s.filterUsers(users, req)
	total := int64(len(filteredUsers))

	if req.Page > 0 && req.PageSize > 0 {
		start := (req.Page - 1) * req.PageSize
		end := start + req.PageSize
		if start < len(filteredUsers) {
			if end > len(filteredUsers) {
				end = len(filteredUsers)
			}
			filteredUsers = filteredUsers[start:end]
		} else {
			filteredUsers = []models.User{}
		}
	}

	return filteredUsers, total, nil
}

func (s *UserService) GetUser(ctx context.Context, tenantID uuid.UUID, userID string) (*models.User, error) {
	var tenant models.Tenant
	if err := s.db.WithContext(ctx).Where("id = ?", tenantID).First(&tenant).Error; err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	if tenant.KeycloakOrganizationID == "" {
		return nil, fmt.Errorf("tenant has no Keycloak organization")
	}

	keycloakUser, err := s.keycloakAdmin.GetUser(ctx, s.config.Keycloak.MSPRealm, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found in Keycloak: %w", err)
	}

	members, err := s.keycloakAdmin.ListOrganizationMembers(ctx, s.config.Keycloak.MSPRealm, tenant.KeycloakOrganizationID)
	if err != nil {
		return nil, fmt.Errorf("failed to verify organization membership: %w", err)
	}

	isMember := false
	for _, member := range members {
		if member.ID == userID {
			isMember = true
			break
		}
	}

	if !isMember {
		return nil, fmt.Errorf("user is not a member of this organization")
	}

	roles, err := s.keycloakAdmin.GetUserRealmRoles(ctx, s.config.Keycloak.MSPRealm, userID)
	if err != nil {
		s.logger.Warn("Failed to get user roles", zap.Error(err))
	}

	var roleNames []string
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}

	user := &models.User{
		ID:                   keycloakUser.ID,
		Username:             keycloakUser.Username,
		Email:                keycloakUser.Email,
		FirstName:            keycloakUser.FirstName,
		LastName:             keycloakUser.LastName,
		Enabled:              keycloakUser.Enabled,
		KeycloakOrganization: tenant.KeycloakOrganizationID,
		Roles:                roleNames,
	}

	return user, nil
}

func (s *UserService) CreateUser(ctx context.Context, req *models.CreateUserRequest) (*models.User, error) {
	var tenant models.Tenant
	var err error

	if req.TenantID != uuid.Nil {
		if err := s.db.WithContext(ctx).Where("id = ?", req.TenantID).First(&tenant).Error; err != nil {
			return nil, fmt.Errorf("tenant not found: %w", err)
		}
	} else if req.TenantName != "" {
		if err := s.db.WithContext(ctx).Where("name = ?", req.TenantName).First(&tenant).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return nil, fmt.Errorf("tenant not found with name: %s", req.TenantName)
			}
			return nil, fmt.Errorf("failed to lookup tenant by name: %w", err)
		}
	} else if req.TenantDomain != "" {
		if err := s.db.WithContext(ctx).Where("domain = ?", req.TenantDomain).First(&tenant).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return nil, fmt.Errorf("tenant not found with domain: %s", req.TenantDomain)
			}
			return nil, fmt.Errorf("failed to lookup tenant by domain: %w", err)
		}
	} else {
		return nil, fmt.Errorf("tenant identifier is required (tenant_id, tenant_name, or tenant_domain)")
	}

	req.TenantID = tenant.ID

	if tenant.KeycloakOrganizationID == "" {
		return nil, fmt.Errorf("tenant has no Keycloak organization")
	}

	keycloakUser := &keycloak.UserRepresentation{
		Username:      req.Username,
		Email:         req.Email,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		Enabled:       true,
		EmailVerified: false,
	}

	if req.Password != "" {
		keycloakUser.Credentials = []keycloak.CredentialRepresentation{
			{
				Type:      "password",
				Value:     req.Password,
				Temporary: req.TemporaryPassword,
			},
		}
	}

	createdUser, err := s.keycloakAdmin.CreateUser(ctx, s.config.Keycloak.MSPRealm, keycloakUser)
	if err != nil {
		return nil, fmt.Errorf("failed to create user in Keycloak: %w", err)
	}

	if err := s.keycloakAdmin.AddOrganizationMember(ctx, s.config.Keycloak.MSPRealm, tenant.KeycloakOrganizationID, createdUser.ID); err != nil {
		_ = s.keycloakAdmin.DeleteUser(ctx, s.config.Keycloak.MSPRealm, createdUser.ID)
		return nil, fmt.Errorf("failed to add user to organization: %w", err)
	}

	if len(req.Roles) > 0 {
		if err := s.assignRolesToUser(ctx, createdUser.ID, req.Roles); err != nil {
			s.logger.Warn("Failed to assign roles to user", zap.Error(err))
		}
	}

	user := &models.User{
		ID:                   createdUser.ID,
		Username:             createdUser.Username,
		Email:                createdUser.Email,
		FirstName:            createdUser.FirstName,
		LastName:             createdUser.LastName,
		Enabled:              createdUser.Enabled,
		KeycloakOrganization: tenant.KeycloakOrganizationID,
		Roles:                req.Roles,
	}

	s.logger.Info("User created successfully",
		zap.String("user_id", user.ID),
		zap.String("username", user.Username),
		zap.String("organization_id", tenant.KeycloakOrganizationID))

	return user, nil
}

func (s *UserService) UpdateUser(ctx context.Context, tenantID uuid.UUID, userID string, req *models.UpdateUserRequest) (*models.User, error) {
	var tenant models.Tenant
	if err := s.db.WithContext(ctx).Where("id = ?", tenantID).First(&tenant).Error; err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	if tenant.KeycloakOrganizationID == "" {
		return nil, fmt.Errorf("tenant has no Keycloak organization")
	}

	existingUser, err := s.keycloakAdmin.GetUser(ctx, s.config.Keycloak.MSPRealm, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	if req.Email != nil {
		existingUser.Email = *req.Email
	}
	if req.FirstName != nil {
		existingUser.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		existingUser.LastName = *req.LastName
	}
	if req.Enabled != nil {
		existingUser.Enabled = *req.Enabled
	}

	if req.Password != nil {
		existingUser.Credentials = []keycloak.CredentialRepresentation{
			{
				Type:      "password",
				Value:     *req.Password,
				Temporary: req.TemporaryPassword != nil && *req.TemporaryPassword,
			},
		}
	}

	if err := s.keycloakAdmin.UpdateUser(ctx, s.config.Keycloak.MSPRealm, userID, existingUser); err != nil {
		return nil, fmt.Errorf("failed to update user in Keycloak: %w", err)
	}

	if req.Roles != nil {
		if err := s.assignRolesToUser(ctx, userID, *req.Roles); err != nil {
			s.logger.Warn("Failed to update user roles", zap.Error(err))
		}
	}

	return s.GetUser(ctx, tenantID, userID)
}

func (s *UserService) DeleteUser(ctx context.Context, tenantID uuid.UUID, userID string) error {
	var tenant models.Tenant
	if err := s.db.WithContext(ctx).Where("id = ?", tenantID).First(&tenant).Error; err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}

	if tenant.KeycloakOrganizationID == "" {
		return fmt.Errorf("tenant has no Keycloak organization")
	}

	if err := s.keycloakAdmin.RemoveOrganizationMember(ctx, s.config.Keycloak.MSPRealm, tenant.KeycloakOrganizationID, userID); err != nil {
		s.logger.Warn("Failed to remove user from organization", zap.Error(err))
	}

	if err := s.keycloakAdmin.DeleteUser(ctx, s.config.Keycloak.MSPRealm, userID); err != nil {
		return fmt.Errorf("failed to delete user from Keycloak: %w", err)
	}

	s.logger.Info("User deleted successfully",
		zap.String("user_id", userID),
		zap.String("organization_id", tenant.KeycloakOrganizationID))

	return nil
}

func (s *UserService) ChangePassword(ctx context.Context, tenantID uuid.UUID, userID string, newPassword string, temporary bool) error {
	var tenant models.Tenant
	if err := s.db.WithContext(ctx).Where("id = ?", tenantID).First(&tenant).Error; err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}

	if tenant.KeycloakOrganizationID == "" {
		return fmt.Errorf("tenant has no Keycloak organization")
	}

	existingUser, err := s.keycloakAdmin.GetUser(ctx, s.config.Keycloak.MSPRealm, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	existingUser.Credentials = []keycloak.CredentialRepresentation{
		{
			Type:      "password",
			Value:     newPassword,
			Temporary: temporary,
		},
	}

	if err := s.keycloakAdmin.UpdateUser(ctx, s.config.Keycloak.MSPRealm, userID, existingUser); err != nil {
		return fmt.Errorf("failed to change password: %w", err)
	}

	s.logger.Info("Password changed successfully",
		zap.String("user_id", userID),
		zap.String("organization_id", tenant.KeycloakOrganizationID))

	return nil
}

func (s *UserService) assignRolesToUser(ctx context.Context, userID string, roleNames []string) error {
	var roles []keycloak.RoleRepresentation

	for _, roleName := range roleNames {
		role, err := s.keycloakAdmin.GetRealmRole(ctx, s.config.Keycloak.MSPRealm, roleName)
		if err != nil {
			return fmt.Errorf("failed to get role %s: %w", roleName, err)
		}
		roles = append(roles, *role)
	}

	if len(roles) > 0 {
		if err := s.keycloakAdmin.AssignRealmRolesToUser(ctx, s.config.Keycloak.MSPRealm, userID, roles); err != nil {
			return fmt.Errorf("failed to assign roles to user: %w", err)
		}
	}

	return nil
}

func (s *UserService) filterUsers(users []models.User, req *models.UserSearchRequest) []models.User {
	var filtered []models.User

	for _, user := range users {
		if req.SearchTerm != "" {
			searchTerm := req.SearchTerm
			if !s.userMatchesSearch(user, searchTerm) {
				continue
			}
		}

		if req.Status != "" {
			if req.Status == "enabled" && !user.Enabled {
				continue
			}
			if req.Status == "disabled" && user.Enabled {
				continue
			}
		}

		if req.Role != "" {
			hasRole := false
			for _, role := range user.Roles {
				if role == req.Role {
					hasRole = true
					break
				}
			}
			if !hasRole {
				continue
			}
		}

		filtered = append(filtered, user)
	}

	return filtered
}

func (s *UserService) userMatchesSearch(user models.User, searchTerm string) bool {
	term := strings.ToLower(searchTerm)
	return strings.Contains(strings.ToLower(user.Username), term) ||
		strings.Contains(strings.ToLower(user.Email), term) ||
		strings.Contains(strings.ToLower(user.FirstName), term) ||
		strings.Contains(strings.ToLower(user.LastName), term)
}

func (s *UserService) BulkCreateUsers(ctx context.Context, tenantID uuid.UUID, req *models.BulkCreateUserRequest) ([]models.User, error) {
	var tenant models.Tenant
	if err := s.db.WithContext(ctx).Where("id = ?", tenantID).First(&tenant).Error; err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	if tenant.KeycloakOrganizationID == "" {
		return nil, fmt.Errorf("tenant has no Keycloak organization")
	}

	var createdUsers []models.User
	var errors []string

	for i, userReq := range req.Users {
		roles := userReq.Roles
		if len(roles) == 0 && len(req.DefaultRoleNames) > 0 {
			roles = req.DefaultRoleNames
		}

		createReq := &models.CreateUserRequest{
			TenantID:          tenantID,
			Email:             userReq.Email,
			FirstName:         userReq.FirstName,
			LastName:          userReq.LastName,
			Username:          userReq.Username,
			Password:          userReq.Password,
			TemporaryPassword: userReq.TemporaryPassword,
			Enabled:           userReq.Enabled,
			Attributes:        userReq.Attributes,
			Roles:             roles,
			SendInvite:        req.SendInvite,
		}

		createReq.TenantID = tenantID
		user, err := s.CreateUser(ctx, createReq)
		if err != nil {
			errors = append(errors, fmt.Sprintf("User %d (%s): %v", i+1, userReq.Email, err))
			continue
		}

		createdUsers = append(createdUsers, *user)
	}

	if len(errors) > 0 {
		s.logger.Warn("Some users failed to create during bulk operation",
			zap.Strings("errors", errors),
			zap.String("organization_id", tenant.KeycloakOrganizationID))
	}

	s.logger.Info("Bulk user creation completed",
		zap.Int("total_requested", len(req.Users)),
		zap.Int("successfully_created", len(createdUsers)),
		zap.Int("failed", len(errors)),
		zap.String("organization_id", tenant.KeycloakOrganizationID))

	return createdUsers, nil
}

type CSVImportResult struct {
	SuccessfulUsers []models.User `json:"successful_users"`
	FailedUsers     []CSVError    `json:"failed_users"`
	TotalProcessed  int           `json:"total_processed"`
	SuccessCount    int           `json:"success_count"`
	ErrorCount      int           `json:"error_count"`
}

type CSVError struct {
	Row     int    `json:"row"`
	Email   string `json:"email"`
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

func (s *UserService) ImportUsersFromCSV(ctx context.Context, tenantID uuid.UUID, records [][]string) (*CSVImportResult, error) {
	var tenant models.Tenant
	if err := s.db.WithContext(ctx).Where("id = ?", tenantID).First(&tenant).Error; err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	if tenant.KeycloakOrganizationID == "" {
		return nil, fmt.Errorf("tenant has no Keycloak organization")
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("CSV must contain at least a header and one data row")
	}

	header := records[0]
	columnMap := make(map[string]int)
	for i, col := range header {
		columnMap[strings.ToLower(strings.TrimSpace(col))] = i
	}

	requiredColumns := []string{"email", "first_name", "last_name"}
	for _, required := range requiredColumns {
		if _, exists := columnMap[required]; !exists {
			return nil, fmt.Errorf("required column '%s' not found in CSV header", required)
		}
	}

	result := &CSVImportResult{
		TotalProcessed: len(records) - 1, // Exclude header
	}

	for rowIndex, record := range records[1:] {
		actualRow := rowIndex + 2 // +2 because we skip header and arrays are 0-indexed

		if len(record) < len(header) {
			result.FailedUsers = append(result.FailedUsers, CSVError{
				Row:   actualRow,
				Error: "Insufficient columns in row",
			})
			continue
		}

		email := strings.TrimSpace(record[columnMap["email"]])
		firstName := strings.TrimSpace(record[columnMap["first_name"]])
		lastName := strings.TrimSpace(record[columnMap["last_name"]])

		if email == "" || firstName == "" || lastName == "" {
			result.FailedUsers = append(result.FailedUsers, CSVError{
				Row:   actualRow,
				Email: email,
				Error: "Missing required fields (email, first_name, last_name)",
			})
			continue
		}

		username := email // Default username to email
		if usernameCol, exists := columnMap["username"]; exists && usernameCol < len(record) {
			if u := strings.TrimSpace(record[usernameCol]); u != "" {
				username = u
			}
		}

		password := ""
		if passwordCol, exists := columnMap["password"]; exists && passwordCol < len(record) {
			password = strings.TrimSpace(record[passwordCol])
		}

		enabled := true
		if enabledCol, exists := columnMap["enabled"]; exists && enabledCol < len(record) {
			if e := strings.TrimSpace(record[enabledCol]); e != "" {
				enabled = strings.ToLower(e) == "true" || e == "1"
			}
		}

		var roles []string
		if rolesCol, exists := columnMap["roles"]; exists && rolesCol < len(record) {
			if r := strings.TrimSpace(record[rolesCol]); r != "" {
				for _, role := range strings.Split(r, ",") {
					if cleaned := strings.TrimSpace(role); cleaned != "" {
						roles = append(roles, cleaned)
					}
				}
			}
		}

		createReq := &models.CreateUserRequest{
			TenantID:          tenantID,
			Email:             email,
			FirstName:         firstName,
			LastName:          lastName,
			Username:          username,
			Password:          password,
			TemporaryPassword: password != "", // If password provided, make it temporary
			Enabled:           enabled,
			Roles:             roles,
			SendInvite:        false, // Don't send invites during CSV import
		}

		createReq.TenantID = tenantID
		user, err := s.CreateUser(ctx, createReq)
		if err != nil {
			result.FailedUsers = append(result.FailedUsers, CSVError{
				Row:     actualRow,
				Email:   email,
				Error:   "Failed to create user",
				Details: err.Error(),
			})
			continue
		}

		result.SuccessfulUsers = append(result.SuccessfulUsers, *user)
	}

	result.SuccessCount = len(result.SuccessfulUsers)
	result.ErrorCount = len(result.FailedUsers)

	s.logger.Info("CSV import completed",
		zap.Int("total_processed", result.TotalProcessed),
		zap.Int("successful", result.SuccessCount),
		zap.Int("failed", result.ErrorCount),
		zap.String("organization_id", tenant.KeycloakOrganizationID))

	return result, nil
}

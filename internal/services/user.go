package services

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/booli/booli-admin-api/internal/models"
	"go.uber.org/zap"
)

// UserService manages users through Keycloak (no database dependencies)
type UserService struct {
	keycloakAdmin *keycloak.AdminClient
	logger        *zap.Logger
}

// NewUserService creates a new user service
func NewUserService(keycloakAdmin *keycloak.AdminClient, logger *zap.Logger) *UserService {
	return &UserService{
		keycloakAdmin: keycloakAdmin,
		logger:        logger,
	}
}

// ListUsers retrieves users from a Keycloak realm
func (s *UserService) ListUsers(ctx context.Context, realmName string, req *models.UserSearchRequest) ([]models.User, int64, error) {
	keycloakUsers, err := s.keycloakAdmin.GetUsers(ctx, realmName)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get users from Keycloak realm: %w", err)
	}

	var users []models.User
	for _, kcUser := range keycloakUsers {
		user := models.User{
			ID:        kcUser.ID,
			Username:  kcUser.Username,
			Email:     kcUser.Email,
			FirstName: kcUser.FirstName,
			LastName:  kcUser.LastName,
			Enabled:   kcUser.Enabled,
		}
		users = append(users, user)
	}

	// Apply client-side filtering
	filteredUsers := s.filterUsers(users, req)
	total := int64(len(filteredUsers))

	// Apply pagination
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

// GetUser retrieves a specific user from a Keycloak realm
func (s *UserService) GetUser(ctx context.Context, realmName, userID string) (*models.User, error) {
	keycloakUser, err := s.keycloakAdmin.GetUser(ctx, realmName, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found in Keycloak: %w", err)
	}

	// Get user roles
	roles, err := s.keycloakAdmin.GetUserRealmRoles(ctx, realmName, userID)
	if err != nil {
		s.logger.Warn("Failed to get user roles", zap.Error(err))
	}

	var roleNames []string
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}

	user := &models.User{
		ID:        keycloakUser.ID,
		Username:  keycloakUser.Username,
		Email:     keycloakUser.Email,
		FirstName: keycloakUser.FirstName,
		LastName:  keycloakUser.LastName,
		Enabled:   keycloakUser.Enabled,
		Roles:     roleNames,
	}

	return user, nil
}

// CreateUser creates a new user in a Keycloak realm
func (s *UserService) CreateUser(ctx context.Context, realmName string, req *models.CreateUserRequest) (*models.User, error) {
	// Create user in Keycloak
	keycloakUser := &keycloak.UserRepresentation{
		Username:  req.Username,
		Email:     req.Email,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Enabled:   req.Enabled,
	}

	// Add credentials if password is provided
	if req.Password != "" {
		keycloakUser.Credentials = []keycloak.CredentialRepresentation{
			{
				Type:      "password",
				Value:     req.Password,
				Temporary: req.TemporaryPassword,
			},
		}
	}

	createdUser, err := s.keycloakAdmin.CreateUser(ctx, realmName, keycloakUser)
	if err != nil {
		return nil, fmt.Errorf("failed to create user in Keycloak: %w", err)
	}

	// Assign default role if specified
	if req.DefaultRole != "" {
		if err := s.keycloakAdmin.AssignRealmRoleToUser(ctx, realmName, createdUser.ID, req.DefaultRole); err != nil {
			s.logger.Warn("Failed to assign default role to user",
				zap.String("user_id", createdUser.ID),
				zap.String("role", req.DefaultRole),
				zap.Error(err))
		}
	}

	s.logger.Info("Created user",
		zap.String("realm", realmName),
		zap.String("username", req.Username),
		zap.String("user_id", createdUser.ID))

	// Return the created user
	return s.GetUser(ctx, realmName, createdUser.ID)
}

// UpdateUser updates a user in a Keycloak realm
func (s *UserService) UpdateUser(ctx context.Context, realmName, userID string, req *models.UpdateUserRequest) (*models.User, error) {
	// Get current user
	currentUser, err := s.keycloakAdmin.GetUser(ctx, realmName, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Update fields if provided
	updateUser := *currentUser
	if req.Email != nil {
		updateUser.Email = *req.Email
	}
	if req.FirstName != nil {
		updateUser.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		updateUser.LastName = *req.LastName
	}
	if req.Enabled != nil {
		updateUser.Enabled = *req.Enabled
	}

	// Update user in Keycloak
	if err := s.keycloakAdmin.UpdateUser(ctx, realmName, userID, &updateUser); err != nil {
		return nil, fmt.Errorf("failed to update user in Keycloak: %w", err)
	}

	s.logger.Info("Updated user",
		zap.String("realm", realmName),
		zap.String("user_id", userID))

	// Return the updated user
	return s.GetUser(ctx, realmName, userID)
}

// DeleteUser deletes a user from a Keycloak realm
func (s *UserService) DeleteUser(ctx context.Context, realmName, userID string) error {
	if err := s.keycloakAdmin.DeleteUser(ctx, realmName, userID); err != nil {
		return fmt.Errorf("failed to delete user from Keycloak: %w", err)
	}

	s.logger.Info("Deleted user",
		zap.String("realm", realmName),
		zap.String("user_id", userID))

	return nil
}

// AssignRole assigns a role to a user
func (s *UserService) AssignRole(ctx context.Context, realmName, userID, roleName string) error {
	if err := s.keycloakAdmin.AssignRealmRoleToUser(ctx, realmName, userID, roleName); err != nil {
		return fmt.Errorf("failed to assign role to user: %w", err)
	}

	s.logger.Info("Assigned role to user",
		zap.String("realm", realmName),
		zap.String("user_id", userID),
		zap.String("role", roleName))

	return nil
}

// RevokeRole revokes a role from a user
func (s *UserService) RevokeRole(ctx context.Context, realmName, userID, roleName string) error {
	if err := s.keycloakAdmin.RevokeRealmRoleFromUser(ctx, realmName, userID, roleName); err != nil {
		return fmt.Errorf("failed to revoke role from user: %w", err)
	}

	s.logger.Info("Revoked role from user",
		zap.String("realm", realmName),
		zap.String("user_id", userID),
		zap.String("role", roleName))

	return nil
}

// ResetPassword resets a user's password
func (s *UserService) ResetPassword(ctx context.Context, realmName, userID, newPassword string, temporary bool) error {
	if err := s.keycloakAdmin.ResetUserPassword(ctx, realmName, userID, newPassword, temporary); err != nil {
		return fmt.Errorf("failed to reset user password: %w", err)
	}

	s.logger.Info("Reset user password",
		zap.String("realm", realmName),
		zap.String("user_id", userID),
		zap.Bool("temporary", temporary))

	return nil
}

// EnableUser enables a user account
func (s *UserService) EnableUser(ctx context.Context, realmName, userID string) error {
	_, err := s.UpdateUser(ctx, realmName, userID, &models.UpdateUserRequest{
		Enabled: &[]bool{true}[0],
	})
	return err
}

// DisableUser disables a user account
func (s *UserService) DisableUser(ctx context.Context, realmName, userID string) error {
	_, err := s.UpdateUser(ctx, realmName, userID, &models.UpdateUserRequest{
		Enabled: &[]bool{false}[0],
	})
	return err
}

// GetUserRoles gets all roles assigned to a user
func (s *UserService) GetUserRoles(ctx context.Context, realmName, userID string) ([]string, error) {
	roles, err := s.keycloakAdmin.GetUserRealmRoles(ctx, realmName, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	var roleNames []string
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}

	return roleNames, nil
}

// SearchUsers searches for users by username or email
func (s *UserService) SearchUsers(ctx context.Context, realmName, query string, max int) ([]models.User, error) {
	keycloakUsers, err := s.keycloakAdmin.SearchUsers(ctx, realmName, query, max)
	if err != nil {
		return nil, fmt.Errorf("failed to search users: %w", err)
	}

	var users []models.User
	for _, kcUser := range keycloakUsers {
		user := models.User{
			ID:        kcUser.ID,
			Username:  kcUser.Username,
			Email:     kcUser.Email,
			FirstName: kcUser.FirstName,
			LastName:  kcUser.LastName,
			Enabled:   kcUser.Enabled,
		}
		users = append(users, user)
	}

	return users, nil
}

// Helper function to filter users based on search criteria
func (s *UserService) filterUsers(users []models.User, req *models.UserSearchRequest) []models.User {
	if req == nil {
		return users
	}

	var filtered []models.User
	for _, user := range users {
		match := true

		// Filter by search query (username, email, first name, last name)
		if req.Search != "" {
			query := strings.ToLower(req.Search)
			match = strings.Contains(strings.ToLower(user.Username), query) ||
				strings.Contains(strings.ToLower(user.Email), query) ||
				strings.Contains(strings.ToLower(user.FirstName), query) ||
				strings.Contains(strings.ToLower(user.LastName), query)
		}

		// Filter by enabled status
		if req.Enabled != nil && user.Enabled != *req.Enabled {
			match = false
		}

		// Filter by role
		if req.Role != "" && match {
			hasRole := false
			for _, role := range user.Roles {
				if role == req.Role {
					hasRole = true
					break
				}
			}
			if !hasRole {
				match = false
			}
		}

		if match {
			filtered = append(filtered, user)
		}
	}

	return filtered
}

// BulkCreateUsers creates multiple users in a Keycloak realm
func (s *UserService) BulkCreateUsers(ctx context.Context, realmName string, users []models.CreateUserRequest) (*models.BulkCreateResult, error) {
	result := &models.BulkCreateResult{
		TotalProcessed: len(users),
		Successful:     make([]*models.User, 0),
		Failed:         make([]models.BulkError, 0),
	}
	
	for i, userReq := range users {
		s.logger.Info("Creating user", 
			zap.String("realm", realmName),
			zap.String("email", userReq.Email),
			zap.Int("progress", i+1),
			zap.Int("total", len(users)))
		
		createdUser, err := s.CreateUser(ctx, realmName, &userReq)
		if err != nil {
			result.Failed = append(result.Failed, models.BulkError{
				Row:    i + 2,
				Email:  userReq.Email,
				Error:  err.Error(),
			})
			result.FailureCount++
		} else {
			result.Successful = append(result.Successful, createdUser)
			result.SuccessCount++
		}
	}
	
	return result, nil
}

// ImportUsersFromCSV imports users from parsed CSV records
func (s *UserService) ImportUsersFromCSV(ctx context.Context, realmName string, csvRecords [][]string) (*models.CSVImportResult, error) {
	if len(csvRecords) < 2 {
		return nil, fmt.Errorf("CSV must contain at least header row and one data row")
	}
	
	// Parse CSV headers
	headers := csvRecords[0]
	columnMap := make(map[string]int)
	for i, header := range headers {
		columnMap[strings.ToLower(strings.TrimSpace(header))] = i
	}
	
	// Required columns
	requiredColumns := []string{"email", "first_name", "last_name"}
	for _, col := range requiredColumns {
		if _, exists := columnMap[col]; !exists {
			return nil, fmt.Errorf("required column '%s' not found in CSV", col)
		}
	}
	
	// Convert CSV rows to user requests
	var users []models.CreateUserRequest
	var parseErrors []models.CSVError
	
	for i, row := range csvRecords[1:] {
		rowNum := i + 2
		
		if len(row) != len(headers) {
			parseErrors = append(parseErrors, models.CSVError{
				Row:   rowNum,
				Error: fmt.Sprintf("Row has %d columns, expected %d", len(row), len(headers)),
			})
			continue
		}
		
		user := models.CreateUserRequest{
			Email:     getColumnValue(row, columnMap, "email"),
			FirstName: getColumnValue(row, columnMap, "first_name"),
			LastName:  getColumnValue(row, columnMap, "last_name"),
		}
		
		// Optional columns
		if username := getColumnValue(row, columnMap, "username"); username != "" {
			user.Username = username
		} else {
			user.Username = user.Email
		}
		
		if password := getColumnValue(row, columnMap, "password"); password != "" {
			user.Password = password
		} else {
			generatedPassword, err := generateRandomPassword()
			if err != nil {
				return nil, fmt.Errorf("failed to generate password for user %s: %w", user.Email, err)
			}
			user.Password = generatedPassword
		}
		
		if role := getColumnValue(row, columnMap, "role"); role != "" {
			user.DefaultRole = role
		}
		
		if enabled := getColumnValue(row, columnMap, "enabled"); enabled != "" {
			enabledBool := strings.ToLower(enabled) == "true" || enabled == "1"
			user.Enabled = enabledBool
		} else {
			user.Enabled = true
		}
		
		// Validate required fields
		if user.Email == "" || user.FirstName == "" || user.LastName == "" {
			parseErrors = append(parseErrors, models.CSVError{
				Row:   rowNum,
				Error: "Missing required fields (email, first_name, last_name)",
			})
			continue
		}
		
		users = append(users, user)
	}
	
	// If there are parse errors, return them
	if len(parseErrors) > 0 {
		return &models.CSVImportResult{
			TotalProcessed: len(csvRecords) - 1,
			ParseErrors:    parseErrors,
		}, nil
	}
	
	// Bulk create users
	bulkResult, err := s.BulkCreateUsers(ctx, realmName, users)
	if err != nil {
		return nil, err
	}
	
	// Convert to CSV import result
	csvResult := &models.CSVImportResult{
		TotalProcessed:  bulkResult.TotalProcessed,
		SuccessCount:    bulkResult.SuccessCount,
		ErrorCount:      bulkResult.FailureCount,
		SuccessfulUsers: make([]models.User, 0, len(bulkResult.Successful)),
		FailedUsers:     make([]models.CSVError, 0, len(bulkResult.Failed)),
	}
	
	// Convert successful users
	for _, user := range bulkResult.Successful {
		csvResult.SuccessfulUsers = append(csvResult.SuccessfulUsers, *user)
	}
	
	// Convert failed users
	for _, failed := range bulkResult.Failed {
		csvResult.FailedUsers = append(csvResult.FailedUsers, models.CSVError{
			Row:   failed.Row,
			Email: failed.Email,
			Error: failed.Error,
		})
	}
	
	return csvResult, nil
}

// Helper functions
func getColumnValue(row []string, columnMap map[string]int, columnName string) string {
	if idx, exists := columnMap[columnName]; exists && idx < len(row) {
		return strings.TrimSpace(row[idx])
	}
	return ""
}

func generateRandomPassword() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	const length = 12
	
	password := make([]byte, length)
	for i := range password {
		n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("failed to generate secure random password: %w", err)
		}
		password[i] = charset[n.Int64()]
	}
	return string(password), nil
}
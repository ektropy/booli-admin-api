package services

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/booli/booli-admin-api/internal/auth"
	"github.com/booli/booli-admin-api/internal/config"
	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/booli/booli-admin-api/internal/models"
	"go.uber.org/zap"
)

type TenantService struct {
	keycloakAdmin *keycloak.AdminClient
	oidcService   *auth.OIDCService
	config        *config.Config
	logger        *zap.Logger
}

func NewTenantService(keycloakAdmin *keycloak.AdminClient, oidcService *auth.OIDCService, cfg *config.Config, logger *zap.Logger) *TenantService {
	return &TenantService{
		keycloakAdmin: keycloakAdmin,
		oidcService:   oidcService,
		config:        cfg,
		logger:        logger,
	}
}

func (s *TenantService) CreateTenant(ctx context.Context, req *models.CreateTenantRequest, mspRealm string) (*models.Tenant, error) {
	s.logger.Info("Starting tenant creation",
		zap.String("name", req.Name),
		zap.String("domain", req.Domain),
		zap.String("type", string(req.Type)))

	if req.Name == "" {
		s.logger.Error("Tenant creation failed: name is required")
		return nil, fmt.Errorf("tenant name is required")
	}

	if s.keycloakAdmin == nil {
		s.logger.Error("Keycloak admin client is nil")
		return nil, fmt.Errorf("keycloak admin client not available")
	}

	tenantType := req.Type
	if tenantType == "" {
		tenantType = models.TenantTypeClient
		s.logger.Info("Defaulting tenant type to client")
	}

	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Name
	}

	realmName, adminPassword, clientSecret, err := s.createKeycloakRealm(ctx, req.Name, displayName, req.Domain, req.AdminEmail, tenantType, mspRealm)
	if err != nil {
		return nil, fmt.Errorf("failed to create Keycloak realm: %w", err)
	}

	tenant := &models.Tenant{
		Name:          req.Name,
		Domain:        req.Domain,
		Type:          tenantType,
		Active:        true,
		RealmName:     realmName,
		AdminPassword: adminPassword,
		ClientSecret:  clientSecret,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	s.logger.Info("Tenant created successfully",
		zap.String("realm_name", realmName),
		zap.String("name", tenant.Name),
		zap.String("type", string(tenant.Type)))

	return tenant, nil
}

func (s *TenantService) GetTenant(ctx context.Context, realmName string) (*models.Tenant, error) {
	realm, err := s.keycloakAdmin.GetRealm(ctx, realmName)
	if err != nil {
		return nil, fmt.Errorf("realm not found: %w", err)
	}

	createdAt := time.Now()
	if createdAtStr, ok := realm.Attributes["created_at"]; ok {
		if parsedTime, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			createdAt = parsedTime
		}
	}

	tenant := &models.Tenant{
		Name:      realm.DisplayName,
		Domain:    realm.Attributes["domain"],
		Type:      models.TenantType(realm.Attributes["tenant_type"]),
		Active:    true,
		RealmName: realm.Realm,
		CreatedAt: createdAt,
		UpdatedAt: time.Now(),
	}

	return tenant, nil
}

func (s *TenantService) GetUserCount(ctx context.Context, realmName string) (int, error) {
	users, err := s.keycloakAdmin.GetUsers(ctx, realmName)
	if err != nil {
		return 0, fmt.Errorf("failed to get users from Keycloak realm: %w", err)
	}
	return len(users), nil
}

func (s *TenantService) ListTenants(ctx context.Context, filterByMSP string, page, pageSize int) (*models.TenantListResponse, error) {
	realms, err := s.keycloakAdmin.GetRealms(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get realms from Keycloak: %w", err)
	}

	var tenants []models.Tenant
	for _, realm := range realms {
		if realm.Realm == "master" {
			continue
		}

		if filterByMSP != "" {
			if realm.Attributes["tenant_type"] != string(models.TenantTypeClient) {
				continue
			}
		}

		createdAt := time.Now()
		if createdAtStr, ok := realm.Attributes["created_at"]; ok {
			if parsedTime, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
				createdAt = parsedTime
			}
		}

		tenant := models.Tenant{
			Name:      realm.DisplayName,
			Domain:    realm.Attributes["domain"],
			Type:      models.TenantType(realm.Attributes["tenant_type"]),
			Active:    true,
			RealmName: realm.Realm,
			CreatedAt: createdAt,
			UpdatedAt: time.Now(),
		}
		tenants = append(tenants, tenant)
	}

	total := int64(len(tenants))
	start := (page - 1) * pageSize
	end := start + pageSize
	if end > len(tenants) {
		end = len(tenants)
	}

	if start > len(tenants) {
		start = len(tenants)
	}

	paginatedTenants := tenants[start:end]
	responses := make([]models.TenantResponse, len(paginatedTenants))
	for i, tenant := range paginatedTenants {
		responses[i] = *tenant.ToResponse()
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))

	return &models.TenantListResponse{
		Tenants:    responses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

func (s *TenantService) GetTenantByName(ctx context.Context, name string) (*models.Tenant, error) {
	sanitizedName := strings.ToLower(name)
	sanitizedName = strings.ReplaceAll(sanitizedName, " ", "-")
	sanitizedName = strings.ReplaceAll(sanitizedName, "_", "-")
	realmName := fmt.Sprintf("tenant-%s", sanitizedName)

	return s.GetTenant(ctx, realmName)
}

func (s *TenantService) GetTenantByDomain(ctx context.Context, domain string) (*models.Tenant, error) {
	realms, err := s.keycloakAdmin.GetRealms(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get realms from Keycloak: %w", err)
	}

	for _, realm := range realms {
		if realm.Attributes["domain"] == domain {
			createdAt := time.Now()
			if createdAtStr, ok := realm.Attributes["created_at"]; ok {
				if parsedTime, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
					createdAt = parsedTime
				}
			}

			tenant := &models.Tenant{
				Name:      realm.DisplayName,
				Domain:    realm.Attributes["domain"],
				Type:      models.TenantType(realm.Attributes["tenant_type"]),
				Active:    true,
				RealmName: realm.Realm,
				CreatedAt: createdAt,
				UpdatedAt: time.Now(),
			}
			return tenant, nil
		}
	}

	return nil, nil
}

func (s *TenantService) UpdateTenant(ctx context.Context, realmName string, req *models.UpdateTenantRequest) (*models.Tenant, error) {
	realm, err := s.keycloakAdmin.GetRealm(ctx, realmName)
	if err != nil {
		return nil, fmt.Errorf("realm not found: %w", err)
	}

	updateRealm := &keycloak.RealmRepresentation{
		Realm:       realm.Realm,
		DisplayName: realm.DisplayName,
		Enabled:     realm.Enabled,
		Attributes:  realm.Attributes,
	}

	if req.Name != nil {
		updateRealm.DisplayName = *req.Name
		updateRealm.Attributes["tenant_name"] = *req.Name
	}
	if req.Domain != nil {
		updateRealm.Attributes["domain"] = *req.Domain
	}
	if req.Settings != nil {
		var newSettings models.TenantSettings
		if err := json.Unmarshal(*req.Settings, &newSettings); err != nil {
			return nil, fmt.Errorf("invalid settings format: %w", err)
		}

		settingsJSON, _ := json.Marshal(newSettings)
		updateRealm.Attributes["settings"] = string(settingsJSON)
	}

	if err := s.keycloakAdmin.UpdateRealm(ctx, realmName, updateRealm); err != nil {
		return nil, fmt.Errorf("failed to update realm: %w", err)
	}

	createdAt := time.Now()
	if createdAtStr, ok := updateRealm.Attributes["created_at"]; ok {
		if parsedTime, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			createdAt = parsedTime
		}
	}

	updatedTenant := &models.Tenant{
		Name:      updateRealm.DisplayName,
		Domain:    updateRealm.Attributes["domain"],
		Type:      models.TenantType(updateRealm.Attributes["tenant_type"]),
		Active:    true,
		RealmName: updateRealm.Realm,
		CreatedAt: createdAt,
		UpdatedAt: time.Now(),
	}

	s.logger.Info("Tenant updated successfully",
		zap.String("realm_name", realmName),
		zap.String("name", updatedTenant.Name))

	return updatedTenant, nil
}

func (s *TenantService) DeleteTenant(ctx context.Context, realmName string) error {
	if err := s.keycloakAdmin.DeleteRealm(ctx, realmName); err != nil {
		return fmt.Errorf("failed to delete Keycloak realm: %w", err)
	}

	s.logger.Info("Tenant deleted successfully",
		zap.String("realm_name", realmName))
	return nil
}

func (s *TenantService) createKeycloakRealm(ctx context.Context, name, displayName, domain, adminEmail string, tenantType models.TenantType, mspRealm string) (string, string, string, error) {
	s.logger.Info("Starting Keycloak realm creation",
		zap.String("tenant_name", name),
		zap.String("display_name", displayName),
		zap.String("domain", domain),
		zap.String("type", string(tenantType)))

	sanitizedName := strings.ToLower(name)
	sanitizedName = strings.ReplaceAll(sanitizedName, " ", "-")
	sanitizedName = strings.ReplaceAll(sanitizedName, "_", "-")
	realmName := fmt.Sprintf("tenant-%s", sanitizedName)
	s.logger.Info("Generated realm name",
		zap.String("tenant_name", name),
		zap.String("realm_name", realmName))

	realm := &keycloak.RealmRepresentation{
		Realm:                 realmName,
		DisplayName:           displayName,
		Enabled:               true,
		LoginWithEmailAllowed: true,
		RegistrationAllowed:   false,
		ResetPasswordAllowed:  true,
		RememberMe:            true,
		VerifyEmail:           false,
		LoginTheme:            "keycloak",
		AccountTheme:          "keycloak",
		AdminTheme:            "keycloak",
		EmailTheme:            "keycloak",
		Attributes: map[string]string{
			"tenant_name": name,
			"tenant_type": string(tenantType),
			"domain":      domain,
			"created_at":  time.Now().Format(time.RFC3339),
		},
	}

	s.logger.Info("Calling Keycloak API to create realm",
		zap.String("realm_name", realmName))

	if err := s.keycloakAdmin.CreateRealm(ctx, realm); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			s.logger.Info("Keycloak realm already exists, continuing",
				zap.String("realm_name", realmName))
		} else {
			s.logger.Error("Keycloak realm creation failed",
				zap.String("realm_name", realmName),
				zap.Error(err))
			return "", "", "", fmt.Errorf("failed to create Keycloak realm: %w", err)
		}
	} else {
		s.logger.Info("Keycloak realm created successfully", zap.String("realm_name", realmName))
	}

	if err := s.registerTenantOIDCProvider(ctx, realmName); err != nil {
		s.logger.Error("Failed to register OIDC provider, cleaning up realm",
			zap.String("realm_name", realmName),
			zap.Error(err))
		if deleteErr := s.keycloakAdmin.DeleteRealm(ctx, realmName); deleteErr != nil {
			s.logger.Error("Failed to cleanup realm after OIDC provider registration failure",
				zap.String("realm_name", realmName),
				zap.Error(deleteErr))
		}
		return "", "", "", fmt.Errorf("failed to register OIDC provider: %w", err)
	}

	if err := s.createRealmDefaultRoles(ctx, realmName, tenantType); err != nil {
		s.logger.Error("Failed to create default roles, cleaning up realm",
			zap.String("realm_name", realmName),
			zap.Error(err))
		if deleteErr := s.keycloakAdmin.DeleteRealm(ctx, realmName); deleteErr != nil {
			s.logger.Error("Failed to cleanup realm after role creation failure",
				zap.String("realm_name", realmName),
				zap.Error(deleteErr))
		}
		return "", "", "", fmt.Errorf("failed to create default realm roles: %w", err)
	}

	adminUser, adminPassword, err := s.createRealmAdminUser(ctx, realmName, name, domain, adminEmail)
	if err != nil {
		s.logger.Error("Failed to create admin user, cleaning up realm",
			zap.String("realm_name", realmName),
			zap.Error(err))
		if deleteErr := s.keycloakAdmin.DeleteRealm(ctx, realmName); deleteErr != nil {
			s.logger.Error("Failed to cleanup realm after admin user creation failure",
				zap.String("realm_name", realmName),
				zap.Error(deleteErr))
		}
		return "", "", "", fmt.Errorf("failed to create realm admin user: %w", err)
	}

	clientSecret, err := s.createRealmAPIClient(ctx, realmName)
	if err != nil {
		s.logger.Error("Failed to create API client, cleaning up realm",
			zap.String("realm_name", realmName),
			zap.Error(err))
		if deleteErr := s.keycloakAdmin.DeleteRealm(ctx, realmName); deleteErr != nil {
			s.logger.Error("Failed to cleanup realm after API client creation failure",
				zap.String("realm_name", realmName),
				zap.Error(deleteErr))
		}
		return "", "", "", fmt.Errorf("failed to create API client: %w", err)
	}

	s.logger.Info("Created Keycloak realm successfully",
		zap.String("realm_name", realmName),
		zap.String("admin_user_id", adminUser.ID),
		zap.String("admin_email", adminUser.Email))

	return realmName, adminPassword, clientSecret, nil
}

func (s *TenantService) createRealmDefaultRoles(ctx context.Context, realmName string, tenantType models.TenantType) error {
	s.logger.Info("Creating default realm roles",
		zap.String("realm", realmName),
		zap.String("tenant_type", string(tenantType)))

	var rolesToCreate []string
	switch tenantType {
	case models.TenantTypeMSP:
		rolesToCreate = []string{"tenant-admin", "user", "viewer", "tenant-manager"}
	case models.TenantTypeClient:
		rolesToCreate = []string{"tenant-admin", "user", "viewer"}
	default:
		rolesToCreate = []string{"tenant-admin", "user", "viewer"}
	}

	for _, roleName := range rolesToCreate {
		description := fmt.Sprintf("Default %s role for tenant", roleName)
		if err := s.keycloakAdmin.CreateRealmRole(ctx, realmName, roleName, description); err != nil {
			if strings.Contains(err.Error(), "already exists") {
				s.logger.Info("Realm role already exists, continuing",
					zap.String("realm", realmName),
					zap.String("role", roleName))
			} else {
				s.logger.Error("Failed to create realm role",
					zap.String("realm", realmName),
					zap.String("role", roleName),
					zap.Error(err))
				return fmt.Errorf("failed to create role %s: %w", roleName, err)
			}
		} else {
			s.logger.Info("Created realm role",
				zap.String("realm", realmName),
				zap.String("role", roleName))
		}
	}

	s.logger.Info("All default realm roles created successfully",
		zap.String("realm", realmName),
		zap.Int("roles_created", len(rolesToCreate)))
	return nil
}

func (s *TenantService) createRealmAdminUser(ctx context.Context, realmName, tenantName, domain, providedEmail string) (*keycloak.UserRepresentation, string, error) {
	s.logger.Info("Creating realm admin user",
		zap.String("realm", realmName),
		zap.String("tenant_name", tenantName))

	adminEmail := providedEmail
	if adminEmail == "" {
		if domain != "" {
			adminEmail = fmt.Sprintf("booli-admin@%s", domain)
		} else {
			adminEmail = fmt.Sprintf("booli-admin@%s.local", strings.ToLower(strings.ReplaceAll(tenantName, " ", "-")))
		}
	}

	securePassword, err := generateSecurePassword()
	if err != nil {
		s.logger.Error("Failed to generate secure password",
			zap.String("realm", realmName),
			zap.Error(err))
		return nil, "", fmt.Errorf("failed to generate secure password: %w", err)
	}

	adminUser := &keycloak.UserRepresentation{
		Username:      "admin",
		Email:         adminEmail,
		FirstName:     "Tenant",
		LastName:      "Administrator",
		Enabled:       true,
		EmailVerified: false,
		Attributes: map[string][]string{
			"tenant_id": {realmName},
		},
		Credentials: []keycloak.CredentialRepresentation{
			{
				Type:      "password",
				Value:     securePassword,
				Temporary: true,
			},
		},
	}

	s.logger.Info("Creating admin user in realm",
		zap.String("realm", realmName),
		zap.String("username", adminUser.Username),
		zap.String("email", adminUser.Email))

	createdUser, err := s.keycloakAdmin.CreateUser(ctx, realmName, adminUser)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			s.logger.Info("Admin user already exists, getting existing user",
				zap.String("realm", realmName),
				zap.String("username", adminUser.Username))
			existingUser, getErr := s.keycloakAdmin.GetUserByUsername(ctx, realmName, adminUser.Username)
			if getErr != nil {
				s.logger.Error("Failed to get existing admin user",
					zap.String("realm", realmName),
					zap.String("username", adminUser.Username),
					zap.Error(getErr))
				return nil, "", fmt.Errorf("failed to get existing admin user: %w", getErr)
			}
			createdUser = existingUser
		} else {
			s.logger.Error("Failed to create admin user",
				zap.String("realm", realmName),
				zap.String("username", adminUser.Username),
				zap.Error(err))
			return nil, "", fmt.Errorf("failed to create admin user: %w", err)
		}
	}

	adminRole, err := s.keycloakAdmin.GetRealmRole(ctx, realmName, "tenant-admin")
	if err != nil {
		s.logger.Error("Failed to get tenant-admin role",
			zap.String("realm", realmName),
			zap.Error(err))
		return nil, "", fmt.Errorf("failed to get tenant-admin role: %w", err)
	}

	if err := s.keycloakAdmin.AssignRealmRolesToUser(ctx, realmName, createdUser.ID, []keycloak.RoleRepresentation{*adminRole}); err != nil {
		s.logger.Error("Failed to assign tenant-admin role to user",
			zap.String("realm", realmName),
			zap.String("user_id", createdUser.ID),
			zap.Error(err))
		return nil, "", fmt.Errorf("failed to assign tenant-admin role: %w", err)
	}

	s.logger.Info("Created realm admin user successfully",
		zap.String("realm", realmName),
		zap.String("user_id", createdUser.ID),
		zap.String("username", createdUser.Username),
		zap.String("email", createdUser.Email))

	return createdUser, securePassword, nil
}

func (s *TenantService) ProvisionTenant(ctx context.Context, name, domain string, tenantType models.TenantType, mspRealm string) (*models.Tenant, error) {
	realmName, _, _, err := s.createKeycloakRealm(ctx, name, name, domain, "", tenantType, mspRealm)
	if err != nil {
		return nil, fmt.Errorf("failed to create Keycloak realm: %w", err)
	}

	tenant := &models.Tenant{
		Name:      name,
		Domain:    domain,
		Type:      tenantType,
		Active:    true,
		RealmName: realmName,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return tenant, nil
}

func (s *TenantService) AddUserToTenant(ctx context.Context, realmName, userID string) error {
	user, err := s.keycloakAdmin.GetUser(ctx, realmName, userID)
	if err != nil {
		return fmt.Errorf("user not found in realm: %w", err)
	}

	s.logger.Info("User already exists in tenant realm",
		zap.String("user_id", userID),
		zap.String("realm", realmName),
		zap.String("username", user.Username))

	return nil
}

func (s *TenantService) RemoveUserFromTenant(ctx context.Context, realmName, userID string) error {
	if err := s.keycloakAdmin.DeleteUser(ctx, realmName, userID); err != nil {
		return fmt.Errorf("failed to remove user from realm: %w", err)
	}

	s.logger.Info("Removed user from tenant realm",
		zap.String("user_id", userID),
		zap.String("realm", realmName))

	return nil
}

func (s *TenantService) registerTenantOIDCProvider(ctx context.Context, realmName string) error {
	s.logger.Info("Registering OIDC provider for tenant realm",
		zap.String("realm", realmName))

	providerName := fmt.Sprintf("keycloak-%s", realmName)

	tenantProvider := auth.CreateKeycloakProvider(
		providerName,
		s.config.Keycloak.URL,
		realmName,
		"",
		"",
		"",
		s.config.Keycloak.APIAudience,
		s.config.Keycloak.SkipTLSVerify,
		s.config.Keycloak.CACertPath,
	)

	if err := s.oidcService.AddProvider(ctx, tenantProvider); err != nil {
		return fmt.Errorf("failed to register OIDC provider %s: %w", providerName, err)
	}

	s.logger.Info("OIDC provider registered successfully",
		zap.String("provider", providerName),
		zap.String("realm", realmName))

	return nil
}

func generateSecurePassword() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	const length = 16

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

func (s *TenantService) createRealmAPIClient(ctx context.Context, realmName string) (string, error) {
	s.logger.Info("Creating API client for tenant realm",
		zap.String("realm", realmName))

	clientSecret, err := generateSecurePassword()
	if err != nil {
		return "", fmt.Errorf("failed to generate client secret: %w", err)
	}

	client := &keycloak.ClientRepresentation{
		ClientID:                  "tenant-api-client",
		Name:                      "Tenant API Client",
		Description:               "Client for tenant admin API access",
		Enabled:                   true,
		PublicClient:              false,
		DirectAccessGrantsEnabled: true,
		StandardFlowEnabled:       true,
		ServiceAccountsEnabled:    true,
		ClientAuthenticatorType:   "client-secret",
		Secret:                    clientSecret,
		RedirectUris:              []string{"*"},
		WebOrigins:                []string{"*"},
		FullScopeAllowed:          true,
		Protocol:                  "openid-connect",
		Attributes: map[string]string{
			"access.token.lifespan": "3600",
		},
	}

	if _, err := s.keycloakAdmin.CreateClient(ctx, realmName, client); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			s.logger.Info("API client already exists in realm",
				zap.String("realm", realmName),
				zap.String("client_id", client.ClientID))
			return clientSecret, nil
		}
		return "", fmt.Errorf("failed to create API client: %w", err)
	}

	s.logger.Info("Created API client successfully",
		zap.String("realm", realmName),
		zap.String("client_id", client.ClientID))

	return clientSecret, nil
}

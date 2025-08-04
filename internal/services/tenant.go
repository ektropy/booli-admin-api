package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/booli/booli-admin-api/internal/config"
	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type TenantService struct {
	db            *gorm.DB
	redis         *redis.Client
	keycloakAdmin *keycloak.AdminClient
	logger        *zap.Logger
	config        *config.Config
}

func NewTenantService(db *gorm.DB, redis *redis.Client, keycloakAdmin *keycloak.AdminClient, logger *zap.Logger, cfg *config.Config) *TenantService {
	return &TenantService{
		db:            db,
		redis:         redis,
		keycloakAdmin: keycloakAdmin,
		logger:        logger,
		config:        cfg,
	}
}

func (s *TenantService) CreateTenant(ctx context.Context, req *models.CreateTenantRequest, mspTenantID *uuid.UUID) (*models.Tenant, error) {
	s.logger.Info("Starting tenant creation",
		zap.String("name", req.Name),
		zap.String("domain", req.Domain),
		zap.String("type", string(req.Type)),
		zap.Bool("has_msp_parent", mspTenantID != nil))

	if req.Name == "" {
		s.logger.Error("Tenant creation failed: name is required")
		return nil, fmt.Errorf("tenant name is required")
	}

	tenant := &models.Tenant{
		Name:     req.Name,
		Domain:   req.Domain,
		Type:     req.Type,
		Settings: req.Settings,
	}

	if tenant.Type == "" {
		tenant.Type = models.TenantTypeClient
		s.logger.Info("Defaulting tenant type to client")
	}

	if tenant.Type == models.TenantTypeClient && mspTenantID != nil {
		tenant.ParentTenantID = mspTenantID
		s.logger.Info("Setting parent tenant ID for client tenant", zap.String("parent_id", mspTenantID.String()))
	}

	if tenant.ParentTenantID != nil {
		s.logger.Info("Validating parent tenant", zap.String("parent_id", tenant.ParentTenantID.String()))
		var parentTenant models.Tenant
		if err := s.db.WithContext(ctx).Where("id = ? AND type = ?", *tenant.ParentTenantID, models.TenantTypeMSP).First(&parentTenant).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				s.logger.Error("Parent MSP tenant not found", zap.String("parent_id", tenant.ParentTenantID.String()))
				return nil, fmt.Errorf("parent MSP tenant not found")
			}
			s.logger.Error("Failed to validate parent tenant", zap.Error(err))
			return nil, fmt.Errorf("failed to validate parent tenant: %w", err)
		}

		if !parentTenant.CanManageChildTenants() {
			s.logger.Error("Parent MSP tenant cannot manage child tenants",
				zap.String("parent_id", parentTenant.ID.String()),
				zap.String("parent_status", string(parentTenant.Status)))
			return nil, fmt.Errorf("parent MSP tenant cannot manage child tenants")
		}
		s.logger.Info("Parent tenant validation successful")
	}

	if s.db == nil {
		s.logger.Error("Database connection is nil")
		return nil, fmt.Errorf("database connection not available")
	}
	if s.keycloakAdmin == nil {
		s.logger.Error("Keycloak admin client is nil")
		return nil, fmt.Errorf("keycloak admin client not available")
	}

	s.logger.Info("Starting database transaction")
	tx := s.db.Begin()
	if tx.Error != nil {
		s.logger.Error("Failed to start database transaction", zap.Error(tx.Error))
		return nil, fmt.Errorf("failed to start transaction: %w", tx.Error)
	}
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("Panic occurred during tenant creation, rolling back", zap.Any("panic", r))
			tx.Rollback()
		}
	}()

	s.logger.Info("Creating tenant record in database")
	if err := tx.WithContext(ctx).Create(tenant).Error; err != nil {
		s.logger.Error("Failed to create tenant record", zap.Error(err))
		tx.Rollback()
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}
	s.logger.Info("Tenant record created successfully", zap.String("tenant_id", tenant.ID.String()))

	s.logger.Info("Creating default roles for tenant", zap.String("tenant_type", string(tenant.Type)))
	if err := s.createDefaultRoles(ctx, tx, tenant.ID, tenant.Type); err != nil {
		s.logger.Error("Failed to create default roles", zap.Error(err))
		tx.Rollback()
		return nil, fmt.Errorf("failed to create default roles: %w", err)
	}
	s.logger.Info("Default roles created successfully")

	s.logger.Info("Committing database transaction")
	if err := tx.Commit().Error; err != nil {
		s.logger.Error("Failed to commit database transaction", zap.Error(err))
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	s.logger.Info("Database transaction committed successfully")

	s.logger.Info("Creating Keycloak organization")
	if err := s.createKeycloakOrganization(ctx, tenant); err != nil {
		s.logger.Error("Failed to create Keycloak organization, manual cleanup may be required",
			zap.String("tenant_id", tenant.ID.String()),
			zap.Error(err))
		return nil, fmt.Errorf("failed to create Keycloak organization: %w", err)
	}
	s.logger.Info("Keycloak organization created successfully")

	s.logger.Info("Tenant created successfully",
		zap.String("tenant_id", tenant.ID.String()),
		zap.String("name", tenant.Name),
		zap.String("type", string(tenant.Type)))

	return tenant, nil
}

func (s *TenantService) GetTenant(ctx context.Context, tenantID uuid.UUID, includeCounts bool) (*models.Tenant, error) {
	var tenant models.Tenant
	query := s.db.WithContext(ctx).Where("id = ?", tenantID)

	if includeCounts {
		query = query.Preload("Roles").Preload("SSOProviders").Preload("ChildTenants")
	}

	if err := query.First(&tenant).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("tenant not found")
		}
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	return &tenant, nil
}

func (s *TenantService) GetUserCount(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var tenant models.Tenant
	if err := s.db.WithContext(ctx).Where("id = ?", tenantID).First(&tenant).Error; err != nil {
		return 0, fmt.Errorf("tenant not found: %w", err)
	}

	if tenant.KeycloakOrganizationID == "" {
		return 0, nil
	}

	organizationID := tenant.KeycloakOrganizationID
	members, err := s.keycloakAdmin.ListOrganizationMembers(ctx, s.config.Keycloak.MSPRealm, organizationID)
	if err != nil {
		return 0, fmt.Errorf("failed to get organization members from Keycloak: %w", err)
	}
	return len(members), nil
}

func (s *TenantService) ListTenants(ctx context.Context, mspTenantID *uuid.UUID, page, pageSize int) (*models.TenantListResponse, error) {
	var tenants []models.Tenant
	var total int64

	query := s.db.WithContext(ctx).Model(&models.Tenant{})

	if mspTenantID != nil {
		query = query.Where("parent_tenant_id = ?", *mspTenantID)
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("failed to count tenants: %w", err)
	}

	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Find(&tenants).Error; err != nil {
		return nil, fmt.Errorf("failed to list tenants: %w", err)
	}

	responses := make([]models.TenantResponse, len(tenants))
	for i, tenant := range tenants {
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
	var tenant models.Tenant
	if err := s.db.WithContext(ctx).Where("name = ?", name).First(&tenant).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get tenant by name: %w", err)
	}
	return &tenant, nil
}

func (s *TenantService) GetTenantByDomain(ctx context.Context, domain string) (*models.Tenant, error) {
	var tenant models.Tenant
	if err := s.db.WithContext(ctx).Where("domain = ?", domain).First(&tenant).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get tenant by domain: %w", err)
	}
	return &tenant, nil
}

func (s *TenantService) UpdateTenant(ctx context.Context, tenantID uuid.UUID, req *models.UpdateTenantRequest) (*models.Tenant, error) {
	var tenant models.Tenant
	if err := s.db.WithContext(ctx).Where("id = ?", tenantID).First(&tenant).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("tenant not found")
		}
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	if req.Name != nil {
		tenant.Name = *req.Name
		if tenant.KeycloakOrganizationID != "" {
			org := &keycloak.OrganizationRepresentation{
				Name:    tenant.Name,
				Enabled: true,
			}
			if err := s.keycloakAdmin.UpdateOrganization(ctx, s.config.Keycloak.MSPRealm, tenant.KeycloakOrganizationID, org); err != nil {
				s.logger.Warn("Failed to update Keycloak organization name", zap.Error(err))
			}
		}
	}
	if req.Domain != nil {
		tenant.Domain = *req.Domain
	}
	if req.Status != nil {
		tenant.Status = *req.Status
	}
	if req.Settings != nil {
		var newSettings models.TenantSettings
		if err := json.Unmarshal(*req.Settings, &newSettings); err != nil {
			return nil, fmt.Errorf("invalid settings format: %w", err)
		}
		if err := s.validateTenantSettings(newSettings, tenant.Type); err != nil {
			return nil, fmt.Errorf("invalid settings: %w", err)
		}

		var currentSettings models.TenantSettings
		if len(tenant.Settings) > 0 {
			_ = json.Unmarshal(tenant.Settings, &currentSettings)
		}

		tenant.Settings = *req.Settings
		s.logTenantSettingsChanges(currentSettings, newSettings, tenant.ID, ctx)
	}
	if req.ParentTenantID != nil {
		tenant.ParentTenantID = req.ParentTenantID
	}

	if err := s.db.WithContext(ctx).Save(&tenant).Error; err != nil {
		return nil, fmt.Errorf("failed to update tenant: %w", err)
	}

	s.logger.Info("Tenant updated successfully",
		zap.String("tenant_id", tenant.ID.String()),
		zap.String("name", tenant.Name))

	return &tenant, nil
}

func (s *TenantService) DeleteTenant(ctx context.Context, tenantID uuid.UUID) error {
	var tenant models.Tenant
	if err := s.db.WithContext(ctx).Where("id = ?", tenantID).First(&tenant).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return fmt.Errorf("tenant not found")
		}
		return fmt.Errorf("failed to get tenant: %w", err)
	}

	var childCount int64
	if err := s.db.WithContext(ctx).Model(&models.Tenant{}).Where("parent_tenant_id = ?", tenantID).Count(&childCount).Error; err != nil {
		return fmt.Errorf("failed to check child tenants: %w", err)
	}

	if childCount > 0 {
		return fmt.Errorf("cannot delete tenant with child tenants")
	}

	if tenant.KeycloakOrganizationID != "" {
		if err := s.keycloakAdmin.DeleteOrganization(ctx, s.config.Keycloak.MSPRealm, tenant.KeycloakOrganizationID); err != nil {
			s.logger.Warn("Failed to delete Keycloak organization",
				zap.String("tenant_id", tenantID.String()),
				zap.String("organization_id", tenant.KeycloakOrganizationID),
				zap.Error(err))
		}
	}

	if err := s.db.WithContext(ctx).Delete(&models.Tenant{}, tenantID).Error; err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}

	s.logger.Info("Tenant deleted successfully",
		zap.String("tenant_id", tenantID.String()),
		zap.String("organization_id", tenant.KeycloakOrganizationID))
	return nil
}

func (s *TenantService) createDefaultRoles(ctx context.Context, tx *gorm.DB, tenantID uuid.UUID, tenantType models.TenantType) error {
	s.logger.Info("Creating default roles for tenant",
		zap.String("tenant_id", tenantID.String()),
		zap.String("tenant_type", string(tenantType)))

	var rolesToCreate map[string]models.Permissions

	switch tenantType {
	case models.TenantTypeMSP:
		rolesToCreate = models.MSPRoles
		s.logger.Info("Using MSP roles template", zap.Int("role_count", len(rolesToCreate)))
	case models.TenantTypeClient:
		rolesToCreate = models.DefaultRoles
		s.logger.Info("Using default client roles template", zap.Int("role_count", len(rolesToCreate)))
	default:
		rolesToCreate = models.DefaultRoles
		s.logger.Info("Using default roles template for unknown tenant type",
			zap.String("tenant_type", string(tenantType)),
			zap.Int("role_count", len(rolesToCreate)))
	}

	if len(rolesToCreate) == 0 {
		s.logger.Warn("No roles to create for tenant type", zap.String("tenant_type", string(tenantType)))
		return nil
	}

	for roleName, permissions := range rolesToCreate {
		s.logger.Info("Creating role",
			zap.String("role_name", roleName),
			zap.String("tenant_id", tenantID.String()))

		permissionsJSON, err := json.Marshal(permissions)
		if err != nil {
			s.logger.Error("Failed to marshal permissions for role",
				zap.String("role_name", roleName),
				zap.Error(err))
			return fmt.Errorf("failed to marshal permissions for role %s: %w", roleName, err)
		}

		role := &models.Role{
			TenantID:    tenantID,
			Name:        roleName,
			Description: fmt.Sprintf("Default %s role", roleName),
			Permissions: datatypes.JSON(permissionsJSON),
			IsSystem:    true,
		}

		if err := tx.WithContext(ctx).Create(role).Error; err != nil {
			s.logger.Error("Failed to create role in database",
				zap.String("role_name", roleName),
				zap.String("tenant_id", tenantID.String()),
				zap.Error(err))
			return fmt.Errorf("failed to create role %s: %w", roleName, err)
		}

		s.logger.Info("Role created successfully",
			zap.String("role_name", roleName),
			zap.String("role_id", role.ID.String()))
	}

	s.logger.Info("All default roles created successfully",
		zap.String("tenant_id", tenantID.String()),
		zap.Int("roles_created", len(rolesToCreate)))
	return nil
}

func (s *TenantService) createKeycloakOrganization(ctx context.Context, tenant *models.Tenant) error {
	s.logger.Info("Starting Keycloak organization creation",
		zap.String("tenant_id", tenant.ID.String()),
		zap.String("tenant_name", tenant.Name))

	var domains []keycloak.OrganizationDomainRepresentation
	if tenant.Domain != "" {
		s.logger.Info("Using provided tenant domain", zap.String("domain", tenant.Domain))
		domains = []keycloak.OrganizationDomainRepresentation{
			{
				Name:     tenant.Domain,
				Verified: false, // Set to false initially, can be verified later
			},
		}
	} else {
		defaultDomain := fmt.Sprintf("%s.internal", strings.ToLower(strings.ReplaceAll(tenant.Name, " ", "-")))
		s.logger.Info("Generated default domain for tenant", zap.String("default_domain", defaultDomain))
		domains = []keycloak.OrganizationDomainRepresentation{
			{
				Name:     defaultDomain,
				Verified: false,
			},
		}
	}

	orgName := strings.ToLower(strings.ReplaceAll(tenant.Name, " ", "-"))
	s.logger.Info("Sanitized organization name",
		zap.String("original_name", tenant.Name),
		zap.String("sanitized_name", orgName))

	org := &keycloak.OrganizationRepresentation{
		Name:        orgName,
		Enabled:     true,
		Description: fmt.Sprintf("Organization for %s (%s)", tenant.Name, tenant.Type),
		Domains:     domains,
	}

	s.logger.Info("Calling Keycloak API to create organization",
		zap.String("realm", s.config.Keycloak.MSPRealm),
		zap.String("org_name", orgName))

	createdOrg, err := s.keycloakAdmin.CreateOrganization(ctx, s.config.Keycloak.MSPRealm, org)
	if err != nil {
		s.logger.Error("Keycloak organization creation failed",
			zap.String("org_name", orgName),
			zap.String("realm", s.config.Keycloak.MSPRealm),
			zap.Error(err))
		return fmt.Errorf("failed to create Keycloak organization: %w", err)
	}

	s.logger.Info("Keycloak organization created successfully",
		zap.String("organization_id", createdOrg.ID),
		zap.String("org_name", orgName))

	tenant.KeycloakOrganizationID = createdOrg.ID
	tenant.Status = models.TenantStatusActive

	s.logger.Info("Updating tenant with organization ID",
		zap.String("tenant_id", tenant.ID.String()),
		zap.String("organization_id", createdOrg.ID))

	if err := s.db.WithContext(ctx).Save(tenant).Error; err != nil {
		s.logger.Error("Failed to update tenant with organization ID, cleaning up Keycloak organization",
			zap.String("tenant_id", tenant.ID.String()),
			zap.String("organization_id", createdOrg.ID),
			zap.Error(err))

		if deleteErr := s.keycloakAdmin.DeleteOrganization(ctx, s.config.Keycloak.MSPRealm, createdOrg.ID); deleteErr != nil {
			s.logger.Error("Failed to cleanup Keycloak organization after tenant update failure",
				zap.String("organization_id", createdOrg.ID),
				zap.Error(deleteErr))
		}
		return fmt.Errorf("failed to update tenant with organization ID: %w", err)
	}

	s.logger.Info("Created Keycloak organization successfully",
		zap.String("organization_id", createdOrg.ID),
		zap.String("tenant_id", tenant.ID.String()))

	return nil
}

func (s *TenantService) ProvisionTenant(ctx context.Context, tenant *models.Tenant) error {
	if tenant.KeycloakOrganizationID != "" {
		return fmt.Errorf("organization already provisioned for tenant %s", tenant.ID.String())
	}

	tenant.Status = models.TenantStatusProvisioning
	if err := s.db.WithContext(ctx).Save(tenant).Error; err != nil {
		return fmt.Errorf("failed to update tenant status: %w", err)
	}

	if err := s.createKeycloakOrganization(ctx, tenant); err != nil {
		tenant.Status = models.TenantStatusActive
		s.db.WithContext(ctx).Save(tenant)
		return fmt.Errorf("failed to create Keycloak organization: %w", err)
	}

	return nil
}

func (s *TenantService) AddUserToTenant(ctx context.Context, tenantID uuid.UUID, userID string) error {
	var tenant models.Tenant
	if err := s.db.WithContext(ctx).Where("id = ?", tenantID).First(&tenant).Error; err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}

	if tenant.KeycloakOrganizationID == "" {
		return fmt.Errorf("tenant has no Keycloak organization")
	}

	if err := s.keycloakAdmin.AddOrganizationMember(ctx, s.config.Keycloak.MSPRealm, tenant.KeycloakOrganizationID, userID); err != nil {
		return fmt.Errorf("failed to add user to organization: %w", err)
	}

	s.logger.Info("Added user to organization",
		zap.String("tenant_id", tenantID.String()),
		zap.String("user_id", userID),
		zap.String("organization_id", tenant.KeycloakOrganizationID))

	return nil
}

func (s *TenantService) RemoveUserFromTenant(ctx context.Context, tenantID uuid.UUID, userID string) error {
	var tenant models.Tenant
	if err := s.db.WithContext(ctx).Where("id = ?", tenantID).First(&tenant).Error; err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}

	if tenant.KeycloakOrganizationID == "" {
		return fmt.Errorf("tenant has no Keycloak organization")
	}

	if err := s.keycloakAdmin.RemoveOrganizationMember(ctx, s.config.Keycloak.MSPRealm, tenant.KeycloakOrganizationID, userID); err != nil {
		return fmt.Errorf("failed to remove user from organization: %w", err)
	}

	s.logger.Info("Removed user from organization",
		zap.String("tenant_id", tenantID.String()),
		zap.String("user_id", userID),
		zap.String("organization_id", tenant.KeycloakOrganizationID))

	return nil
}

func (s *TenantService) validateTenantSettings(settings models.TenantSettings, tenantType models.TenantType) error {
	if tenantType == models.TenantTypeClient {
		if settings.MSPSSOEnabled {
			return fmt.Errorf("client tenants cannot enable MSP SSO")
		}
	}

	if settings.MaxUsers < 0 {
		return fmt.Errorf("max users cannot be negative")
	}
	if settings.MaxRoles < 0 {
		return fmt.Errorf("max roles cannot be negative")
	}
	if settings.MaxSSOProviders < 0 {
		return fmt.Errorf("max SSO providers cannot be negative")
	}

	if settings.DataRetentionDays < 0 {
		return fmt.Errorf("data retention days cannot be negative")
	}

	return nil
}

func (s *TenantService) logTenantSettingsChanges(oldSettings, newSettings models.TenantSettings, tenantID uuid.UUID, ctx context.Context) {
	changes := make(map[string]interface{})

	if oldSettings.EnableSSO != newSettings.EnableSSO {
		changes["enable_sso"] = newSettings.EnableSSO
	}
	if oldSettings.EnableMFA != newSettings.EnableMFA {
		changes["enable_mfa"] = newSettings.EnableMFA
	}
	if oldSettings.EnableAudit != newSettings.EnableAudit {
		changes["enable_audit"] = newSettings.EnableAudit
	}
	if oldSettings.MSPSSOEnabled != newSettings.MSPSSOEnabled {
		changes["msp_sso_enabled"] = newSettings.MSPSSOEnabled
	}
	if oldSettings.MSPSSOProvider != newSettings.MSPSSOProvider {
		changes["msp_sso_provider"] = newSettings.MSPSSOProvider
	}
	if oldSettings.MaxUsers != newSettings.MaxUsers {
		changes["max_users"] = newSettings.MaxUsers
	}
	if oldSettings.MaxRoles != newSettings.MaxRoles {
		changes["max_roles"] = newSettings.MaxRoles
	}
	if oldSettings.MaxSSOProviders != newSettings.MaxSSOProviders {
		changes["max_sso_providers"] = newSettings.MaxSSOProviders
	}
	if oldSettings.DataRetentionDays != newSettings.DataRetentionDays {
		changes["data_retention_days"] = newSettings.DataRetentionDays
	}

	if len(changes) > 0 {
		s.logger.Info("Tenant settings updated",
			zap.String("tenant_id", tenantID.String()),
			zap.Any("changes", changes))
	}
}

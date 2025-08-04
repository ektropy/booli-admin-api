package services

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/booli/booli-admin-api/internal/config"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type RoleService struct {
	db     *gorm.DB
	redis  *redis.Client
	logger *zap.Logger
	config *config.Config
}

func NewRoleService(db *gorm.DB, redis *redis.Client, logger *zap.Logger, cfg *config.Config) *RoleService {
	return &RoleService{
		db:     db,
		redis:  redis,
		logger: logger,
		config: cfg,
	}
}

func (s *RoleService) ListRoles(ctx context.Context, tenantID uuid.UUID, page, pageSize int, includeSystem bool) ([]models.Role, int64, error) {
	var roles []models.Role
	var total int64

	query := s.db.WithContext(ctx).Model(&models.Role{}).Where("tenant_id = ?", tenantID)
	if !includeSystem {
		query = query.Where("is_system = false")
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count roles: %w", err)
	}

	offset := (page - 1) * pageSize
	if err := query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&roles).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list roles: %w", err)
	}

	return roles, total, nil
}

func (s *RoleService) CreateRole(ctx context.Context, role *models.Role) (*models.Role, error) {
	var existingRole models.Role
	if err := s.db.WithContext(ctx).Where("tenant_id = ? AND name = ?", role.TenantID, role.Name).First(&existingRole).Error; err == nil {
		return nil, fmt.Errorf("role with name '%s' already exists", role.Name)
	} else if err != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("failed to check existing role: %w", err)
	}

	var permissions models.Permissions
	if len(role.Permissions) > 0 {
		if err := json.Unmarshal(role.Permissions, &permissions); err != nil {
			return nil, fmt.Errorf("invalid permissions format: %w", err)
		}
		if err := s.validatePermissions(permissions, role.TenantID); err != nil {
			return nil, fmt.Errorf("invalid permissions: %w", err)
		}
	}

	if err := s.db.WithContext(ctx).Create(role).Error; err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	s.logger.Info("Role created",
		zap.String("role_id", role.ID.String()),
		zap.String("role_name", role.Name),
		zap.String("tenant_id", role.TenantID.String()))

	return role, nil
}

func (s *RoleService) GetRole(ctx context.Context, tenantID, roleID uuid.UUID) (*models.Role, error) {
	var role models.Role
	if err := s.db.WithContext(ctx).Where("id = ? AND tenant_id = ?", roleID, tenantID).First(&role).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	return &role, nil
}

func (s *RoleService) UpdateRole(ctx context.Context, tenantID, roleID uuid.UUID, req *models.UpdateRoleRequest) (*models.Role, error) {
	var role models.Role
	if err := s.db.WithContext(ctx).Where("id = ? AND tenant_id = ?", roleID, tenantID).First(&role).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	if role.IsSystem {
		return nil, fmt.Errorf("cannot update system role")
	}

	updates := make(map[string]interface{})
	if req.Name != nil {
		var existingRole models.Role
		if err := s.db.WithContext(ctx).Where("tenant_id = ? AND name = ? AND id != ?", tenantID, *req.Name, roleID).First(&existingRole).Error; err == nil {
			return nil, fmt.Errorf("role with name '%s' already exists", *req.Name)
		} else if err != gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("failed to check existing role: %w", err)
		}
		updates["name"] = *req.Name
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.Permissions != nil {
		if err := s.validatePermissions(*req.Permissions, role.TenantID); err != nil {
			return nil, fmt.Errorf("invalid permissions: %w", err)
		}

		var currentPerms models.Permissions
		if len(role.Permissions) > 0 {
			_ = json.Unmarshal(role.Permissions, &currentPerms)
		}

		permissionsJSON, _ := json.Marshal(*req.Permissions)
		updates["permissions"] = datatypes.JSON(permissionsJSON)

		s.logPermissionChanges(currentPerms, *req.Permissions, roleID, ctx)
	}

	if len(updates) > 0 {
		if err := s.db.WithContext(ctx).Model(&role).Updates(updates).Error; err != nil {
			return nil, fmt.Errorf("failed to update role: %w", err)
		}
	}

	return &role, nil
}

func (s *RoleService) DeleteRole(ctx context.Context, tenantID, roleID uuid.UUID) error {
	var role models.Role
	if err := s.db.WithContext(ctx).Where("id = ? AND tenant_id = ?", roleID, tenantID).First(&role).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return fmt.Errorf("role not found")
		}
		return fmt.Errorf("failed to get role: %w", err)
	}

	if role.IsSystem {
		return fmt.Errorf("cannot delete system role")
	}

	if err := s.db.WithContext(ctx).Delete(&role).Error; err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	return nil
}

func (s *RoleService) validatePermissions(permissions models.Permissions, tenantID uuid.UUID) error {
	var tenant models.Tenant
	if err := s.db.First(&tenant, tenantID).Error; err != nil {
		return fmt.Errorf("failed to get tenant: %w", err)
	}

	if tenant.Type == models.TenantTypeClient {
		if permissions.TenantCreate || permissions.TenantUpdate || permissions.TenantDelete || permissions.TenantList {
			return fmt.Errorf("client tenants cannot have tenant management permissions")
		}
		if permissions.SystemConfig || permissions.SystemMonitor || permissions.SystemMaintain {
			return fmt.Errorf("client tenants cannot have system permissions")
		}
	}

	return nil
}

func (s *RoleService) logPermissionChanges(oldPerms, newPerms models.Permissions, roleID uuid.UUID, ctx context.Context) {
	changes := make(map[string]interface{})

	if oldPerms.UserCreate != newPerms.UserCreate {
		changes["user_create"] = newPerms.UserCreate
	}
	if oldPerms.UserRead != newPerms.UserRead {
		changes["user_read"] = newPerms.UserRead
	}
	if oldPerms.UserUpdate != newPerms.UserUpdate {
		changes["user_update"] = newPerms.UserUpdate
	}
	if oldPerms.UserDelete != newPerms.UserDelete {
		changes["user_delete"] = newPerms.UserDelete
	}
	if oldPerms.RoleCreate != newPerms.RoleCreate {
		changes["role_create"] = newPerms.RoleCreate
	}
	if oldPerms.RoleUpdate != newPerms.RoleUpdate {
		changes["role_update"] = newPerms.RoleUpdate
	}
	if oldPerms.RoleDelete != newPerms.RoleDelete {
		changes["role_delete"] = newPerms.RoleDelete
	}
	if oldPerms.SSOCreate != newPerms.SSOCreate {
		changes["sso_create"] = newPerms.SSOCreate
	}
	if oldPerms.SSOUpdate != newPerms.SSOUpdate {
		changes["sso_update"] = newPerms.SSOUpdate
	}
	if oldPerms.SSODelete != newPerms.SSODelete {
		changes["sso_delete"] = newPerms.SSODelete
	}
	if oldPerms.TenantCreate != newPerms.TenantCreate {
		changes["tenant_create"] = newPerms.TenantCreate
	}
	if oldPerms.TenantUpdate != newPerms.TenantUpdate {
		changes["tenant_update"] = newPerms.TenantUpdate
	}
	if oldPerms.TenantDelete != newPerms.TenantDelete {
		changes["tenant_delete"] = newPerms.TenantDelete
	}
	if oldPerms.SystemConfig != newPerms.SystemConfig {
		changes["system_config"] = newPerms.SystemConfig
	}
	if oldPerms.SystemMonitor != newPerms.SystemMonitor {
		changes["system_monitor"] = newPerms.SystemMonitor
	}
	if oldPerms.SystemMaintain != newPerms.SystemMaintain {
		changes["system_maintain"] = newPerms.SystemMaintain
	}

	if len(changes) > 0 {
		s.logger.Info("Role permissions updated",
			zap.String("role_id", roleID.String()),
			zap.Any("changes", changes))
	}
}

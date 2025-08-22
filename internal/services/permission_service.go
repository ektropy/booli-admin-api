package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/booli/booli-admin-api/internal/keycloak"
	"go.uber.org/zap"
)

type PermissionService struct {
	keycloakAdmin *keycloak.AdminClient
	logger        *zap.Logger
}

func NewPermissionService(keycloakAdmin *keycloak.AdminClient, logger *zap.Logger) *PermissionService {
	return &PermissionService{
		keycloakAdmin: keycloakAdmin,
		logger:        logger,
	}
}

func (p *PermissionService) SetupRealmPermissions(ctx context.Context, realmName string) error {
	p.logger.Info("Setting up realm permissions", zap.String("realm", realmName))

	if err := p.keycloakAdmin.EnableFGAPv2(ctx, realmName); err != nil {
		return fmt.Errorf("failed to enable FGAPv2: %w", err)
	}

	for roleName, template := range keycloak.MSPPermissionTemplates {
		roleRep := &keycloak.RoleRepresentation{
			Name:        roleName,
			Description: template.Description,
		}
		if err := p.keycloakAdmin.CreateRole(ctx, realmName, roleRep); err != nil {
			if !strings.Contains(err.Error(), "already exists") {
				p.logger.Warn("Failed to create role",
					zap.String("realm", realmName),
					zap.String("role", roleName),
					zap.Error(err))
			}
		}

		if err := p.keycloakAdmin.CreatePermissionPolicy(ctx, realmName, roleName, template); err != nil {
			p.logger.Warn("Failed to create permission policy",
				zap.String("realm", realmName),
				zap.String("role", roleName),
				zap.Error(err))
		}
	}

	p.logger.Info("Realm permissions setup completed", zap.String("realm", realmName))
	return nil
}

func (p *PermissionService) AssignUserRole(ctx context.Context, realmName, userID, roleName string) error {
	p.logger.Info("Assigning user role with permissions",
		zap.String("realm", realmName),
		zap.String("user_id", userID),
		zap.String("role", roleName))

	if _, exists := keycloak.MSPPermissionTemplates[roleName]; !exists {
		return fmt.Errorf("unknown role: %s", roleName)
	}

	if err := p.keycloakAdmin.AssignRoleWithPermissions(ctx, realmName, userID, roleName); err != nil {
		return fmt.Errorf("failed to assign role with permissions: %w", err)
	}

	p.logger.Info("User role assigned successfully",
		zap.String("realm", realmName),
		zap.String("user_id", userID),
		zap.String("role", roleName))
	return nil
}

func (p *PermissionService) CheckUserPermission(ctx context.Context, realmName, userID, scope, resource string) (bool, error) {
	return p.keycloakAdmin.HasPermissionScope(ctx, realmName, userID, scope, resource)
}

func (p *PermissionService) GetUserEffectivePermissions(ctx context.Context, realmName, userID string) ([]string, error) {
	return p.keycloakAdmin.GetUserEffectiveScopes(ctx, realmName, userID)
}

func (p *PermissionService) ValidateRoleHierarchy(userRole, requiredRole string) bool {
	hierarchy := map[string]int{
		"tenant-viewer": 1,
		"tenant-user":   2,
		"tenant-admin":  3,
		"msp-viewer":    4,
		"msp-power":     5,
		"msp-admin":     6,
	}
	
	userLevel, userExists := hierarchy[userRole]
	requiredLevel, requiredExists := hierarchy[requiredRole]
	
	if !userExists || !requiredExists {
		return false
	}
	
	return userLevel >= requiredLevel
}

func (p *PermissionService) GetUserHighestRole(ctx context.Context, realmName, userID string) (string, error) {
	roles, err := p.keycloakAdmin.GetUserRealmRoles(ctx, realmName, userID)
	if err != nil {
		return "", fmt.Errorf("failed to get user roles: %w", err)
	}

	hierarchy := map[string]int{
		"tenant-viewer": 1,
		"tenant-user":   2,
		"tenant-admin":  3,
		"msp-viewer":    4,
		"msp-power":     5,
		"msp-admin":     6,
	}
	highestLevel := 0
	highestRole := ""

	for _, role := range roles {
		if level, exists := hierarchy[role.Name]; exists && level > highestLevel {
			highestLevel = level
			highestRole = role.Name
		}
	}

	if highestRole == "" {
		return "tenant-viewer", nil
	}

	return highestRole, nil
}

func (p *PermissionService) CreateMSPPermissionStructure(ctx context.Context, mspRealm, clientPattern string) error {
	p.logger.Info("Creating MSP permission structure",
		zap.String("msp_realm", mspRealm),
		zap.String("client_pattern", clientPattern))

	if err := p.SetupRealmPermissions(ctx, mspRealm); err != nil {
		return fmt.Errorf("failed to setup MSP realm permissions: %w", err)
	}

	mspConfig := map[string]interface{}{
		"msp_realm":         mspRealm,
		"client_pattern":    clientPattern,
		"isolation_enabled": true,
	}

	p.logger.Info("MSP permission structure created successfully",
		zap.String("msp_realm", mspRealm),
		zap.Any("config", mspConfig))
	return nil
}

func (p *PermissionService) ValidateCrossRealmAccess(ctx context.Context, userRealm, userID, targetRealm string) (bool, error) {
	userRole, err := p.GetUserHighestRole(ctx, userRealm, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user role: %w", err)
	}

	if userRealm == targetRealm {
		return true, nil
	}

	if userRole == "msp-admin" || userRole == "msp-power" {
		if p.isMSPClientRelationship(userRealm, targetRealm) {
			return true, nil
		}
	}

	return false, nil
}

func (p *PermissionService) isMSPClientRelationship(mspRealm, clientRealm string) bool {
	if !strings.HasPrefix(mspRealm, "msp-") {
		return false
	}
	
	mspName := strings.TrimPrefix(mspRealm, "msp-")
	expectedPrefix := fmt.Sprintf("%s-client-", mspName)
	
	return strings.HasPrefix(clientRealm, expectedPrefix)
}
package services

import (
	"context"
	"fmt"

	"github.com/booli/booli-admin-api/internal/keycloak"
	"go.uber.org/zap"
)

type RealmSetupService struct {
	keycloakAdmin *keycloak.AdminClient
	logger        *zap.Logger
}

func NewRealmSetupService(keycloakAdmin *keycloak.AdminClient, logger *zap.Logger) *RealmSetupService {
	return &RealmSetupService{
		keycloakAdmin: keycloakAdmin,
		logger:        logger,
	}
}

type MSPRole struct {
	Name        string
	Description string
	Composite   bool
	ClientRole  bool
}

func (s *RealmSetupService) GetMSPRoles() []MSPRole {
	return []MSPRole{
		{
			Name:        "msp-admin",
			Description: "MSP Administrator - Full access to all tenant realms and MSP operations",
			Composite:   false,
			ClientRole:  false,
		},
		{
			Name:        "msp-power",
			Description: "MSP Power User - Write access to tenant realms, limited MSP operations",
			Composite:   false,
			ClientRole:  false,
		},
		{
			Name:        "msp-viewer",
			Description: "MSP Viewer - Read-only access to tenant realms and MSP information",
			Composite:   false,
			ClientRole:  false,
		},
	}
}

func (s *RealmSetupService) GetTenantRoles() []MSPRole {
	return []MSPRole{
		{
			Name:        "tenant-admin",
			Description: "Tenant Administrator - Full access to tenant resources",
			Composite:   false,
			ClientRole:  false,
		},
		{
			Name:        "tenant-user",
			Description: "Tenant User - Standard user access to tenant resources",
			Composite:   false,
			ClientRole:  false,
		},
		{
			Name:        "tenant-viewer",
			Description: "Tenant Viewer - Read-only access to tenant resources",
			Composite:   false,
			ClientRole:  false,
		},
	}
}

func (s *RealmSetupService) SetupMasterRealm(ctx context.Context) error {
	s.logger.Info("Setting up master realm with MSP roles")

	mspRoles := s.GetMSPRoles()
	for _, role := range mspRoles {
		if err := s.createRealmRole(ctx, "master", role); err != nil {
			return fmt.Errorf("failed to create MSP role %s: %w", role.Name, err)
		}
	}

	s.logger.Info("Master realm setup completed successfully")
	return nil
}

func (s *RealmSetupService) SetupTenantRealm(ctx context.Context, realmName string) error {
	s.logger.Info("Setting up tenant realm with standard roles", zap.String("realm", realmName))

	tenantRoles := s.GetTenantRoles()
	for _, role := range tenantRoles {
		if err := s.createRealmRole(ctx, realmName, role); err != nil {
			return fmt.Errorf("failed to create tenant role %s in realm %s: %w", role.Name, realmName, err)
		}
	}

	s.logger.Info("Tenant realm setup completed successfully", zap.String("realm", realmName))
	return nil
}

func (s *RealmSetupService) SetupMSPRealm(ctx context.Context, mspRealmName string) error {
	s.logger.Info("Setting up MSP realm with MSP and tenant roles", zap.String("realm", mspRealmName))

	mspRoles := s.GetMSPRoles()
	for _, role := range mspRoles {
		if err := s.createRealmRole(ctx, mspRealmName, role); err != nil {
			return fmt.Errorf("failed to create MSP role %s in realm %s: %w", role.Name, mspRealmName, err)
		}
	}

	tenantRoles := s.GetTenantRoles()
	for _, role := range tenantRoles {
		if err := s.createRealmRole(ctx, mspRealmName, role); err != nil {
			return fmt.Errorf("failed to create tenant role %s in MSP realm %s: %w", role.Name, mspRealmName, err)
		}
	}

	s.logger.Info("MSP realm setup completed successfully", zap.String("realm", mspRealmName))
	return nil
}

func (s *RealmSetupService) createRealmRole(ctx context.Context, realmName string, role MSPRole) error {
	existingRole, err := s.keycloakAdmin.GetRealmRole(ctx, realmName, role.Name)
	if err == nil && existingRole != nil {
		s.logger.Debug("Role already exists, skipping creation",
			zap.String("realm", realmName),
			zap.String("role", role.Name))
		return nil
	}

	err = s.keycloakAdmin.CreateRealmRole(ctx, realmName, role.Name, role.Description)
	if err != nil {
		return fmt.Errorf("failed to create realm role: %w", err)
	}

	s.logger.Info("Created realm role",
		zap.String("realm", realmName),
		zap.String("role", role.Name),
		zap.String("description", role.Description))

	return nil
}

func (s *RealmSetupService) EnsureMSPAdminUser(ctx context.Context, username, email, password string) error {
	s.logger.Info("Ensuring MSP admin user exists", zap.String("username", username))

	existingUser, err := s.keycloakAdmin.GetUserByUsername(ctx, "master", username)
	if err != nil && existingUser == nil {
		userRepresentation := &keycloak.UserRepresentation{
			Username: username,
			Email:    email,
			Enabled:  true,
			Credentials: []keycloak.CredentialRepresentation{
				{
					Type:      "password",
					Value:     password,
					Temporary: false,
				},
			},
		}

		createdUser, err := s.keycloakAdmin.CreateUser(ctx, "master", userRepresentation)
		if err != nil {
			return fmt.Errorf("failed to create MSP admin user: %w", err)
		}

		s.logger.Info("Created MSP admin user",
			zap.String("username", createdUser.Username),
			zap.String("user_id", createdUser.ID))

		existingUser = createdUser
	}

	err = s.keycloakAdmin.AssignRealmRoleToUser(ctx, "master", existingUser.ID, "msp-admin")
	if err != nil {
		return fmt.Errorf("failed to assign MSP admin role: %w", err)
	}

	s.logger.Info("MSP admin user setup completed successfully",
		zap.String("username", username),
		zap.String("user_id", existingUser.ID))

	return nil
}

func (s *RealmSetupService) ValidateRealmRoleSetup(ctx context.Context, realmName string, isMSPRealm bool) error {
	s.logger.Info("Validating realm role setup", zap.String("realm", realmName))

	var expectedRoles []MSPRole
	if isMSPRealm {
		expectedRoles = append(s.GetMSPRoles(), s.GetTenantRoles()...)
	} else {
		expectedRoles = s.GetTenantRoles()
	}

	for _, expectedRole := range expectedRoles {
		role, err := s.keycloakAdmin.GetRealmRole(ctx, realmName, expectedRole.Name)
		if err != nil || role == nil {
			return fmt.Errorf("required role %s not found in realm %s", expectedRole.Name, realmName)
		}

		s.logger.Debug("Validated realm role",
			zap.String("realm", realmName),
			zap.String("role", role.Name))
	}

	s.logger.Info("Realm role setup validation completed successfully", zap.String("realm", realmName))
	return nil
}

func (s *RealmSetupService) GetRealmRoleHierarchy() map[string]int {
	return map[string]int{
		"tenant-viewer": 1,
		"tenant-user":   2,
		"tenant-admin":  3,
		"msp-viewer":    4,
		"msp-power":     5,
		"msp-admin":     6,
	}
}

func (s *RealmSetupService) DetermineAccessLevelFromRoles(roles []string) keycloak.RealmAccessLevel {
	hierarchy := s.GetRealmRoleHierarchy()
	maxLevel := 0

	for _, role := range roles {
		if level, exists := hierarchy[role]; exists && level > maxLevel {
			maxLevel = level
		}
	}

	switch {
	case maxLevel >= 6: // msp-admin
		return keycloak.RealmAccessMSPAdmin
	case maxLevel >= 5: // msp-power
		return keycloak.RealmAccessWrite
	case maxLevel >= 4: // msp-viewer
		return keycloak.RealmAccessRead
	case maxLevel >= 3: // tenant-admin
		return keycloak.RealmAccessAdmin
	case maxLevel >= 2: // tenant-user
		return keycloak.RealmAccessWrite
	case maxLevel >= 1: // tenant-viewer
		return keycloak.RealmAccessRead
	default:
		return keycloak.RealmAccessNone
	}
}

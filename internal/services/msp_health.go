package services

import (
	"context"
	"fmt"

	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/booli/booli-admin-api/internal/models"
	"go.uber.org/zap"
)

type MSPHealth struct {
	RealmName    string   `json:"realm_name"`
	InDatabase   bool     `json:"in_database"`
	InKeycloak   bool     `json:"in_keycloak"`
	RealmEnabled bool     `json:"realm_enabled"`
	RolesCreated []string `json:"roles_created"`
	MissingRoles []string `json:"missing_roles"`
	Issues       []string `json:"issues,omitempty"`
	Status       string   `json:"status"`
}

func (m *MSPService) HealthCheck(ctx context.Context) ([]MSPHealth, error) {
	m.logger.Info("Starting MSP health check")

	var msps []models.MSP
	if err := m.db.Find(&msps).Error; err != nil {
		return nil, fmt.Errorf("failed to get MSPs from database: %w", err)
	}

	var healthChecks []MSPHealth

	for _, msp := range msps {
		health := m.checkMSPHealth(ctx, &msp)
		healthChecks = append(healthChecks, health)
	}

	keycloakRealms, err := m.getKeycloakMSPRealms(ctx)
	if err != nil {
		m.logger.Warn("Failed to get Keycloak realms", zap.Error(err))
	} else {
		for _, realmName := range keycloakRealms {
			if !m.realmInDatabase(realmName, msps) {
				health := MSPHealth{
					RealmName:    realmName,
					InDatabase:   false,
					InKeycloak:   true,
					RealmEnabled: true,
					Issues:       []string{"Realm exists in Keycloak but not in database"},
					Status:       "warning",
				}
				healthChecks = append(healthChecks, health)
			}
		}
	}

	m.logger.Info("MSP health check completed", zap.Int("checked", len(healthChecks)))
	return healthChecks, nil
}

func (m *MSPService) checkMSPHealth(ctx context.Context, msp *models.MSP) MSPHealth {
	health := MSPHealth{
		RealmName:  msp.RealmName,
		InDatabase: true,
		Status:     "healthy",
	}

	realm, err := m.keycloakAdmin.GetRealm(ctx, msp.RealmName)
	if err != nil {
		health.InKeycloak = false
		health.Issues = append(health.Issues, "Realm not found in Keycloak")
		health.Status = "error"
		return health
	}

	health.InKeycloak = true
	health.RealmEnabled = realm.Enabled

	if !realm.Enabled {
		health.Issues = append(health.Issues, "Realm is disabled in Keycloak")
		health.Status = "warning"
	}

	expectedRoles := []string{"msp-admin", "msp-power", "msp-basic"}
	health.RolesCreated, health.MissingRoles = m.checkRealmRoles(ctx, msp.RealmName, expectedRoles)

	if len(health.MissingRoles) > 0 {
		health.Issues = append(health.Issues, fmt.Sprintf("Missing roles: %v", health.MissingRoles))
		if health.Status == "healthy" {
			health.Status = "warning"
		}
	}

	if !msp.Active && health.Status == "healthy" {
		health.Issues = append(health.Issues, "MSP is marked as inactive in database")
		health.Status = "warning"
	}

	return health
}

func (m *MSPService) checkRealmRoles(ctx context.Context, realmName string, expectedRoles []string) ([]string, []string) {
	var rolesCreated []string
	var missingRoles []string

	for _, roleName := range expectedRoles {
		_, err := m.keycloakAdmin.GetRealmRole(ctx, realmName, roleName)
		if err != nil {
			missingRoles = append(missingRoles, roleName)
		} else {
			rolesCreated = append(rolesCreated, roleName)
		}
	}

	return rolesCreated, missingRoles
}

func (m *MSPService) getKeycloakMSPRealms(ctx context.Context) ([]string, error) {
	realms, err := m.keycloakAdmin.GetRealms(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get realms from Keycloak: %w", err)
	}

	var mspRealms []string
	for _, realm := range realms {
		if realm.Realm != "master" && (realm.Realm == "msp-platform-local" ||
			(len(realm.Realm) > 4 && realm.Realm[:4] == "msp-")) {
			mspRealms = append(mspRealms, realm.Realm)
		}
	}

	return mspRealms, nil
}

func (m *MSPService) realmInDatabase(realmName string, msps []models.MSP) bool {
	for _, msp := range msps {
		if msp.RealmName == realmName {
			return true
		}
	}
	return false
}

func (m *MSPService) Reconcile(ctx context.Context, realmName string) (*MSPHealth, error) {
	m.logger.Info("Starting MSP reconciliation", zap.String("realm", realmName))

	var msp models.MSP
	err := m.db.Where("realm_name = ?", realmName).First(&msp).Error

	if err != nil {
		return nil, fmt.Errorf("MSP not found in database: %s", realmName)
	}

	health := m.checkMSPHealth(ctx, &msp)

	if len(health.MissingRoles) > 0 {
		m.logger.Info("Creating missing roles",
			zap.String("realm", realmName),
			zap.Strings("roles", health.MissingRoles))

		for _, roleName := range health.MissingRoles {
			if template, exists := keycloak.MSPPermissionTemplates[roleName]; exists {
				roleRep := &keycloak.RoleRepresentation{
					Name:        roleName,
					Description: template.Description,
				}
				if err := m.keycloakAdmin.CreateRole(ctx, realmName, roleRep); err != nil {
					m.logger.Warn("Failed to create role during reconciliation",
						zap.String("realm", realmName),
						zap.String("role", roleName),
						zap.Error(err))
				} else {
					m.logger.Info("Role created during reconciliation",
						zap.String("realm", realmName),
						zap.String("role", roleName))
				}
			}
		}

		if err := m.permissionService.SetupRealmPermissions(ctx, realmName); err != nil {
			m.logger.Warn("Failed to setup permissions during reconciliation",
				zap.String("realm", realmName),
				zap.Error(err))
		}
	}

	finalHealth := m.checkMSPHealth(ctx, &msp)
	m.logger.Info("MSP reconciliation completed",
		zap.String("realm", realmName),
		zap.String("status", finalHealth.Status))

	return &finalHealth, nil
}

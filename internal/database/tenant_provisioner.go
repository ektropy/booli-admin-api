package database

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/booli/booli-admin-api/internal/services"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

// TenantConfig represents a single tenant configuration in YAML
type TenantConfig struct {
	Name     string                  `yaml:"name"`
	Domain   string                  `yaml:"domain"`
	Type     string                  `yaml:"type"` // "msp", "partner", "direct", or "client"
	Settings TenantSettingsConfig    `yaml:"settings"`
	IDPs     []IDPConfig             `yaml:"idps,omitempty"`
}

// TenantSettingsConfig represents tenant settings in YAML
type TenantSettingsConfig struct {
	EnableSSO         bool     `yaml:"enable_sso"`
	EnableMFA         bool     `yaml:"enable_mfa"`
	EnableAudit       bool     `yaml:"enable_audit"`
	MaxUsers          int      `yaml:"max_users"`
	MaxRoles          int      `yaml:"max_roles"`
	MaxSSOProviders   int      `yaml:"max_sso_providers"`
	DataRetentionDays int      `yaml:"data_retention_days"`
	ComplianceFlags   []string `yaml:"compliance_flags"`
}

// IDPConfig represents an identity provider configuration in YAML
type IDPConfig struct {
	Alias      string            `yaml:"alias"`
	ProviderID string            `yaml:"provider_id"`
	Enabled    bool              `yaml:"enabled"`
	Config     map[string]string `yaml:"config"`
}

// TenantsYAML represents the root structure of the tenants YAML file
type TenantsYAML struct {
	Tenants []TenantConfig `yaml:"tenants"`
}

// ProvisionTenantsFromYAML loads and provisions tenants from a YAML file
// This creates full tenant infrastructure including Keycloak realm and OIDC provider
func ProvisionTenantsFromYAML(
	ctx context.Context,
	db *gorm.DB,
	tenantService *services.TenantService,
	keycloakAdmin *keycloak.AdminClient,
	logger *zap.Logger,
	yamlPath string,
) error {
	if yamlPath == "" {
		yamlPath = "/config/tenants.yaml"
	}

	// Check if file exists
	if _, err := os.Stat(yamlPath); os.IsNotExist(err) {
		logger.Info("Tenants YAML file not found, skipping provisioning",
			zap.String("path", yamlPath))
		return nil
	}

	logger.Info("Loading tenants configuration from YAML",
		zap.String("path", yamlPath))

	// Read YAML file
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		return fmt.Errorf("failed to read tenants YAML file: %w", err)
	}

	// Parse YAML
	var tenantsConfig TenantsYAML
	if err := yaml.Unmarshal(data, &tenantsConfig); err != nil {
		return fmt.Errorf("failed to parse tenants YAML: %w", err)
	}

	logger.Info("Parsed tenants configuration",
		zap.Int("tenant_count", len(tenantsConfig.Tenants)))

	// Provision each tenant
	for _, tenantConfig := range tenantsConfig.Tenants {
		if err := provisionTenant(ctx, db, tenantService, keycloakAdmin, logger, tenantConfig); err != nil {
			logger.Error("Failed to provision tenant",
				zap.String("tenant", tenantConfig.Name),
				zap.Error(err))
			// Continue with other tenants even if one fails
			continue
		}
	}

	return nil
}

func provisionTenant(
	ctx context.Context,
	db *gorm.DB,
	tenantService *services.TenantService,
	keycloakAdmin *keycloak.AdminClient,
	logger *zap.Logger,
	config TenantConfig,
) error {
	var existingTenant models.Tenant
	err := db.Where("name = ?", config.Name).First(&existingTenant).Error
	if err == nil {
		logger.Info("Tenant already exists, skipping",
			zap.String("tenant", config.Name),
			zap.String("realm", existingTenant.RealmName))
		return nil
	} else if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("failed to check existing tenant: %w", err)
	}

	logger.Info("Provisioning new tenant",
		zap.String("tenant", config.Name),
		zap.String("type", config.Type))

	var tenantType models.TenantType
	switch config.Type {
	case "msp":
		tenantType = models.TenantTypeMSP
	case "partner":
		tenantType = models.TenantTypeMSP
	case "direct", "client":
		tenantType = models.TenantTypeClient
	default:
		tenantType = models.TenantTypeClient
	}

	settingsJSON, err := json.Marshal(models.TenantSettings{
		EnableSSO:         config.Settings.EnableSSO,
		EnableMFA:         config.Settings.EnableMFA,
		EnableAudit:       config.Settings.EnableAudit,
		MaxUsers:          config.Settings.MaxUsers,
		MaxRoles:          config.Settings.MaxRoles,
		MaxSSOProviders:   config.Settings.MaxSSOProviders,
		DataRetentionDays: config.Settings.DataRetentionDays,
		ComplianceFlags:   config.Settings.ComplianceFlags,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal tenant settings: %w", err)
	}

	createReq := &models.CreateTenantRequest{
		Name:     config.Name,
		Domain:   config.Domain,
		Type:     tenantType,
		Settings: settingsJSON,
	}

	tenant, err := tenantService.CreateTenant(ctx, createReq, "")
	if err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	logger.Info("Tenant provisioned successfully",
		zap.String("tenant", config.Name),
		zap.String("realm", tenant.RealmName),
		zap.String("oidc_provider", "keycloak-"+tenant.RealmName))

	for _, idpConfig := range config.IDPs {
		idp := &keycloak.IdentityProviderRepresentation{
			Alias:      idpConfig.Alias,
			ProviderId: idpConfig.ProviderID,
			Enabled:    idpConfig.Enabled,
			TrustEmail: true,
			Config:     idpConfig.Config,
		}

		err := keycloakAdmin.CreateIdentityProvider(ctx, tenant.RealmName, idp)
		if err != nil {
			logger.Error("Failed to create identity provider",
				zap.String("tenant", config.Name),
				zap.String("realm", tenant.RealmName),
				zap.String("idp", idpConfig.Alias),
				zap.Error(err))
			continue
		}

		logger.Info("Identity provider created successfully",
			zap.String("tenant", config.Name),
			zap.String("realm", tenant.RealmName),
			zap.String("idp", idpConfig.Alias))
	}

	return nil
}

// LoadTenantsYAMLFromConfig attempts to load from common locations
func LoadTenantsYAMLFromConfig() string {
	// Try these paths in order
	paths := []string{
		os.Getenv("BOOLI_TENANTS_CONFIG"), // Environment variable override
		"/config/tenants.yaml",              // Kubernetes ConfigMap mount
		"/etc/booli/tenants.yaml",           // System config
		"./config/tenants.yaml",             // Local development
		"./tenants.yaml",                    // Current directory
	}

	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// ValidateTenantsYAML validates a tenants YAML file without provisioning
func ValidateTenantsYAML(yamlPath string) error {
	if yamlPath == "" {
		return fmt.Errorf("yaml path is required")
	}

	absPath, err := filepath.Abs(yamlPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var tenantsConfig TenantsYAML
	if err := yaml.Unmarshal(data, &tenantsConfig); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	if len(tenantsConfig.Tenants) == 0 {
		return fmt.Errorf("no tenants defined in YAML")
	}

	// Validate each tenant
	for i, tenant := range tenantsConfig.Tenants {
		if tenant.Name == "" {
			return fmt.Errorf("tenant %d: name is required", i)
		}
		if tenant.Domain == "" {
			return fmt.Errorf("tenant %s: domain is required", tenant.Name)
		}
		if tenant.Type != "msp" && tenant.Type != "partner" && tenant.Type != "direct" && tenant.Type != "client" {
			return fmt.Errorf("tenant %s: invalid type '%s' (must be msp, partner, direct, or client)", tenant.Name, tenant.Type)
		}
	}

	return nil
}

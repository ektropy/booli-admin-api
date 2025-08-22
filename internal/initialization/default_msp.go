package initialization

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/booli/booli-admin-api/internal/models"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type DefaultMSPConfig struct {
	Enabled   bool
	Name      string
	Domain    string
	RealmName string
}

func GetDefaultMSPConfig() *DefaultMSPConfig {
	enabled := os.Getenv("KEYCLOAK_DEFAULT_MSP_ENABLED")
	if enabled != "true" {
		return nil
	}

	config := &DefaultMSPConfig{
		Enabled:   true,
		Name:      getEnvOrDefault("KEYCLOAK_DEFAULT_MSP_NAME", "Platform Administration"),
		Domain:    getEnvOrDefault("KEYCLOAK_DEFAULT_MSP_DOMAIN", "platform-local"),
		RealmName: getEnvOrDefault("KEYCLOAK_DEFAULT_MSP_REALM", "msp-platform-local"),
	}

	return config
}

func CreateDefaultMSP(ctx context.Context, db *gorm.DB, logger *zap.Logger) error {
	config := GetDefaultMSPConfig()
	if config == nil || !config.Enabled {
		logger.Info("Default MSP creation is disabled")
		return nil
	}

	logger.Info("Creating default MSP",
		zap.String("name", config.Name),
		zap.String("domain", config.Domain),
		zap.String("realm", config.RealmName))

	var existingMSP models.MSP
	err := db.Where("realm_name = ?", config.RealmName).First(&existingMSP).Error
	if err == nil {
		logger.Info("Default MSP already exists",
			zap.String("realm", config.RealmName))
		return nil
	}

	if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("failed to check existing MSP: %w", err)
	}

	settings := models.MSPSettings{
		MaxClientTenants: -1,
		MaxAdminUsers:    -1,
		MaxPowerUsers:    -1,
		EnabledFeatures: []string{
			"multi-tenant",
			"sso",
			"audit",
			"api-access",
		},
		NotificationEmail: "admin@" + config.Domain,
		Timezone:          "UTC",
		Region:            "global",
	}

	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshal MSP settings: %w", err)
	}

	msp := &models.MSP{
		RealmName:     config.RealmName,
		Name:          config.Name,
		Domain:        config.Domain,
		ClientPattern: config.Domain + "-client-",
		Active:        true,
		Settings:      settingsJSON,
	}

	if err := db.Create(msp).Error; err != nil {
		return fmt.Errorf("failed to create default MSP: %w", err)
	}

	logger.Info("Default MSP created successfully",
		zap.String("realm", config.RealmName),
		zap.String("name", config.Name))

	return nil
}
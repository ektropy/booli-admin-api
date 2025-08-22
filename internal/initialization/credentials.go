package initialization

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"strings"

	"go.uber.org/zap"
)

const (
	passwordCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
	passwordLength  = 16
)

type PlatformAdminConfig struct {
	Username            string
	Password            string
	Email               string
	ForcePasswordChange bool
}

func GenerateSecurePassword() (string, error) {
	b := make([]byte, passwordLength)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(passwordCharset))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %w", err)
		}
		b[i] = passwordCharset[n.Int64()]
	}
	return string(b), nil
}

func GetPlatformAdminConfig(logger *zap.Logger) (*PlatformAdminConfig, error) {
	config := &PlatformAdminConfig{
		Username: getEnvOrDefault("PLATFORM_ADMIN_USERNAME", "platform-admin"),
		Email:    getEnvOrDefault("PLATFORM_ADMIN_EMAIL", "admin@platform.local"),
		Password: os.Getenv("PLATFORM_ADMIN_PASSWORD"),
	}

	if config.Password == "" {
		generatedPassword, err := GenerateSecurePassword()
		if err != nil {
			return nil, fmt.Errorf("failed to generate secure password: %w", err)
		}
		config.Password = generatedPassword
		config.ForcePasswordChange = true

		if logger != nil {
			logger.Info("=====================================")
			logger.Info("PLATFORM ADMIN CREDENTIALS GENERATED")
			logger.Info("=====================================")
			logger.Info("Username", zap.String("value", config.Username))
			logger.Info("Password", zap.String("value", config.Password))
			logger.Info("Email", zap.String("value", config.Email))
			logger.Info("=====================================")
			logger.Warn("SAVE THESE CREDENTIALS SECURELY - THEY WON'T BE SHOWN AGAIN")
			logger.Warn("Password change will be required on first login")
			logger.Info("=====================================")
		}
	} else {
		if logger != nil {
			logger.Info("Using configured platform admin credentials",
				zap.String("username", config.Username),
				zap.String("email", config.Email))
		}
	}

	return config, nil
}

func GetDefaultMSPAdminConfig(logger *zap.Logger) (*PlatformAdminConfig, error) {
	config := &PlatformAdminConfig{
		Username: getEnvOrDefault("KEYCLOAK_MSP_DEFAULT_USER_USERNAME", "msp-admin"),
		Email:    getEnvOrDefault("KEYCLOAK_MSP_DEFAULT_USER_EMAIL", "admin@msp.local"),
		Password: os.Getenv("KEYCLOAK_MSP_DEFAULT_USER_PASSWORD"),
	}

	if config.Password == "" {
		generatedPassword, err := GenerateSecurePassword()
		if err != nil {
			return nil, fmt.Errorf("failed to generate secure password: %w", err)
		}
		config.Password = generatedPassword
		config.ForcePasswordChange = true

		if logger != nil {
			logger.Info("=====================================")
			logger.Info("DEFAULT MSP ADMIN CREDENTIALS GENERATED")
			logger.Info("=====================================")
			logger.Info("Username", zap.String("value", config.Username))
			logger.Info("Password", zap.String("value", config.Password))
			logger.Info("Email", zap.String("value", config.Email))
			logger.Info("=====================================")
			logger.Warn("SAVE THESE CREDENTIALS SECURELY - THEY WON'T BE SHOWN AGAIN")
			logger.Warn("Password change will be required on first login")
			logger.Info("=====================================")
		}
	}

	return config, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return strings.TrimSpace(value)
	}
	return defaultValue
}
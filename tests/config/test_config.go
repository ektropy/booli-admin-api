package config

import (
	"os"
	"time"
)

type TestConfig struct {
	KeycloakVersion string
	PostgresVersion string
	ValkeyVersion   string

	KeycloakAdminUser     string
	KeycloakAdminPassword string
	KeycloakMasterRealm   string
	KeycloakMSPRealm      string
	KeycloakClientID      string
	KeycloakClientSecret  string

	PostgresUser     string
	PostgresPassword string
	PostgresDB       string

	StartupTimeout  time.Duration
	ShutdownTimeout time.Duration
	PollInterval    time.Duration

	APIBasePath string
	APIAudience string
	BackendHost string
	BackendPort string

	DefaultTestUsers []TestUser
	DefaultRoles     []string
}

type TestUser struct {
	Username  string
	Password  string
	Email     string
	FirstName string
	LastName  string
	Roles     []string
}

func GetTestConfig() *TestConfig {
	return &TestConfig{
		KeycloakVersion: getEnvOrDefault("TEST_KEYCLOAK_VERSION", "26.3.3"),
		PostgresVersion: getEnvOrDefault("TEST_POSTGRES_VERSION", "15-alpine"),
		ValkeyVersion:   getEnvOrDefault("TEST_VALKEY_VERSION", "8.0-alpine"),

		KeycloakAdminUser:     getEnvOrDefault("TEST_KEYCLOAK_ADMIN_USER", "admin"),
		KeycloakAdminPassword: getEnvOrDefault("TEST_KEYCLOAK_ADMIN_PASSWORD", "admin"),
		KeycloakMasterRealm:   "master",
		KeycloakMSPRealm:      getEnvOrDefault("TEST_KEYCLOAK_MSP_REALM", "master"),
		KeycloakClientID:      getEnvOrDefault("TEST_KEYCLOAK_CLIENT_ID", "msp-client"),
		KeycloakClientSecret:  getEnvOrDefault("TEST_KEYCLOAK_CLIENT_SECRET", "msp-secret"),

		PostgresUser:     getEnvOrDefault("TEST_POSTGRES_USER", "postgres"),
		PostgresPassword: getEnvOrDefault("TEST_POSTGRES_PASSWORD", "postgres"),
		PostgresDB:       getEnvOrDefault("TEST_POSTGRES_DB", "booli_admin_test"),

		StartupTimeout:  getDurationOrDefault("TEST_STARTUP_TIMEOUT", 300*time.Second),
		ShutdownTimeout: getDurationOrDefault("TEST_SHUTDOWN_TIMEOUT", 30*time.Second),
		PollInterval:    getDurationOrDefault("TEST_POLL_INTERVAL", 5*time.Second),

		APIBasePath: "/api/2025-08-01",
		APIAudience: getEnvOrDefault("TEST_API_AUDIENCE", "booli-admin-api"),
		BackendHost: getEnvOrDefault("TEST_BACKEND_HOST", "localhost"),
		BackendPort: getEnvOrDefault("TEST_BACKEND_PORT", "8749"),

		DefaultTestUsers: []TestUser{
			{
				Username:  "msp-admin",
				Password:  "admin123",
				Email:     "msp-admin@test.com",
				FirstName: "MSP Admin",
				LastName:  "User",
				Roles:     []string{"msp-admin"},
			},
			{
				Username:  "test-user",
				Password:  "test123",
				Email:     "user@test.com",
				FirstName: "Test",
				LastName:  "User",
				Roles:     []string{"user"},
			},
		},

		DefaultRoles: []string{
			"msp-admin",
			"msp-power",
			"msp-basic",
			"tenant-admin",
			"tenant-power",
			"tenant-basic",
			"user",
		},
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

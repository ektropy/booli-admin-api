package config

import (
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zapcore"
)

func TestLoad(t *testing.T) {
	// Clean environment
	cleanEnv()
	defer restoreEnv()
	
	cfg, err := Load()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	
	// Verify defaults
	assert.Equal(t, "production", cfg.Environment)
	assert.Equal(t, "8080", cfg.Server.Port)
}

func TestLoadConfig(t *testing.T) {
	// Clean environment
	cleanEnv()
	defer restoreEnv()
	
	cfg, err := LoadConfig("")
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "production", cfg.Environment)
}

func TestLoadWithConfigFile_NonExistentFile(t *testing.T) {
	cfg, err := LoadWithConfigFile("non-existent.yaml")
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "error reading config file")
}

func TestLoadWithConfigFile_EmptyFile(t *testing.T) {
	// Clean environment first
	cleanEnv()
	defer restoreEnv()
	
	cfg, err := LoadWithConfigFile("")
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
}

func TestSetDefaults(t *testing.T) {
	// Reset viper
	viper.Reset()
	
	setDefaults()
	
	// Test all defaults are set
	assert.Equal(t, "production", viper.GetString("environment"))
	assert.Equal(t, "8080", viper.GetString("server.port"))
	assert.Equal(t, 30, viper.GetInt("server.read_timeout"))
	assert.Equal(t, 30, viper.GetInt("server.write_timeout"))
	assert.Equal(t, 120, viper.GetInt("server.idle_timeout"))
	
	assert.Equal(t, "", viper.GetString("database.host"))
	assert.Equal(t, 5432, viper.GetInt("database.port"))
	assert.Equal(t, "", viper.GetString("database.user"))
	assert.Equal(t, "", viper.GetString("database.password"))
	assert.Equal(t, "", viper.GetString("database.dbname"))
	assert.Equal(t, "require", viper.GetString("database.sslmode"))
	assert.Equal(t, 25, viper.GetInt("database.max_connections"))
	assert.Equal(t, 5, viper.GetInt("database.max_idle"))
	assert.Equal(t, 10, viper.GetInt("database.connect_timeout"))
	assert.Equal(t, 3600, viper.GetInt("database.max_lifetime"))
	assert.Equal(t, 300, viper.GetInt("database.max_idle_time"))
	
	assert.Equal(t, "", viper.GetString("redis.host"))
	assert.Equal(t, 6379, viper.GetInt("redis.port"))
	assert.Equal(t, "", viper.GetString("redis.password"))
	assert.Equal(t, 0, viper.GetInt("redis.db"))
	assert.Equal(t, 10, viper.GetInt("redis.dial_timeout"))
	assert.Equal(t, 10, viper.GetInt("redis.read_timeout"))
	assert.Equal(t, 10, viper.GetInt("redis.write_timeout"))
	
	assert.Equal(t, "", viper.GetString("keycloak.url"))
	assert.Equal(t, "", viper.GetString("keycloak.admin_user"))
	assert.Equal(t, "", viper.GetString("keycloak.admin_password"))
	assert.Equal(t, "master", viper.GetString("keycloak.master_realm"))
	assert.Equal(t, "msp", viper.GetString("keycloak.msp_realm"))
	assert.Equal(t, "", viper.GetString("keycloak.client_id"))
	assert.Equal(t, "", viper.GetString("keycloak.client_secret"))
	assert.Equal(t, "", viper.GetString("keycloak.callback_url"))
	assert.Equal(t, "booli-admin-api", viper.GetString("keycloak.api_audience"))
	assert.False(t, viper.GetBool("keycloak.skip_tls_verify"))
	assert.Equal(t, "", viper.GetString("keycloak.ca_cert_path"))
}

func TestNewLogger_Development(t *testing.T) {
	logger, err := NewLogger("development")
	assert.NoError(t, err)
	assert.NotNil(t, logger)
	
	// Clean up
	logger.Sync()
}

func TestNewLogger_Production(t *testing.T) {
	logger, err := NewLogger("production")
	assert.NoError(t, err)
	assert.NotNil(t, logger)
	
	// Clean up
	logger.Sync()
}

func TestNewLogger_Testing(t *testing.T) {
	logger, err := NewLogger("testing")
	assert.NoError(t, err)
	assert.NotNil(t, logger)
	
	// Clean up
	logger.Sync()
}

func TestNewLogger_InvalidEnvironment(t *testing.T) {
	logger, err := NewLogger("invalid-env")
	assert.NoError(t, err) // Should not error, just use production config
	assert.NotNil(t, logger)
	
	// Clean up
	logger.Sync()
}

func TestGetLogLevel(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		expected    zapcore.Level
	}{
		{"development", "development", zapcore.DebugLevel},
		{"test", "test", zapcore.DebugLevel},
		{"staging", "staging", zapcore.InfoLevel},
		{"production", "production", zapcore.InfoLevel},
		{"unknown", "unknown", zapcore.InfoLevel},
		{"empty", "", zapcore.InfoLevel},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset viper to avoid LOG_LEVEL env var interference
			viper.Reset()
			level := getLogLevel(tt.environment)
			assert.Equal(t, tt.expected, level)
		})
	}
}

func TestGetLogLevel_WithExplicitLogLevel(t *testing.T) {
	originalEnv := os.Getenv("LOG_LEVEL")
	defer func() {
		if originalEnv != "" {
			os.Setenv("LOG_LEVEL", originalEnv)
		} else {
			os.Unsetenv("LOG_LEVEL")
		}
	}()
	
	tests := []struct {
		logLevel    string
		expected    zapcore.Level
		environment string
	}{
		{"debug", zapcore.DebugLevel, "production"},
		{"info", zapcore.InfoLevel, "development"},
		{"warn", zapcore.WarnLevel, "development"},
		{"warning", zapcore.WarnLevel, "development"},
		{"error", zapcore.ErrorLevel, "development"},
		{"fatal", zapcore.FatalLevel, "development"},
		{"invalid", zapcore.InfoLevel, "production"}, // Should fall back to env default
	}
	
	for _, tt := range tests {
		t.Run(tt.logLevel, func(t *testing.T) {
			viper.Reset()
			viper.Set("LOG_LEVEL", tt.logLevel)
			level := getLogLevel(tt.environment)
			assert.Equal(t, tt.expected, level)
		})
	}
}

func TestConfigStruct_ServerConfig(t *testing.T) {
	server := ServerConfig{
		Port:         "8080",
		ReadTimeout:  30,
		WriteTimeout: 30,
		IdleTimeout:  120,
	}
	
	assert.Equal(t, "8080", server.Port)
	assert.Equal(t, 30, server.ReadTimeout)
	assert.Equal(t, 30, server.WriteTimeout)
	assert.Equal(t, 120, server.IdleTimeout)
}

func TestConfigStruct_DatabaseConfig(t *testing.T) {
	db := DatabaseConfig{
		Host:           "localhost",
		Port:           5432,
		User:           "postgres",
		Password:       "password",
		DBName:         "testdb",
		SSLMode:        "disable",
		MaxConns:       25,
		MaxIdle:        5,
		ConnectTimeout: 10,
		MaxLifetime:    3600,
		MaxIdleTime:    300,
	}
	
	assert.Equal(t, "localhost", db.Host)
	assert.Equal(t, 5432, db.Port)
	assert.Equal(t, "postgres", db.User)
	assert.Equal(t, "password", db.Password)
	assert.Equal(t, "testdb", db.DBName)
	assert.Equal(t, "disable", db.SSLMode)
	assert.Equal(t, 25, db.MaxConns)
	assert.Equal(t, 5, db.MaxIdle)
	assert.Equal(t, 10, db.ConnectTimeout)
	assert.Equal(t, 3600, db.MaxLifetime)
	assert.Equal(t, 300, db.MaxIdleTime)
}

func TestConfigStruct_RedisConfig(t *testing.T) {
	redis := RedisConfig{
		Host:         "redis",
		Port:         6379,
		Password:     "redis-pass",
		DB:           1,
		Prefix:       "booli:",
		DialTimeout:  10,
		ReadTimeout:  10,
		WriteTimeout: 10,
	}
	
	assert.Equal(t, "redis", redis.Host)
	assert.Equal(t, 6379, redis.Port)
	assert.Equal(t, "redis-pass", redis.Password)
	assert.Equal(t, 1, redis.DB)
	assert.Equal(t, "booli:", redis.Prefix)
	assert.Equal(t, 10, redis.DialTimeout)
	assert.Equal(t, 10, redis.ReadTimeout)
	assert.Equal(t, 10, redis.WriteTimeout)
}

func TestConfigStruct_KeycloakConfig(t *testing.T) {
	keycloak := KeycloakConfig{
		URL:           "https://keycloak.example.com",
		AdminUser:     "admin",
		AdminPass:     "admin-pass",
		MasterRealm:   "master",
		MSPRealm:      "msp",
		ClientID:      "booli-admin",
		ClientSecret:  "client-secret",
		CallbackURL:   "https://app.example.com/callback",
		APIAudience:   "booli-admin-api",
		SkipTLSVerify: true,
		CACertPath:    "/path/to/ca.crt",
	}
	
	assert.Equal(t, "https://keycloak.example.com", keycloak.URL)
	assert.Equal(t, "admin", keycloak.AdminUser)
	assert.Equal(t, "admin-pass", keycloak.AdminPass)
	assert.Equal(t, "master", keycloak.MasterRealm)
	assert.Equal(t, "msp", keycloak.MSPRealm)
	assert.Equal(t, "booli-admin", keycloak.ClientID)
	assert.Equal(t, "client-secret", keycloak.ClientSecret)
	assert.Equal(t, "https://app.example.com/callback", keycloak.CallbackURL)
	assert.Equal(t, "booli-admin-api", keycloak.APIAudience)
	assert.True(t, keycloak.SkipTLSVerify)
	assert.Equal(t, "/path/to/ca.crt", keycloak.CACertPath)
}

func TestConfigStruct_CompleteConfig(t *testing.T) {
	config := Config{
		Environment: "production",
		Server: ServerConfig{
			Port: "8080",
		},
		Database: DatabaseConfig{
			Host: "localhost",
			Port: 5432,
		},
		Redis: RedisConfig{
			Host: "redis",
			Port: 6379,
		},
		Keycloak: KeycloakConfig{
			URL:         "https://keycloak.example.com",
			MasterRealm: "master",
		},
	}
	
	assert.Equal(t, "production", config.Environment)
	assert.Equal(t, "8080", config.Server.Port)
	assert.Equal(t, "localhost", config.Database.Host)
	assert.Equal(t, 5432, config.Database.Port)
	assert.Equal(t, "redis", config.Redis.Host)
	assert.Equal(t, 6379, config.Redis.Port)
	assert.Equal(t, "https://keycloak.example.com", config.Keycloak.URL)
	assert.Equal(t, "master", config.Keycloak.MasterRealm)
}

func TestEnvironmentVariableLoading(t *testing.T) {
	cleanEnv()
	defer restoreEnv()
	
	// Set test environment variables
	testEnvs := map[string]string{
		"BOOLI_SERVER_PORT":        "9090",
		"BOOLI_ENVIRONMENT":        "test",
		"BOOLI_DATABASE_HOST":      "testhost",
		"BOOLI_DATABASE_PORT":      "3306",
		"BOOLI_DATABASE_USER":      "testuser",
		"BOOLI_DATABASE_PASSWORD":  "testpass",
		"BOOLI_DATABASE_DBNAME":    "testdb",
		"BOOLI_DATABASE_SSLMODE":   "require",
		"BOOLI_KEYCLOAK_URL":       "http://test-keycloak:8080",
		"BOOLI_REDIS_HOST":         "test-redis",
		"BOOLI_REDIS_PORT":         "6380",
	}
	
	for key, value := range testEnvs {
		os.Setenv(key, value)
	}
	
	cfg, err := LoadConfig("")
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	
	assert.Equal(t, "9090", cfg.Server.Port)
	assert.Equal(t, "test", cfg.Environment)
	assert.Equal(t, "testhost", cfg.Database.Host)
	assert.Equal(t, 3306, cfg.Database.Port)
	assert.Equal(t, "testuser", cfg.Database.User)
	assert.Equal(t, "testpass", cfg.Database.Password)
	assert.Equal(t, "testdb", cfg.Database.DBName)
	assert.Equal(t, "require", cfg.Database.SSLMode)
	assert.Equal(t, "http://test-keycloak:8080", cfg.Keycloak.URL)
	assert.Equal(t, "test-redis", cfg.Redis.Host)
	assert.Equal(t, 6380, cfg.Redis.Port)
}

// Helper functions
func cleanEnv() {
	envVars := []string{
		"BOOLI_SERVER_PORT", "BOOLI_ENVIRONMENT", "BOOLI_DATABASE_HOST",
		"BOOLI_DATABASE_PORT", "BOOLI_DATABASE_USER", "BOOLI_DATABASE_PASSWORD",
		"BOOLI_DATABASE_DBNAME", "BOOLI_DATABASE_SSLMODE", "BOOLI_KEYCLOAK_URL",
		"BOOLI_REDIS_HOST", "BOOLI_REDIS_PORT", "LOG_LEVEL",
	}
	
	for _, envVar := range envVars {
		os.Unsetenv(envVar)
	}
	
	viper.Reset()
}

func restoreEnv() {
	viper.Reset()
}
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Config struct {
	Environment string         `mapstructure:"environment"`
	Server      ServerConfig   `mapstructure:"server"`
	Database    DatabaseConfig `mapstructure:"database"`
	Redis       RedisConfig    `mapstructure:"redis"`
	Keycloak    KeycloakConfig `mapstructure:"keycloak"`
}

type ServerConfig struct {
	Port         string `mapstructure:"port"`
	ReadTimeout  int    `mapstructure:"read_timeout"`
	WriteTimeout int    `mapstructure:"write_timeout"`
	IdleTimeout  int    `mapstructure:"idle_timeout"`
}

type DatabaseConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"dbname"`
	SSLMode  string `mapstructure:"sslmode"`
	MaxConns int    `mapstructure:"max_connections"`
	MaxIdle  int    `mapstructure:"max_idle"`
}

type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
	Prefix   string `mapstructure:"prefix"`
}

type KeycloakConfig struct {
	URL          string `mapstructure:"url"`
	AdminUser    string `mapstructure:"admin_user"`
	AdminPass    string `mapstructure:"admin_password"`
	MasterRealm  string `mapstructure:"master_realm"`
	MSPRealm     string `mapstructure:"msp_realm"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	CallbackURL  string `mapstructure:"callback_url"`
	APIAudience  string `mapstructure:"api_audience"`
}

func Load() (*Config, error) {
	return LoadWithConfigFile("")
}

func LoadWithConfigFile(configFile string) (*Config, error) {
	setDefaults()

	if configFile != "" {
		viper.SetConfigFile(configFile)
		if err := viper.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("error reading config file %s: %w", configFile, err)
		}
	} else {
		viper.SetConfigName("config")
		viper.AddConfigPath(".")
		viper.AddConfigPath("./config")
		viper.AddConfigPath("/etc/booli-admin/")

		formats := []string{"yaml", "toml", "json"}
		var configFound bool
		for _, format := range formats {
			viper.SetConfigType(format)
			if err := viper.ReadInConfig(); err == nil {
				configFound = true
				break
			}
		}
		if !configFound {
			if err := viper.ReadInConfig(); err != nil {
				if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
					return nil, fmt.Errorf("error reading config file: %w", err)
				}
			}
		}
	}

	viper.SetEnvPrefix("BOOLI")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	return &config, nil
}

func setDefaults() {
	viper.SetDefault("environment", "production")
	viper.SetDefault("server.port", "8080")
	viper.SetDefault("server.read_timeout", 30)
	viper.SetDefault("server.write_timeout", 30)
	viper.SetDefault("server.idle_timeout", 120)
	viper.SetDefault("database.host", "")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.user", "")
	viper.SetDefault("database.password", "")
	viper.SetDefault("database.dbname", "")
	viper.SetDefault("database.sslmode", "require")
	viper.SetDefault("database.max_connections", 25)
	viper.SetDefault("database.max_idle", 5)

	viper.SetDefault("redis.host", "")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)

	viper.SetDefault("keycloak.url", "")
	viper.SetDefault("keycloak.admin_user", "")
	viper.SetDefault("keycloak.admin_password", "")
	viper.SetDefault("keycloak.master_realm", "master")
	viper.SetDefault("keycloak.msp_realm", "msp")
	viper.SetDefault("keycloak.client_id", "")
	viper.SetDefault("keycloak.client_secret", "")
	viper.SetDefault("keycloak.callback_url", "")
	viper.SetDefault("keycloak.api_audience", "booli-admin-api")
}

func NewLogger(environment string) (*zap.Logger, error) {
	var config zap.Config

	if environment == "development" {
		config = zap.NewDevelopmentConfig()
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		config = zap.NewProductionConfig()
		if environment == "test" {
			config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		} else {
			config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
		}
	}

	config.OutputPaths = []string{"stdout"}
	config.ErrorOutputPaths = []string{"stderr"}

	logger, err := config.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build logger: %w", err)
	}

	return logger, nil
}

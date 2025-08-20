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
	Host           string `mapstructure:"host"`
	Port           int    `mapstructure:"port"`
	User           string `mapstructure:"user"`
	Password       string `mapstructure:"password"`
	DBName         string `mapstructure:"dbname"`
	SSLMode        string `mapstructure:"sslmode"`
	MaxConns       int    `mapstructure:"max_connections"`
	MaxIdle        int    `mapstructure:"max_idle"`
	ConnectTimeout int    `mapstructure:"connect_timeout"`
	MaxLifetime    int    `mapstructure:"max_lifetime"`
	MaxIdleTime    int    `mapstructure:"max_idle_time"`
}

type RedisConfig struct {
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port"`
	Password     string `mapstructure:"password"`
	DB           int    `mapstructure:"db"`
	Prefix       string `mapstructure:"prefix"`
	DialTimeout  int    `mapstructure:"dial_timeout"`
	ReadTimeout  int    `mapstructure:"read_timeout"`
	WriteTimeout int    `mapstructure:"write_timeout"`
}

type KeycloakConfig struct {
	URL           string `mapstructure:"url"`
	AdminUser     string `mapstructure:"admin_user"`
	AdminPass     string `mapstructure:"admin_password"`
	MasterRealm   string `mapstructure:"master_realm"`
	MSPRealm      string `mapstructure:"msp_realm"`
	ClientID      string `mapstructure:"client_id"`
	ClientSecret  string `mapstructure:"client_secret"`
	CallbackURL   string `mapstructure:"callback_url"`
	APIAudience   string `mapstructure:"api_audience"`
	SkipTLSVerify bool   `mapstructure:"skip_tls_verify"`
	CACertPath    string `mapstructure:"ca_cert_path"`
}

func Load() (*Config, error) {
	return LoadWithConfigFile("")
}

func LoadConfig(configFile string) (*Config, error) {
	return LoadWithConfigFile(configFile)
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

	if config.Keycloak.URL == "" {
		if baseURL := viper.GetString("KEYCLOAK_BASE_URL"); baseURL != "" {
			config.Keycloak.URL = baseURL
		}
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
	viper.SetDefault("database.connect_timeout", 10)
	viper.SetDefault("database.max_lifetime", 3600)
	viper.SetDefault("database.max_idle_time", 300)

	viper.SetDefault("redis.host", "")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.dial_timeout", 10)
	viper.SetDefault("redis.read_timeout", 10)
	viper.SetDefault("redis.write_timeout", 10)

	viper.SetDefault("keycloak.url", "http://localhost:8083")
	viper.SetDefault("keycloak.admin_user", "admin")
	viper.SetDefault("keycloak.admin_password", "admin")
	viper.SetDefault("keycloak.master_realm", "master")
	viper.SetDefault("keycloak.msp_realm", "master")
	viper.SetDefault("keycloak.client_id", "msp-client")
	viper.SetDefault("keycloak.client_secret", "test-secret")
	viper.SetDefault("keycloak.callback_url", "")
	viper.SetDefault("keycloak.api_audience", "booli-admin-api")
	viper.SetDefault("keycloak.skip_tls_verify", false)
	viper.SetDefault("keycloak.ca_cert_path", "")
}

func NewLogger(environment string) (*zap.Logger, error) {
	var config zap.Config

	logLevel := getLogLevel(environment)

	if environment == "development" {
		config = zap.NewDevelopmentConfig()
		config.Level = zap.NewAtomicLevelAt(logLevel)
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		config.Development = true
		config.DisableStacktrace = false
	} else {
		config = zap.NewProductionConfig()
		config.Level = zap.NewAtomicLevelAt(logLevel)
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		config.EncoderConfig.MessageKey = "message"
		config.EncoderConfig.LevelKey = "level"
		config.EncoderConfig.CallerKey = "caller"
		config.EncoderConfig.StacktraceKey = "stacktrace"
		config.Development = false

		// Disable stack traces for production to reduce log verbosity
		config.DisableStacktrace = true
	}

	config.OutputPaths = []string{"stdout"}
	config.ErrorOutputPaths = []string{"stderr"}

	logger, err := config.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build logger: %w", err)
	}

	return logger, nil
}

func getLogLevel(environment string) zapcore.Level {
	if levelStr := viper.GetString("LOG_LEVEL"); levelStr != "" {
		switch strings.ToLower(levelStr) {
		case "debug":
			return zapcore.DebugLevel
		case "info":
			return zapcore.InfoLevel
		case "warn", "warning":
			return zapcore.WarnLevel
		case "error":
			return zapcore.ErrorLevel
		case "fatal":
			return zapcore.FatalLevel
		}
	}

	switch environment {
	case "development":
		return zapcore.DebugLevel
	case "test":
		return zapcore.DebugLevel
	case "staging":
		return zapcore.InfoLevel
	case "production":
		return zapcore.WarnLevel
	default:
		return zapcore.InfoLevel
	}
}

package cli

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/booli/booli-admin-api/internal/auth"
	"github.com/booli/booli-admin-api/internal/config"
	"github.com/booli/booli-admin-api/internal/constants"
	"github.com/booli/booli-admin-api/internal/database"
	"github.com/booli/booli-admin-api/internal/initialization"
	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/booli/booli-admin-api/internal/models"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

type CLI struct {
	logger *zap.Logger
}

func New(logger *zap.Logger) *CLI {
	return &CLI{logger: logger}
}

func ShowUsage() {
	fmt.Println("Booli Admin API - Multi-tenant admin portal with Keycloak authentication")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  booli-admin-api [flags]")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -init                 Initialize complete system (databases + Keycloak) then exit")
	fmt.Println("  -init-keycloak        Initialize Keycloak realms and clients then exit")
	fmt.Println("  -init-database        Initialize databases then exit")
	fmt.Println("  -validate-only        Only validate configuration, don't initialize")
	fmt.Println("  -force                Force initialization even if already configured")
	fmt.Println("  -config string        Path to configuration file (YAML, TOML, or JSON)")
	fmt.Println("  -help                 Show usage information")
	fmt.Println("  -version              Show version information")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  All configuration can be set via environment variables with BOOLI_ prefix")
	fmt.Println("  Example: BOOLI_DATABASE_HOST=localhost")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  ./booli-admin-api                           # Start the server")
	fmt.Println("  ./booli-admin-api -init                     # Initialize everything")
	fmt.Println("  ./booli-admin-api -init-keycloak           # Initialize only Keycloak")
	fmt.Println("  ./booli-admin-api -validate-only           # Validate configuration")
	fmt.Println("  ./booli-admin-api -config config.yaml      # Use specific config file")
}

func ShowVersion(version, commit, buildTime string) {
	fmt.Printf("Booli Admin API\n")
	fmt.Printf("Version: %s\n", version)
	fmt.Printf("Commit:  %s\n", commit)
	fmt.Printf("Built:   %s\n", buildTime)
}

func (cli *CLI) ShowVersionInfo(version, commit, buildTime string) {
	cli.logger.Info("Booli Admin API",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("build_time", buildTime))
}

func (cli *CLI) ShowUsage() {
	usage := `Booli Admin API

Usage:
  booli-admin-api [flags]

Flags:
  -init              Initialize complete system (databases + Keycloak) then exit
  -init-keycloak     Initialize Keycloak realms and clients then exit
  -init-database     Initialize databases then exit
  -validate-only     Only validate configuration, don't initialize
  -force             Force initialization even if already configured
  -config            Path to configuration file (YAML, TOML, or JSON)
  -version           Show version information
  -help              Show this help message

Examples:
  # Normal server startup
  booli-admin-api

  # First-time setup (production-ready)
  booli-admin-api -init -force

  # Initialize databases only
  booli-admin-api -init-database

  # Initialize Keycloak configuration only
  booli-admin-api -init-keycloak

  # Force re-initialization
  booli-admin-api -init-keycloak -force

  # Validate configuration only
  booli-admin-api -validate-only

  # Use custom configuration file
  booli-admin-api -config /path/to/config.yaml

Environment Variables:
  BOOLI_ENVIRONMENT              Application environment
                                development: Debug logs, easy init
                                production:  Secure defaults (default)
                                test:        For automated testing only
  BOOLI_KEYCLOAK_URL             Keycloak base URL
  BOOLI_KEYCLOAK_ADMIN_USER      Keycloak admin username
  BOOLI_KEYCLOAK_ADMIN_PASSWORD  Keycloak admin password
  BOOLI_KEYCLOAK_CALLBACK_URL    OAuth callback URL

Security & Safety:
  - Defaults to production mode (secure-by-default)
  - Easy initialization only in development environment
  - Production/test initialization requires -force flag
  - Validates admin credentials before any changes
  - Validates existing configuration before changes`

	cli.logger.Info(usage)
}

func (cli *CLI) CheckDatabasesExist(ctx context.Context, cfg *config.Config) bool {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s sslmode=%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.User, cfg.Database.Password, cfg.Database.SSLMode)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		cli.logger.Debug("Failed to connect to database for existence check", zap.Error(err))
		return false
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		cli.logger.Debug("Failed to ping database for existence check", zap.Error(err))
		return false
	}

	var booliAdminExists bool
	row := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = 'booli_admin')")
	if err := row.Scan(&booliAdminExists); err != nil {
		cli.logger.Debug("Failed to check booli_admin database existence", zap.Error(err))
		return false
	}

	return booliAdminExists
}

func (cli *CLI) RunValidation(initializer *initialization.KeycloakInitializer, initConfig *initialization.InitializationConfig) error {
	cli.logger.Info("Validating Keycloak configuration...")

	if initConfig == nil {
		cli.logger.Info("No initialization configuration required")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), constants.ValidationTimeout)
	defer cancel()

	if err := initializer.ValidateConfiguration(ctx, initConfig); err != nil {
		cli.logger.Error("Configuration validation failed", zap.Error(err))
		return err
	}

	cli.logger.Info("Configuration validation passed",
		zap.Int("realms", len(initConfig.Realms)),
		zap.Int("clients", len(initConfig.Clients)),
		zap.Int("oidc_providers", len(initConfig.OIDCProviders)))

	return nil
}

func (cli *CLI) RunInitialization(initializer *initialization.KeycloakInitializer, initConfig *initialization.InitializationConfig, cfg *config.Config, force bool) error {
	cli.logger.Info("Initializing Keycloak configuration...")

	if initConfig == nil {
		cli.logger.Error("No initialization configuration found",
			zap.String("suggestion", "Set BOOLI_ENVIRONMENT=test or configure initialization via environment variables"))
		return fmt.Errorf("no initialization configuration found")
	}

	if cfg.Keycloak.AdminUser == "" || cfg.Keycloak.AdminPass == "" {
		cli.logger.Error("Missing Keycloak admin credentials",
			zap.String("required", "BOOLI_KEYCLOAK_ADMIN_USER and BOOLI_KEYCLOAK_ADMIN_PASSWORD"))
		return fmt.Errorf("missing Keycloak admin credentials")
	}

	ctx, cancel := context.WithTimeout(context.Background(), constants.InitTimeout)
	defer cancel()

	cli.logger.Info("Starting initialization",
		zap.String("environment", cfg.Environment),
		zap.String("keycloak_url", cfg.Keycloak.URL),
		zap.Int("realms", len(initConfig.Realms)),
		zap.Int("clients", len(initConfig.Clients)),
		zap.Int("oidc_providers", len(initConfig.OIDCProviders)))

	cli.logger.Info("Checking existing configuration...")
	if err := initializer.ValidateConfiguration(ctx, initConfig); err == nil && !force {
		cli.logger.Info("Configuration already exists and is valid",
			zap.String("suggestion", "Use -force to reinitialize"))
		return nil
	}

	cli.logger.Info("Running initialization...")
	if err := initializer.Initialize(ctx, initConfig); err != nil {
		cli.logger.Error("Initialization failed", zap.Error(err))
		return err
	}

	cli.logger.Info("Validating initialization result...")
	if err := initializer.ValidateConfiguration(ctx, initConfig); err != nil {
		cli.logger.Error("Initialization completed but validation failed", zap.Error(err))
		return err
	}

	cli.logger.Info("Keycloak initialization completed successfully")
	return nil
}

func (cli *CLI) RunDatabaseInitialization(cfg *config.Config, force bool) error {
	cli.logger.Info("Initializing databases...")

	if cfg.Database.Host == "" || cfg.Database.User == "" || cfg.Database.Password == "" {
		cli.logger.Error("Missing database configuration",
			zap.String("required", "BOOLI_DATABASE_HOST, BOOLI_DATABASE_USER, BOOLI_DATABASE_PASSWORD"))
		return fmt.Errorf("missing database configuration")
	}

	ctx, cancel := context.WithTimeout(context.Background(), constants.ValidationTimeout)
	defer cancel()

	databasesExist := cli.CheckDatabasesExist(ctx, cfg)
	if !force && databasesExist {
		cli.logger.Error("Database initialization requires -force flag when databases already exist",
			zap.String("environment", cfg.Environment),
			zap.String("suggestion", "Use: booli-admin-api -init-database -force to recreate existing databases"))
		return fmt.Errorf("database initialization requires -force flag when databases already exist")
	}

	cli.logger.Info("Database initialization details",
		zap.String("environment", cfg.Environment),
		zap.String("host", fmt.Sprintf("%s:%d", cfg.Database.Host, cfg.Database.Port)),
		zap.Strings("databases", []string{"booli_admin", "keycloak"}))

	if err := cli.createDatabases(ctx, cfg, force); err != nil {
		cli.logger.Error("Database initialization failed", zap.Error(err))
		return err
	}

	cli.logger.Info("Database initialization completed successfully")
	return nil
}

func (cli *CLI) createDatabases(ctx context.Context, cfg *config.Config, force bool) error {
	adminDSN := fmt.Sprintf("host=%s port=%d user=%s password=%s sslmode=%s",
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.SSLMode)

	db, err := sql.Open("postgres", adminDSN)
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	databases := []string{"booli_admin"}

	for _, dbName := range databases {
		cli.logger.Info("Creating database", zap.String("database", dbName))

		var exists bool
		query := "SELECT EXISTS(SELECT datname FROM pg_catalog.pg_database WHERE datname = $1)"
		if err := db.QueryRowContext(ctx, query, dbName).Scan(&exists); err != nil {
			return fmt.Errorf("failed to check if database %s exists: %w", dbName, err)
		}

		if exists && !force {
			cli.logger.Info("Database already exists",
				zap.String("database", dbName),
				zap.String("suggestion", "use -force to recreate"))
			continue
		}

		if exists && force {
			cli.logger.Info("Dropping existing database", zap.String("database", dbName))
			if _, err := db.ExecContext(ctx, fmt.Sprintf("DROP DATABASE %s", dbName)); err != nil {
				return fmt.Errorf("failed to drop database %s: %w", dbName, err)
			}
		}

		if _, err := db.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %s", dbName)); err != nil {
			return fmt.Errorf("failed to create database %s: %w", dbName, err)
		}

		cli.logger.Info("Database created successfully", zap.String("database", dbName))
	}

	return nil
}

func (cli *CLI) migrateDatabaseTables(cfg *config.Config) error {
	db, err := database.Connect(cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	defer sqlDB.Close()

	if err := database.CreateExtensions(db); err != nil {
		return fmt.Errorf("failed to create extensions: %w", err)
	}

	if err := db.AutoMigrate(
		&models.Tenant{},
		&models.AuditLog{},
		&models.TenantEnvironment{},
		&models.NetworkRange{},
		&models.PublicIP{},
		&models.EgressIP{},
		&models.Domain{},
		&models.NamingConvention{},
		&models.InfrastructureIP{},
		&models.TenantAccessGrant{},
	); err != nil {
		return fmt.Errorf("failed to auto-migrate models: %w", err)
	}

	if err := database.CreateIndexes(db); err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	if err := database.SetupRowLevelSecurity(db); err != nil {
		return fmt.Errorf("failed to setup row level security: %w", err)
	}

	return nil
}

func (cli *CLI) RunFullSystemInitialization(cfg *config.Config, force bool) error {
	cli.logger.Info("Initializing complete system (databases + Keycloak)...")

	ctx, cancel := context.WithTimeout(context.Background(), constants.FullInitTimeout)
	defer cancel()

	var databasesExist bool
	if cfg.Database.Host != "" && cfg.Database.User != "" && cfg.Database.Password != "" {
		databasesExist = cli.CheckDatabasesExist(ctx, cfg)
	}

	var keycloakConfigExists bool
	if cfg.Keycloak.AdminUser != "" && cfg.Keycloak.AdminPass != "" {
		keycloakAdmin := keycloak.NewAdminClient(
			cfg.Keycloak.URL,
			cfg.Keycloak.MasterRealm,
			cfg.Keycloak.ClientID,
			cfg.Keycloak.ClientSecret,
			cfg.Keycloak.AdminUser,
			cfg.Keycloak.AdminPass,
			cfg.Keycloak.SkipTLSVerify,
			cfg.Keycloak.CACertPath,
			cli.logger,
		)
		oidcService := auth.NewOIDCService(cli.logger)
		initializer := initialization.NewKeycloakInitializer(keycloakAdmin, oidcService, cfg, cli.logger)

		var initConfig *initialization.InitializationConfig
		if cfg.Environment == "test" || cfg.Environment == "development" {
			callbackURL := cfg.Keycloak.CallbackURL
			if callbackURL == "" {
				callbackURL = "http://localhost:" + cfg.Server.Port + constants.PathAuthCallback
			}
			initConfig = initialization.GetDefaultTestConfig(cfg.Keycloak.URL, callbackURL, cfg.Keycloak.ClientSecret)
		} else {
			if envConfig, err := initialization.ParseConfigFromEnv(); err == nil && envConfig != nil {
				initConfig = envConfig
			}
		}

		if initConfig != nil {
			if err := initializer.ValidateConfiguration(ctx, initConfig); err == nil {
				keycloakConfigExists = true
			}
		}
	}

	if !force && (databasesExist || keycloakConfigExists) {
		cli.logger.Error("Initialization requires -force flag when databases or configuration already exist",
			zap.String("environment", cfg.Environment),
			zap.Bool("databases_exist", databasesExist),
			zap.Bool("keycloak_config_exists", keycloakConfigExists),
			zap.String("suggestion", "Use: booli-admin-api -init -force to recreate existing configuration"))
		return fmt.Errorf("initialization requires -force flag when configuration already exists")
	}

	cli.logger.Info("Full system initialization details",
		zap.String("environment", cfg.Environment),
		zap.String("database_host", fmt.Sprintf("%s:%d", cfg.Database.Host, cfg.Database.Port)),
		zap.String("keycloak_url", cfg.Keycloak.URL))

	cli.logger.Info("Step 1/3: Initializing databases...")
	if err := cli.createDatabases(ctx, cfg, force); err != nil {
		cli.logger.Error("Database initialization failed", zap.Error(err))
		return err
	}
	cli.logger.Info("Databases initialized successfully")

	cli.logger.Info("Step 2/3: Creating database tables...")
	if err := cli.migrateDatabaseTables(cfg); err != nil {
		cli.logger.Error("Database migration failed", zap.Error(err))
		return err
	}
	cli.logger.Info("Database tables created successfully")

	cli.logger.Info("Step 3/3: Initializing Keycloak...")
	keycloakAdmin := keycloak.NewAdminClient(
		cfg.Keycloak.URL,
		cfg.Keycloak.MasterRealm,
		cfg.Keycloak.ClientID,
		cfg.Keycloak.ClientSecret,
		cfg.Keycloak.AdminUser,
		cfg.Keycloak.AdminPass,
		cfg.Keycloak.SkipTLSVerify,
		cfg.Keycloak.CACertPath,
		cli.logger,
	)

	oidcService := auth.NewOIDCService(cli.logger)
	initializer := initialization.NewKeycloakInitializer(keycloakAdmin, oidcService, cfg, cli.logger)

	var initConfig *initialization.InitializationConfig
	if cfg.Environment == "test" || cfg.Environment == "development" {
		callbackURL := cfg.Keycloak.CallbackURL
		if callbackURL == "" {
			callbackURL = "http://localhost:" + cfg.Server.Port + constants.PathAuthCallback
		}
		initConfig = initialization.GetDefaultTestConfig(cfg.Keycloak.URL, callbackURL, cfg.Keycloak.ClientSecret)
	} else {
		if envConfig, err := initialization.ParseConfigFromEnv(); err == nil && envConfig != nil {
			initConfig = envConfig
		}
	}

	if initConfig == nil {
		cli.logger.Error("No Keycloak initialization configuration found",
			zap.String("suggestion", "For production, configure via environment variables"))
		return fmt.Errorf("no Keycloak initialization configuration found")
	}

	if cfg.Keycloak.AdminUser == "" || cfg.Keycloak.AdminPass == "" {
		cli.logger.Error("Missing Keycloak admin credentials",
			zap.String("required", "BOOLI_KEYCLOAK_ADMIN_USER and BOOLI_KEYCLOAK_ADMIN_PASSWORD"))
		return fmt.Errorf("missing Keycloak admin credentials")
	}

	cli.logger.Info("Validating Keycloak configuration...")
	if err := initializer.ValidateConfiguration(ctx, initConfig); err == nil && !force {
		cli.logger.Info("Keycloak configuration already exists and is valid",
			zap.String("suggestion", "Use -force to reinitialize"))
	} else {
		cli.logger.Info("Applying Keycloak configuration...")
		if err := initializer.Initialize(ctx, initConfig); err != nil {
			cli.logger.Error("Keycloak initialization failed", zap.Error(err))
			return err
		}

		if err := initializer.ValidateConfiguration(ctx, initConfig); err != nil {
			cli.logger.Error("Keycloak initialization completed but validation failed", zap.Error(err))
			return err
		}
		cli.logger.Info("Keycloak initialized successfully")
	}

	cli.logger.Info("Full system initialization completed successfully",
		zap.String("api_url", "http://localhost:8081"),
		zap.String("swagger_url", "http://localhost:8081"+constants.PathSwagger),
		zap.String("next_step", "Configure your first tenant via the admin endpoints"))

	return nil
}

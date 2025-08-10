// @title Booli Admin API
// @version 1.0
// @description Multi-tenant admin portal with Keycloak authentication and MSP support
// @contact.name Booli Admin API Support
// @contact.email support@booli.ai
// @license.name CC BY-NC-ND 4.0
// @license.url https://creativecommons.org/licenses/by-nc-nd/4.0/
// @host localhost:8081
// @BasePath /api/v1
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.
package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/booli/booli-admin-api/internal/app"
	"github.com/booli/booli-admin-api/internal/auth"
	"github.com/booli/booli-admin-api/internal/cli"
	"github.com/booli/booli-admin-api/internal/config"
	"github.com/booli/booli-admin-api/internal/constants"
	"github.com/booli/booli-admin-api/internal/initialization"
	"github.com/booli/booli-admin-api/internal/keycloak"
	"go.uber.org/zap"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	var (
		initFlag     = flag.Bool("init", false, "Initialize complete system (databases + Keycloak) then exit")
		initKeycloak = flag.Bool("init-keycloak", false, "Initialize Keycloak realms and clients then exit")
		initDatabase = flag.Bool("init-database", false, "Initialize databases then exit")
		validateOnly = flag.Bool("validate-only", false, "Only validate configuration, don't initialize")
		force        = flag.Bool("force", false, "Force initialization even if already configured")
		configFile   = flag.String("config", "", "Path to configuration file (YAML, TOML, or JSON)")
		showHelp     = flag.Bool("help", false, "Show usage information")
		showVersion  = flag.Bool("version", false, "Show version information")
	)
	flag.Parse()

	// Handle help and version without any logging
	if *showHelp {
		cli.ShowUsageQuiet()
		return
	}

	if *showVersion {
		cli.ShowVersionInfoQuiet(version, commit, date)
		return
	}

	// Now initialize loggers only for actual operations
	basicLogger, _ := zap.NewProduction()
	if basicLogger == nil {
		basicLogger, _ = zap.NewDevelopment()
	}
	defer basicLogger.Sync()

	basicLogger.Info("Booli Admin API starting",
		zap.String("service", "booli-admin-api"),
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("build_date", date))

	cfg, err := config.LoadWithConfigFile(*configFile)
	if err != nil {
		basicLogger.Fatal("Failed to load configuration",
			zap.Error(err),
			zap.String("config_file", *configFile),
			zap.String("help", "Ensure configuration file exists or set environment variables with BOOLI_ prefix"))
	}

	logger, err := config.NewLogger(cfg.Environment)
	if err != nil {
		basicLogger.Fatal("Failed to initialize logger", zap.Error(err))
	}
	defer logger.Sync()

	logger.Info("Configuration loaded successfully",
		zap.String("environment", cfg.Environment),
		zap.String("server_port", cfg.Server.Port),
		zap.String("database_host", cfg.Database.Host))

	cli := cli.New(logger)

	if *initFlag {
		if err := cli.RunFullSystemInitialization(cfg, *force); err != nil {
			logger.Error("Full system initialization failed", zap.Error(err))
			os.Exit(1)
		}
		return
	}

	if *initDatabase {
		if err := cli.RunDatabaseInitialization(cfg, *force); err != nil {
			logger.Error("Database initialization failed", zap.Error(err))
			os.Exit(1)
		}
		return
	}

	if *initKeycloak || *validateOnly {
		keycloakAdmin := keycloak.NewAdminClient(
			cfg.Keycloak.URL,
			cfg.Keycloak.MasterRealm,
			cfg.Keycloak.ClientID,
			cfg.Keycloak.ClientSecret,
			cfg.Keycloak.AdminUser,
			cfg.Keycloak.AdminPass,
			cfg.Keycloak.SkipTLSVerify,
			cfg.Keycloak.CACertPath,
			logger,
		)

		oidcService := auth.NewOIDCService(logger)
		initializer := initialization.NewKeycloakInitializer(keycloakAdmin, oidcService, cfg, logger)

		var initConfig *initialization.InitializationConfig
		envConfig, err := initialization.ParseConfigFromEnv()
		if err == nil && envConfig != nil {
			initConfig = envConfig
		}

		if *validateOnly {
			if err := cli.RunValidation(initializer, initConfig); err != nil {
				logger.Error("Validation failed", zap.Error(err))
				os.Exit(1)
			}
			return
		}

		if err := cli.RunInitialization(initializer, initConfig, cfg, *force); err != nil {
			logger.Error("Keycloak initialization failed", zap.Error(err))
			os.Exit(1)
		}
		return
	}

	app := app.New(cfg, logger, version)
	if err := app.Initialize(); err != nil {
		logger.Error("Failed to initialize application", zap.Error(err))
		os.Exit(1)
	}

	go func() {
		if err := app.Start(); err != nil && err != http.ErrServerClosed {
			logger.Error("Failed to start server", zap.Error(err))
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), constants.ShutdownTimeout)
	defer cancel()

	if err := app.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", zap.Error(err))
		os.Exit(1)
	}

	logger.Info("Booli Admin API stopped",
		zap.String("service", "booli-admin-api"))
}

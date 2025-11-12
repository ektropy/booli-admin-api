package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/booli/booli-admin-api/internal/auth"
	"github.com/booli/booli-admin-api/internal/config"
	"github.com/booli/booli-admin-api/internal/constants"
	"github.com/booli/booli-admin-api/internal/database"
	"github.com/booli/booli-admin-api/internal/handlers"
	"github.com/booli/booli-admin-api/internal/initialization"
	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/booli/booli-admin-api/internal/middleware"
	"github.com/booli/booli-admin-api/internal/routing"
	"github.com/booli/booli-admin-api/internal/services"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.uber.org/zap"
)

type BuildInfo struct {
	Version   string
	Commit    string
	BuildDate string
}

type Application struct {
	config        *config.Config
	logger        *zap.Logger
	server        *http.Server
	keycloakAdmin *keycloak.AdminClient
	buildInfo     BuildInfo
}

func New(cfg *config.Config, logger *zap.Logger, buildInfo BuildInfo) *Application {
	return &Application{
		config:    cfg,
		logger:    logger,
		buildInfo: buildInfo,
	}
}

func (app *Application) Initialize() error {
	app.logger.Info("Initializing database connection",
		zap.String("host", app.config.Database.Host),
		zap.Int("port", app.config.Database.Port),
		zap.String("database", app.config.Database.DBName))

	db, err := database.ConnectWithEnv(app.config.Database, app.config.Environment)
	if err != nil {
		app.logger.Error("Failed to connect to database",
			zap.Error(err),
			zap.String("host", app.config.Database.Host),
			zap.Int("port", app.config.Database.Port),
			zap.String("database", app.config.Database.DBName))
		return fmt.Errorf("database connection failed: %w", err)
	}

	app.logger.Info("Database connected successfully")

	if err := database.Initialize(db); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}

	app.logger.Info("Database initialized successfully")

	app.logger.Info("Initializing Redis connection",
		zap.String("host", app.config.Redis.Host),
		zap.Int("port", app.config.Redis.Port))

	redis, err := database.ConnectRedis(app.config.Redis)
	if err != nil {
		app.logger.Error("Failed to connect to Redis",
			zap.Error(err),
			zap.String("host", app.config.Redis.Host),
			zap.Int("port", app.config.Redis.Port))
		return fmt.Errorf("redis connection failed: %w", err)
	}

	app.logger.Info("Redis connected successfully")

	if app.config.Keycloak.URL == "" {
		app.logger.Error("Keycloak URL is not configured - application cannot start",
			zap.String("required_env_var", "BOOLI_KEYCLOAK_URL"))
		return fmt.Errorf("keycloak URL is required")
	}

	keycloakAdmin := keycloak.NewAdminClient(
		app.config.Keycloak.URL,
		app.config.Keycloak.MasterRealm,
		"admin-cli",
		"",
		app.config.Keycloak.AdminUser,
		app.config.Keycloak.AdminPass,
		app.config.Keycloak.SkipTLSVerify,
		app.config.Keycloak.CACertPath,
		app.logger,
	)
	app.keycloakAdmin = keycloakAdmin

	oidcService := auth.NewOIDCService(app.logger)

	initializer := initialization.NewKeycloakInitializer(keycloakAdmin, oidcService, app.config, app.logger)

	envConfig, err := initialization.ParseConfigFromEnv()
	if err == nil && envConfig != nil {
		shouldAutoInit := app.config.Environment == "development" || app.config.Environment == "test"
		if !shouldAutoInit {
			if os.Getenv("KEYCLOAK_AUTO_INIT") == "true" {
				shouldAutoInit = true
				app.logger.Warn("Keycloak auto-initialization enabled in production via KEYCLOAK_AUTO_INIT flag")
			}
		}

		if shouldAutoInit {
			app.logger.Info("Using environment-based initialization config",
				zap.String("environment", app.config.Environment),
				zap.Int("realms", len(envConfig.Realms)),
				zap.Int("clients", len(envConfig.Clients)),
				zap.Int("roles", len(envConfig.Roles)),
				zap.Int("users", len(envConfig.Users)))

			if err := initializer.Initialize(context.Background(), envConfig); err != nil {
				app.logger.Error("Keycloak initialization failed", zap.Error(err))
				return fmt.Errorf("keycloak initialization failed: %w", err)
			}

			if err := initialization.CreateDefaultMSP(context.Background(), db, app.logger); err != nil {
				app.logger.Error("Failed to create default MSP", zap.Error(err))
			}
		} else {
			app.logger.Info("Skipping automatic Keycloak initialization in production",
				zap.String("environment", app.config.Environment),
				zap.String("hint", "Set KEYCLOAK_AUTO_INIT=true to enable"))
		}
	}

	callbackURL := app.config.Keycloak.CallbackURL
	if callbackURL == "" {
		callbackURL = "http://localhost:" + app.config.Server.Port + constants.PathAuthCallback
	}

	mspProvider := auth.CreateKeycloakProvider(
		"keycloak",
		app.config.Keycloak.URL,
		app.config.Keycloak.MSPRealm,
		app.config.Keycloak.ClientID,
		app.config.Keycloak.ClientSecret,
		callbackURL,
		app.config.Keycloak.APIAudience,
		app.config.Keycloak.SkipTLSVerify,
		app.config.Keycloak.CACertPath,
	)

	if err := oidcService.AddProvider(context.Background(), mspProvider); err != nil {
		app.logger.Error("Failed to add MSP realm OIDC provider", zap.Error(err))
		return fmt.Errorf("MSP realm OIDC provider configuration failed: %w", err)
	}

	serviceContainer := services.NewContainer(db, redis, keycloakAdmin, app.logger, app.config)

	router := app.setupRouter(serviceContainer, oidcService, initializer)

	app.server = &http.Server{
		Addr:         ":" + app.config.Server.Port,
		Handler:      router,
		ReadTimeout:  time.Duration(app.config.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(app.config.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(app.config.Server.IdleTimeout) * time.Second,
	}

	app.logger.Info("Application initialization completed successfully",
		zap.String("server_address", app.server.Addr),
		zap.Int("routes_configured", len(router.Routes())))

	return nil
}

func (app *Application) setupRouter(serviceContainer *services.Container, oidcService *auth.OIDCService, initializer *initialization.KeycloakInitializer) *gin.Engine {
	if app.config.Environment == "development" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	var loggingConfig middleware.RequestLoggingConfig
	if app.config.Environment == "development" {
		loggingConfig = middleware.DevelopmentRequestLoggingConfig()
	} else {
		loggingConfig = middleware.DefaultRequestLoggingConfig()
	}

	router.Use(middleware.RequestID())
	router.Use(middleware.EnhancedRequestLogger(app.logger, loggingConfig))
	router.Use(middleware.Recovery(app.logger))
	router.Use(middleware.CORS())
	router.Use(middleware.SecurityHeaders())

	buildInfo := handlers.BuildInfo{
		Version:   app.buildInfo.Version,
		Commit:    app.buildInfo.Commit,
		BuildDate: app.buildInfo.BuildDate,
	}
	handlerContainer := handlers.NewContainer(serviceContainer, oidcService, app.logger, app.config, buildInfo)
	handlerContainer.Health.SetInitializer(initializer)

	app.setupRoutes(router, handlerContainer, oidcService)

	return router
}

func (app *Application) setupRoutes(router *gin.Engine, handlers *handlers.Container, oidcService *auth.OIDCService) {
	router.GET("/health", handlers.Health.Check)
	router.GET("/health/keycloak", handlers.Health.ValidateKeycloak)
	router.GET("/version", handlers.Health.GetVersionInfo)
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	rbacMiddleware := middleware.NewRBACMiddleware(app.keycloakAdmin, app.logger)
	apiRouter := routing.NewAPIRouter(rbacMiddleware, oidcService, app.logger)
	apiRouter.SetupAPIRoutes(router, handlers)

	app.logger.Info("Routes configured with resource-based API structure",
		zap.String("api_version", constants.APIVersion))
}

func (app *Application) Start() error {
	app.logger.Info("Server ready",
		zap.String("port", app.config.Server.Port),
		zap.String("api_version", constants.APIVersion),
		zap.String("environment", app.config.Environment))

	if err := app.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		app.logger.Error("Server failed to start", zap.Error(err))
		return err
	}
	return nil
}

func (app *Application) Shutdown(ctx context.Context) error {
	app.logger.Info("HTTP server shutting down gracefully",
		zap.String("service", "booli-admin-api"))
	err := app.server.Shutdown(ctx)
	if err != nil {
		app.logger.Error("Error during server shutdown", zap.Error(err))
	} else {
		app.logger.Info("HTTP server shutdown completed successfully")
	}
	return err
}

package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/booli/booli-admin-api/internal/auth"
	"github.com/booli/booli-admin-api/internal/config"
	"github.com/booli/booli-admin-api/internal/constants"
	"github.com/booli/booli-admin-api/internal/database"
	"github.com/booli/booli-admin-api/internal/handlers"
	"github.com/booli/booli-admin-api/internal/initialization"
	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/booli/booli-admin-api/internal/middleware"
	"github.com/booli/booli-admin-api/internal/services"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.uber.org/zap"
)

type Application struct {
	config  *config.Config
	logger  *zap.Logger
	server  *http.Server
	version string
}

func New(cfg *config.Config, logger *zap.Logger, version string) *Application {
	return &Application{
		config:  cfg,
		logger:  logger,
		version: version,
	}
}

func (app *Application) Initialize() error {
	app.logger.Info("Initializing database connection",
		zap.String("host", app.config.Database.Host),
		zap.Int("port", app.config.Database.Port),
		zap.String("database", app.config.Database.DBName))
	
	db, err := database.Connect(app.config.Database)
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

	keycloakAdmin := keycloak.NewAdminClient(
		app.config.Keycloak.URL,
		app.config.Keycloak.MasterRealm,
		app.config.Keycloak.ClientID,
		app.config.Keycloak.ClientSecret,
		app.config.Keycloak.AdminUser,
		app.config.Keycloak.AdminPass,
		app.config.Keycloak.SkipTLSVerify,
		app.config.Keycloak.CACertPath,
		app.logger,
	)

	oidcService := auth.NewOIDCService(app.logger)

	initializer := initialization.NewKeycloakInitializer(keycloakAdmin, oidcService, app.config, app.logger)

	envConfig, err := initialization.ParseConfigFromEnv()
	if err == nil && envConfig != nil {
		app.logger.Info("Using environment-based initialization config",
			zap.Int("realms", len(envConfig.Realms)),
			zap.Int("clients", len(envConfig.Clients)),
			zap.Int("roles", len(envConfig.Roles)),
			zap.Int("users", len(envConfig.Users)))

		if err := initializer.Initialize(context.Background(), envConfig); err != nil {
			app.logger.Error("Keycloak initialization failed", zap.Error(err))
			return fmt.Errorf("keycloak initialization failed: %w", err)
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

	router.Use(middleware.Logger(app.logger))
	router.Use(middleware.Recovery(app.logger))
	router.Use(middleware.CORS())
	router.Use(middleware.SecurityHeaders())

	handlerContainer := handlers.NewContainer(serviceContainer, oidcService, app.logger, app.config, app.version)
	handlerContainer.Health.SetInitializer(initializer)

	app.setupRoutes(router, handlerContainer, oidcService)

	return router
}

func (app *Application) setupRoutes(router *gin.Engine, handlers *handlers.Container, oidcService *auth.OIDCService) {
	router.GET(constants.PathHealth, handlers.Health.Check)
	router.GET(constants.PathHealthKeycloak, handlers.Health.ValidateKeycloak)
	router.GET(constants.PathSwagger+"*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	v1 := router.Group(constants.APIBasePath)

	auth := v1.Group(constants.PathAuth)
	{
		auth.GET(constants.PathAuthProviders, handlers.Auth.GetProviders)
		auth.GET(constants.PathAuthProvidersWellKnown, handlers.Auth.GetWellKnown)
		auth.POST(constants.PathAuthLogin, handlers.Auth.InitiateLogin)
		auth.GET(constants.PathAuthCallback, handlers.Auth.HandleCallback)
		auth.POST(constants.PathAuthValidate, handlers.Auth.ValidateToken)
		auth.POST(constants.PathAuthLogout, handlers.Auth.Logout)
		auth.GET(constants.PathAuthUserInfo, handlers.Auth.GetUserInfo)
		auth.POST(constants.PathAuthServiceToken, handlers.Auth.GetServiceToken)
		auth.POST(constants.PathAuthServiceValidate, handlers.Auth.ValidateServiceToken)
	}

	protected := v1.Group("/")
	protected.Use(middleware.OIDCAuthRequired(oidcService, app.logger))

	app.logger.Info("Routes configured",
		zap.String("admin_tenants_path", constants.PathAdminTenants))
	{
		admin := protected.Group(constants.PathAdmin)
		admin.Use(middleware.SuperAdminRequired())
		{
			admin.GET(constants.PathTenants, handlers.Tenant.List)
			admin.POST(constants.PathTenants, handlers.Tenant.Create)
			admin.GET(constants.PathAdminTenantsID, handlers.Tenant.Get)
			admin.PUT(constants.PathAdminTenantsID, handlers.Tenant.Update)
			admin.DELETE(constants.PathAdminTenantsID, handlers.Tenant.Delete)
			admin.POST(constants.PathAdminTenantsProvision, handlers.Tenant.ProvisionTenant)

			admin.GET(constants.PathUsers, handlers.User.List)
			admin.POST(constants.PathUsers, handlers.User.Create)
			admin.GET(constants.PathAdminUsersID, handlers.User.Get)
			admin.PUT(constants.PathAdminUsersID, handlers.User.Update)
			admin.DELETE(constants.PathAdminUsersID, handlers.User.Delete)
			admin.GET(constants.PathRoles, handlers.Role.List)
			admin.POST(constants.PathRoles, handlers.Role.Create)
			admin.GET(constants.PathAdminRolesID, handlers.Role.Get)
			admin.PUT(constants.PathAdminRolesID, handlers.Role.Update)
			admin.DELETE(constants.PathAdminRolesID, handlers.Role.Delete)
		}

		tenantScoped := protected.Group("/")
		tenantScoped.Use(middleware.TenantContextRequired())
		{
			tenantScoped.GET(constants.PathUsers, handlers.User.List)
			tenantScoped.POST(constants.PathUsers, handlers.User.Create)
			tenantScoped.GET(constants.PathUsersID, handlers.User.Get)
			tenantScoped.PUT(constants.PathUsersID, handlers.User.Update)
			tenantScoped.DELETE(constants.PathUsersID, handlers.User.Delete)
			tenantScoped.POST(constants.PathUsersBulkCreate, handlers.User.BulkCreate)
			tenantScoped.POST(constants.PathUsersImportCSV, handlers.User.ImportCSV)

			tenantScoped.GET(constants.PathRoles, handlers.Role.List)
			tenantScoped.POST(constants.PathRoles, handlers.Role.Create)
			tenantScoped.GET(constants.PathRolesID, handlers.Role.Get)
			tenantScoped.PUT(constants.PathRolesID, handlers.Role.Update)
			tenantScoped.DELETE(constants.PathRolesID, handlers.Role.Delete)

			tenantScoped.GET(constants.PathSSOProviders, handlers.SSO.ListProviders)
			tenantScoped.POST(constants.PathSSOProviders, handlers.SSO.CreateProvider)
			tenantScoped.GET(constants.PathSSOProvidersID, handlers.SSO.GetProvider)
			tenantScoped.PUT(constants.PathSSOProvidersID, handlers.SSO.UpdateProvider)
			tenantScoped.DELETE(constants.PathSSOProvidersID, handlers.SSO.DeleteProvider)
			tenantScoped.GET(constants.PathAudit, handlers.Audit.List)
			tenantScoped.GET(constants.PathAuditID, handlers.Audit.Get)
			tenantScoped.POST(constants.PathAuditExport, handlers.Audit.Export)
			tenantScoped.GET(constants.PathEnvironments, handlers.Environment.ListEnvironments)
			tenantScoped.POST(constants.PathEnvironments, handlers.Environment.CreateEnvironment)
			tenantScoped.GET(constants.PathEnvironmentsID, handlers.Environment.GetEnvironment)
			tenantScoped.PUT(constants.PathEnvironmentsID, handlers.Environment.UpdateEnvironment)
			tenantScoped.DELETE(constants.PathEnvironmentsID, handlers.Environment.DeleteEnvironment)
			tenantScoped.POST(constants.PathEnvironmentAccess, handlers.Environment.GrantAccess)
			tenantScoped.DELETE(constants.PathEnvironmentAccessGrant, handlers.Environment.RevokeAccess)
			tenantScoped.GET(constants.PathEnvironmentSecurityData, handlers.Environment.GetSIEMEnrichmentData)
			tenantScoped.GET(constants.PathEnvironmentNetworks, handlers.Environment.GetNetworkRanges)
			tenantScoped.GET(constants.PathEnvironmentInfrastructure, handlers.Environment.GetInfrastructureIPs)
		}
	}
}

func (app *Application) Start() error {
	app.logger.Info("HTTP server starting",
		zap.String("service", "booli-admin-api"),
		zap.String("address", app.server.Addr),
		zap.String("version", app.version),
		zap.String("environment", app.config.Environment))
	
	app.logger.Info("Server is now listening for requests",
		zap.String("url", "http://0.0.0.0"+app.server.Addr+"/health"))
	
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

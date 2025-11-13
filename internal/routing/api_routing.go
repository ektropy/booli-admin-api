package routing

import (
	"github.com/booli/booli-admin-api/internal/auth"
	"github.com/booli/booli-admin-api/internal/handlers"
	"github.com/booli/booli-admin-api/internal/middleware"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type APIRouter struct {
	rbac        *middleware.RBACMiddleware
	oidcService *auth.OIDCService
	logger      *zap.Logger
}

func NewAPIRouter(rbac *middleware.RBACMiddleware, oidcService *auth.OIDCService, logger *zap.Logger) *APIRouter {
	return &APIRouter{
		rbac:        rbac,
		oidcService: oidcService,
		logger:      logger,
	}
}

func (r *APIRouter) SetupAPIRoutes(router *gin.Engine, handlers *handlers.Container) {
	r.setupMSPRoutes(router.Group("/api/msps/v1"), handlers.MSP)
	r.setupTenantRoutes(router.Group("/api/tenants/v1"), handlers.Tenant)
	r.setupAuthRoutes(router.Group("/api/auth/v1"), handlers.Auth)
	r.setupUserRoutes(router.Group("/api/users/v1"), handlers.User)
	r.setupIdentityRoutes(router.Group("/api/identity/v1"), handlers.IdentityProvider)
	r.setupAdminRoutes(router.Group("/api/admin/v1"), handlers)
}

func (r *APIRouter) setupMSPRoutes(group *gin.RouterGroup, mspHandler *handlers.MSPHandler) {
	group.Use(middleware.OIDCAuthRequired(r.oidcService, r.logger))
	group.Use(r.rbac.RequirePermissionScopes("manage-realm"))
	
	group.POST("/", mspHandler.CreateMSP)
	group.GET("/", mspHandler.ListMSPs)
	group.GET("/:msp_id", mspHandler.GetMSP)
	group.PUT("/:msp_id", mspHandler.UpdateMSP)
	group.DELETE("/:msp_id", mspHandler.DeleteMSP)
	
	group.POST("/:msp_id/staff", mspHandler.AddMSPStaff)
	group.GET("/:msp_id/staff", mspHandler.ListMSPStaff)
	
	group.POST("/:msp_id/clients", mspHandler.CreateClientTenant)
	group.GET("/:msp_id/clients", mspHandler.ListMSPClients)
	
	group.GET("/health", mspHandler.HealthCheck)
	group.POST("/:msp_id/reconcile", mspHandler.Reconcile)
}

func (r *APIRouter) setupTenantRoutes(group *gin.RouterGroup, tenantHandler *handlers.TenantHandler) {
	group.Use(middleware.OIDCAuthRequired(r.oidcService, r.logger))

	group.GET("/", r.rbac.RequireReadAccess(), tenantHandler.List)
	group.POST("/", r.rbac.RequireAdminAccess(), tenantHandler.Create)
	group.GET("/:id", r.rbac.RequireReadAccess(), tenantHandler.Get)
	group.PUT("/:id", r.rbac.RequireAdminAccess(), tenantHandler.Update)
	group.DELETE("/:id", r.rbac.RequireAdminAccess(), tenantHandler.Delete)

	usersGroup := group.Group("/:id/users")
	usersGroup.POST("", r.rbac.RequireWriteAccess(), tenantHandler.CreateTenantUser)
	usersGroup.GET("", r.rbac.RequireReadAccess(), tenantHandler.ListTenantUsers)
	usersGroup.GET("/:user_id", r.rbac.RequireReadAccess(), tenantHandler.GetTenantUser)
	usersGroup.PUT("/:user_id", r.rbac.RequireWriteAccess(), tenantHandler.UpdateTenantUser)
	usersGroup.DELETE("/:user_id", r.rbac.RequireWriteAccess(), tenantHandler.DeleteTenantUser)
}

func (r *APIRouter) setupAuthRoutes(group *gin.RouterGroup, authHandler *handlers.AuthHandler) {
	group.GET("/providers", authHandler.GetProviders)
	group.POST("/login", authHandler.InitiateLogin)
	group.GET("/callback", authHandler.HandleCallback)
	group.POST("/validate", authHandler.ValidateToken)
	group.POST("/logout", authHandler.Logout)
	group.GET("/userinfo", authHandler.GetUserInfo)
}

func (r *APIRouter) setupUserRoutes(group *gin.RouterGroup, userHandler *handlers.UserHandler) {
	group.Use(middleware.OIDCAuthRequired(r.oidcService, r.logger))

	group.GET("/", r.rbac.RequireReadAccess(), userHandler.List)
	group.POST("/", r.rbac.RequireWriteAccess(), userHandler.Create)
	group.GET("/:id", r.rbac.RequireReadAccess(), userHandler.Get)
	group.PUT("/:id", r.rbac.RequireWriteAccess(), userHandler.Update)
	group.DELETE("/:id", r.rbac.RequireWriteAccess(), userHandler.Delete)
}

func (r *APIRouter) setupIdentityRoutes(group *gin.RouterGroup, idpHandler *handlers.IdentityProviderHandler) {
	group.GET("/", r.rbac.RequireReadAccess(), idpHandler.ListIdentityProviders)
	group.POST("/", r.rbac.RequireAdminAccess(), idpHandler.CreateIdentityProvider)
	group.GET("/:alias", r.rbac.RequireReadAccess(), idpHandler.GetIdentityProvider)
	group.PUT("/:alias", r.rbac.RequireAdminAccess(), idpHandler.UpdateIdentityProvider)
	group.DELETE("/:alias", r.rbac.RequireAdminAccess(), idpHandler.DeleteIdentityProvider)
}

func (r *APIRouter) setupAdminRoutes(group *gin.RouterGroup, handlersContainer *handlers.Container) {
	group.GET("/health", handlersContainer.Health.Check)
	group.GET("/environments", handlersContainer.Environment.ListEnvironments)
	group.GET("/audit", handlersContainer.Audit.List)
}
package routing

import (
	"github.com/booli/booli-admin-api/internal/handlers"
	"github.com/booli/booli-admin-api/internal/middleware"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type APIRouter struct {
	rbac   *middleware.RBACMiddleware
	logger *zap.Logger
}

func NewAPIRouter(rbac *middleware.RBACMiddleware, logger *zap.Logger) *APIRouter {
	return &APIRouter{
		rbac:   rbac,
		logger: logger,
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
	group.Use(r.rbac.RequirePermissionScopes("manage-realm"))
	
	// MSP management endpoints
	group.POST("/", mspHandler.CreateMSP)              // Create MSP
	group.GET("/", mspHandler.ListMSPs)                // List MSPs
	group.GET("/:msp_id", mspHandler.GetMSP)           // Get MSP details
	group.PUT("/:msp_id", mspHandler.UpdateMSP)        // Update MSP
	group.DELETE("/:msp_id", mspHandler.DeleteMSP)     // Delete MSP
	
	// MSP staff management
	group.POST("/:msp_id/staff", mspHandler.AddMSPStaff)                // Add MSP staff
	
	// Client tenant management
	group.POST("/:msp_id/clients", mspHandler.CreateClientTenant)   // Create client tenant
	group.GET("/:msp_id/clients", mspHandler.ListMSPClients)        // List MSP's clients
}

func (r *APIRouter) setupTenantRoutes(group *gin.RouterGroup, tenantHandler *handlers.TenantHandler) {
	group.Use(r.rbac.RequireReadAccess())
	
	// Tenant management endpoints
	group.GET("/", tenantHandler.List)                      // List accessible tenants
	group.POST("/", tenantHandler.Create)                   // Create tenant
	group.GET("/:id", tenantHandler.Get)                    // Get tenant details
	group.PUT("/:id", tenantHandler.Update)                 // Update tenant
	group.DELETE("/:id", tenantHandler.Delete)              // Delete tenant
	
	// Tenant-scoped user management using tenant ID as identifier
	usersGroup := group.Group("/:id/users")
	usersGroup.POST("", tenantHandler.CreateTenantUser)         // Create user in tenant
	usersGroup.GET("", tenantHandler.ListTenantUsers)           // List tenant users
	usersGroup.GET("/:user_id", tenantHandler.GetTenantUser)    // Get tenant user
	usersGroup.PUT("/:user_id", tenantHandler.UpdateTenantUser) // Update tenant user
	usersGroup.DELETE("/:user_id", tenantHandler.DeleteTenantUser) // Delete tenant user
}

func (r *APIRouter) setupAuthRoutes(group *gin.RouterGroup, authHandler *handlers.AuthHandler) {
	// Authentication endpoints - no auth required for most auth endpoints
	group.GET("/providers", authHandler.GetProviders)           // List auth providers
	group.POST("/login", authHandler.InitiateLogin)             // Initiate login
	group.GET("/callback", authHandler.HandleCallback)          // OAuth callback
	group.POST("/validate", authHandler.ValidateToken)          // Validate token
	group.POST("/logout", authHandler.Logout)                   // Logout
	group.GET("/userinfo", authHandler.GetUserInfo)             // Get user info
}

func (r *APIRouter) setupUserRoutes(group *gin.RouterGroup, userHandler *handlers.UserHandler) {
	group.Use(r.rbac.RequireReadAccess())
	
	// User management endpoints
	group.GET("/", userHandler.List)                             // List users
	group.POST("/", userHandler.Create)                          // Create user
	group.GET("/:id", userHandler.Get)                           // Get user details
	group.PUT("/:id", userHandler.Update)                        // Update user
	group.DELETE("/:id", userHandler.Delete)                     // Delete user
}

func (r *APIRouter) setupIdentityRoutes(group *gin.RouterGroup, idpHandler *handlers.IdentityProviderHandler) {
	group.Use(r.rbac.RequireReadAccess())
	
	// Identity provider (SSO) endpoints
	group.GET("/", idpHandler.ListIdentityProviders)             // List identity providers
	group.POST("/", idpHandler.CreateIdentityProvider)           // Create identity provider
	group.GET("/:alias", idpHandler.GetIdentityProvider)         // Get provider details
	group.PUT("/:alias", idpHandler.UpdateIdentityProvider)      // Update provider
	group.DELETE("/:alias", idpHandler.DeleteIdentityProvider)   // Delete provider
}

func (r *APIRouter) setupAdminRoutes(group *gin.RouterGroup, handlersContainer *handlers.Container) {
	// System administration endpoints
	group.GET("/health", handlersContainer.Health.Check)         // System health check
	group.GET("/environments", handlersContainer.Environment.ListEnvironments) // List environments
	group.GET("/audit", handlersContainer.Audit.List)            // Audit logs
}
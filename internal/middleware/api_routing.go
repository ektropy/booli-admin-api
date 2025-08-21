package middleware

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type APIRouter struct {
	rbac   *RBACMiddleware
	logger *zap.Logger
}

func NewAPIRouter(rbac *RBACMiddleware, logger *zap.Logger) *APIRouter {
	return &APIRouter{
		rbac:   rbac,
		logger: logger,
	}
}

func (r *APIRouter) SetupAPIRoutes(router *gin.Engine, handlers interface{}) {
	r.setupMSPRoutes(router.Group("/api/msps/v1"), handlers)
	r.setupTenantRoutes(router.Group("/api/tenants/v1"), handlers)
	r.setupAuthRoutes(router.Group("/api/auth/v1"), handlers)
	r.setupUserRoutes(router.Group("/api/users/v1"), handlers)
	r.setupIdentityRoutes(router.Group("/api/identity/v1"), handlers)
	r.setupAdminRoutes(router.Group("/api/admin/v1"), handlers)
}

func (r *APIRouter) setupMSPRoutes(group *gin.RouterGroup, handlers interface{}) {
	group.Use(r.rbac.RequirePermissionScopes("manage-realm"))
	
	// MSP management endpoints
	group.POST("/", r.rbac.RequireMSPAdminAccess())              // Create MSP
	group.GET("/", r.rbac.RequireMSPAdminAccess())               // List MSPs
	group.GET("/:msp_id", r.rbac.RequireMSPAdminAccess())        // Get MSP details
	group.DELETE("/:msp_id", r.rbac.RequireMSPAdminAccess())     // Delete MSP
	
	// MSP staff management
	group.POST("/:msp_id/staff", r.rbac.RequireMSPAdminAccess())                    // Add MSP staff
	group.PUT("/:msp_id/staff/:user_id/roles", r.rbac.RequireMSPAdminAccess())      // Change staff role
	group.DELETE("/:msp_id/staff/:user_id", r.rbac.RequireMSPAdminAccess())         // Remove staff
	
	// Client tenant management
	group.POST("/:msp_id/clients", r.rbac.RequireMSPAdminAccess())   // Create client tenant
	group.GET("/:msp_id/clients", r.rbac.RequireReadAccess())        // List MSP's clients
}

func (r *APIRouter) setupTenantRoutes(group *gin.RouterGroup, handlers interface{}) {
	group.Use(r.rbac.RequireReadAccess())
	
	// Tenant management endpoints
	group.GET("/", r.rbac.RequireReadAccess())                   // List accessible tenants
	group.GET("/:tenant_id", r.rbac.RequireReadAccess())         // Get tenant details
	group.PUT("/:tenant_id", r.rbac.RequireWriteAccess())        // Update tenant
	group.DELETE("/:tenant_id", r.rbac.RequireAdminAccess())     // Delete tenant
	group.GET("/:tenant_id/stats", r.rbac.RequireReadAccess())   // Get tenant statistics
}

func (r *APIRouter) setupAuthRoutes(group *gin.RouterGroup, handlers interface{}) {
	// Authentication endpoints - no auth required for token endpoints
	group.POST("/token")                                         // Get authentication token
	group.POST("/validate", r.rbac.RequireAuthentication())     // Validate token
	group.POST("/refresh", r.rbac.RequireAuthentication())      // Refresh token
	group.GET("/providers", r.rbac.RequireReadAccess())         // List auth providers
}

func (r *APIRouter) setupUserRoutes(group *gin.RouterGroup, handlers interface{}) {
	group.Use(r.rbac.RequireReadAccess())
	
	// User management endpoints
	group.GET("/", r.rbac.RequireReadAccess())                   // List users (scoped to accessible tenants)
	group.POST("/", r.rbac.RequireWriteAccess())                 // Create user
	group.GET("/:user_id", r.rbac.RequireReadAccess())           // Get user details
	group.PUT("/:user_id", r.rbac.RequireWriteAccess())          // Update user
	group.DELETE("/:user_id", r.rbac.RequireAdminAccess())       // Delete user
	group.POST("/:user_id/invite", r.rbac.RequireWriteAccess())  // Send user invitation
	group.POST("/:user_id/resend", r.rbac.RequireWriteAccess())  // Resend invitation
	group.PUT("/:user_id/roles", r.rbac.RequireAdminAccess())    // Assign user roles
}

func (r *APIRouter) setupIdentityRoutes(group *gin.RouterGroup, handlers interface{}) {
	group.Use(r.rbac.RequireReadAccess())
	
	// Identity provider (SSO) endpoints
	group.GET("/", r.rbac.RequireReadAccess())                   // List identity providers
	group.POST("/", r.rbac.RequireAdminAccess())                 // Create identity provider
	group.GET("/:provider_id", r.rbac.RequireReadAccess())       // Get provider details
	group.PUT("/:provider_id", r.rbac.RequireAdminAccess())      // Update provider
	group.DELETE("/:provider_id", r.rbac.RequireAdminAccess())   // Delete provider
}

func (r *APIRouter) setupAdminRoutes(group *gin.RouterGroup, handlers interface{}) {
	// System administration endpoints
	group.GET("/health")                                         // System health check (no auth)
	group.GET("/stats", r.rbac.RequireMSPAdminAccess())         // System statistics
	group.GET("/audit", r.rbac.RequireMSPAdminAccess())         // Audit logs
	
	// SMTP configuration endpoints
	group.PUT("/smtp-config/:tenant_id", r.rbac.RequireMSPAdminAccess())      // Configure SMTP for tenant
	group.POST("/smtp-config/:tenant_id/test", r.rbac.RequireMSPAdminAccess()) // Test SMTP connection
	group.GET("/smtp-config/:tenant_id", r.rbac.RequireMSPAdminAccess())       // Get SMTP config
}
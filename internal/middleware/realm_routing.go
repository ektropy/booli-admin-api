package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// RealmRoutingMiddleware extracts realm context from URL path and sets it in the request context
// This middleware handles URLs like /api/v1/realms/{realm}/tenants or /api/v1/tenants (uses user's default realm)
func RealmRoutingMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		
		// Check if the path contains realm parameter
		if strings.Contains(path, "/realms/") {
			// Extract realm from URL path like /api/v1/realms/{realm}/tenants
			parts := strings.Split(path, "/")
			realmIndex := -1
			
			for i, part := range parts {
				if part == "realms" && i+1 < len(parts) {
					realmIndex = i + 1
					break
				}
			}
			
			if realmIndex != -1 && realmIndex < len(parts) {
				realmName := parts[realmIndex]
				if realmName != "" {
					c.Set("realm_name", realmName)
					logger.Debug("Extracted realm from URL path",
						zap.String("path", path),
						zap.String("realm", realmName))
				}
			}
		} else {
			// If no realm in URL, use user's default realm from token
			// This is already set by the auth middleware, so we don't need to do anything
			logger.Debug("Using default realm from token", zap.String("path", path))
		}
		
		c.Next()
	}
}

// RealmParameterRequired ensures that a realm parameter is present in the request context
func RealmParameterRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		realmName, exists := c.Get("realm_name")
		if !exists || realmName == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Realm parameter is required",
				"code":  "REALM_PARAMETER_REQUIRED",
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// MSPRealmRouter provides realm-aware routing for MSP operations
type MSPRealmRouter struct {
	rbac   *RBACMiddleware
	logger *zap.Logger
}

// NewMSPRealmRouter creates a new realm router for MSP operations
func NewMSPRealmRouter(rbac *RBACMiddleware, logger *zap.Logger) *MSPRealmRouter {
	return &MSPRealmRouter{
		rbac:   rbac,
		logger: logger,
	}
}

// SetupRealmRoutes configures routes with proper realm access control
func (r *MSPRealmRouter) SetupRealmRoutes(router *gin.Engine) {
	// API v1 group with authentication
	v1 := router.Group("/api/v1")
	v1.Use(RealmRoutingMiddleware(r.logger))
	
	// Routes that operate on specific realms
	realmRoutes := v1.Group("/realms/:realm")
	realmRoutes.Use(RealmParameterRequired())
	realmRoutes.Use(r.rbac.CrossRealmAccessMiddleware())
	
	// Tenant management routes (MSP admins can manage tenants across realms)
	tenantRoutes := realmRoutes.Group("/tenants")
	{
		tenantRoutes.GET("", r.rbac.RequireReadAccess()) // List tenants - read access
		tenantRoutes.POST("", r.rbac.RequireWriteAccess()) // Create tenant - write access
		tenantRoutes.GET("/:id", r.rbac.RequireReadAccess()) // Get tenant - read access
		tenantRoutes.PUT("/:id", r.rbac.RequireWriteAccess()) // Update tenant - write access
		tenantRoutes.DELETE("/:id", r.rbac.RequireAdminAccess()) // Delete tenant - admin access
	}
	
	// User management routes
	userRoutes := realmRoutes.Group("/users")
	{
		userRoutes.GET("", r.rbac.RequireReadAccess()) // List users - read access
		userRoutes.POST("", r.rbac.RequireWriteAccess()) // Create user - write access
		userRoutes.GET("/:id", r.rbac.RequireReadAccess()) // Get user - read access
		userRoutes.PUT("/:id", r.rbac.RequireWriteAccess()) // Update user - write access
		userRoutes.DELETE("/:id", r.rbac.RequireAdminAccess()) // Delete user - admin access
	}
	
	// SSO provider management routes
	ssoRoutes := realmRoutes.Group("/sso")
	{
		ssoRoutes.GET("/providers", r.rbac.RequireReadAccess()) // List providers - read access
		ssoRoutes.POST("/providers", r.rbac.RequireAdminAccess()) // Create provider - admin access
		ssoRoutes.GET("/providers/:id", r.rbac.RequireReadAccess()) // Get provider - read access
		ssoRoutes.PUT("/providers/:id", r.rbac.RequireAdminAccess()) // Update provider - admin access
		ssoRoutes.DELETE("/providers/:id", r.rbac.RequireAdminAccess()) // Delete provider - admin access
	}
	
	// Audit log routes
	auditRoutes := realmRoutes.Group("/audit")
	{
		auditRoutes.GET("/logs", r.rbac.RequireReadAccess()) // List audit logs - read access
		auditRoutes.GET("/logs/:id", r.rbac.RequireReadAccess()) // Get audit log - read access
		auditRoutes.POST("/export", r.rbac.RequireReadAccess()) // Export audit logs - read access
	}
	
	// MSP-only routes (master realm operations)
	mspRoutes := v1.Group("/msp")
	mspRoutes.Use(r.rbac.RequireMSPAdminAccess())
	{
		mspRoutes.GET("/realms", r.rbac.RequireMSPAdminAccess()) // List all realms - MSP admin only
		mspRoutes.POST("/realms", r.rbac.RequireMSPAdminAccess()) // Create realm - MSP admin only
		mspRoutes.GET("/stats", r.rbac.RequireMSPAdminAccess()) // Get MSP statistics - MSP admin only
		mspRoutes.GET("/health", r.rbac.RequireMSPAdminAccess()) // MSP health check - MSP admin only
	}
	
	// Default tenant-scoped routes (use user's default realm)
	defaultRoutes := v1.Group("")
	defaultRoutes.Use(r.rbac.RequireRealmAccess())
	{
		// These routes operate on the user's default tenant realm
		defaultRoutes.GET("/profile", r.rbac.RequireReadAccess()) // User profile
		defaultRoutes.PUT("/profile", r.rbac.RequireWriteAccess()) // Update profile
		defaultRoutes.GET("/dashboard", r.rbac.RequireReadAccess()) // Dashboard data
	}
}

// RealmAccessSummary provides a summary of what realms a user can access
type RealmAccessSummary struct {
	UserID      string                 `json:"user_id"`
	SourceRealm string                 `json:"source_realm"`
	RealmAccess map[string]RealmAccess `json:"realm_access"`
}

// RealmAccess represents a user's access to a specific realm
type RealmAccess struct {
	RealmName   string   `json:"realm_name"`
	AccessLevel string   `json:"access_level"`
	Permissions []string `json:"permissions"`
}

// GetUserRealmAccessSummary returns a summary of all realms a user can access
func (r *MSPRealmRouter) GetUserRealmAccessSummary() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User context required",
				"code":  "USER_CONTEXT_REQUIRED",
			})
			return
		}

		providerName, _ := c.Get("provider_name")
		sourceRealm := ""
		if providerName != nil {
			sourceRealm = extractRealmFromProvider(providerName.(string))
		}

		// This would be implemented to query all realms and check access levels
		// For now, return a placeholder response
		summary := &RealmAccessSummary{
			UserID:      userID.(string),
			SourceRealm: sourceRealm,
			RealmAccess: make(map[string]RealmAccess),
		}

		c.JSON(http.StatusOK, summary)
	}
}
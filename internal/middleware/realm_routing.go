package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func RealmRoutingMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		
		if strings.Contains(path, "/realms/") {
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
			logger.Debug("Using default realm from token", zap.String("path", path))
		}
		
		c.Next()
	}
}

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

type MSPRealmRouter struct {
	rbac   *RBACMiddleware
	logger *zap.Logger
}

func NewMSPRealmRouter(rbac *RBACMiddleware, logger *zap.Logger) *MSPRealmRouter {
	return &MSPRealmRouter{
		rbac:   rbac,
		logger: logger,
	}
}

func (r *MSPRealmRouter) SetupRealmRoutes(router *gin.Engine) {
	v1 := router.Group("/api/v1")
	v1.Use(RealmRoutingMiddleware(r.logger))
	
	realmRoutes := v1.Group("/realms/:realm")
	realmRoutes.Use(RealmParameterRequired())
	realmRoutes.Use(r.rbac.CrossRealmAccessMiddleware())
	
	tenantRoutes := realmRoutes.Group("/tenants")
	{
		tenantRoutes.GET("", r.rbac.RequireReadAccess())
		tenantRoutes.POST("", r.rbac.RequireWriteAccess())
		tenantRoutes.GET("/:id", r.rbac.RequireReadAccess())
		tenantRoutes.PUT("/:id", r.rbac.RequireWriteAccess())
		tenantRoutes.DELETE("/:id", r.rbac.RequireAdminAccess())
	}
	
	userRoutes := realmRoutes.Group("/users")
	{
		userRoutes.GET("", r.rbac.RequireReadAccess())
		userRoutes.POST("", r.rbac.RequireWriteAccess())
		userRoutes.GET("/:id", r.rbac.RequireReadAccess())
		userRoutes.PUT("/:id", r.rbac.RequireWriteAccess())
		userRoutes.DELETE("/:id", r.rbac.RequireAdminAccess())
	}
	
	ssoRoutes := realmRoutes.Group("/sso")
	{
		ssoRoutes.GET("/providers", r.rbac.RequireReadAccess())
		ssoRoutes.POST("/providers", r.rbac.RequireAdminAccess())
		ssoRoutes.GET("/providers/:id", r.rbac.RequireReadAccess())
		ssoRoutes.PUT("/providers/:id", r.rbac.RequireAdminAccess())
		ssoRoutes.DELETE("/providers/:id", r.rbac.RequireAdminAccess())
	}
	
	auditRoutes := realmRoutes.Group("/audit")
	{
		auditRoutes.GET("/logs", r.rbac.RequireReadAccess())
		auditRoutes.GET("/logs/:id", r.rbac.RequireReadAccess())
		auditRoutes.POST("/export", r.rbac.RequireReadAccess())
	}
	
	mspRoutes := v1.Group("/msp")
	mspRoutes.Use(r.rbac.RequireMSPAdminAccess())
	{
		mspRoutes.GET("/realms", r.rbac.RequireMSPAdminAccess())
		mspRoutes.POST("/realms", r.rbac.RequireMSPAdminAccess())
		mspRoutes.GET("/stats", r.rbac.RequireMSPAdminAccess())
		mspRoutes.GET("/health", r.rbac.RequireMSPAdminAccess())
	}
	
	defaultRoutes := v1.Group("")
	defaultRoutes.Use(r.rbac.RequireRealmAccess())
	{
		defaultRoutes.GET("/profile", r.rbac.RequireReadAccess())
		defaultRoutes.PUT("/profile", r.rbac.RequireWriteAccess())
		defaultRoutes.GET("/dashboard", r.rbac.RequireReadAccess())
	}
}

type RealmAccessSummary struct {
	UserID      string                 `json:"user_id"`
	SourceRealm string                 `json:"source_realm"`
	RealmAccess map[string]RealmAccess `json:"realm_access"`
}

type RealmAccess struct {
	RealmName   string   `json:"realm_name"`
	AccessLevel string   `json:"access_level"`
	Permissions []string `json:"permissions"`
}

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
			sourceRealm = r.rbac.ExtractRealmFromProvider(providerName.(string))
		}

		summary := &RealmAccessSummary{
			UserID:      userID.(string),
			SourceRealm: sourceRealm,
			RealmAccess: make(map[string]RealmAccess),
		}

		c.JSON(http.StatusOK, summary)
	}
}
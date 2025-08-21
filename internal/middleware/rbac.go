package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/booli/booli-admin-api/internal/services"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type RBACMiddleware struct {
	keycloakAdmin     *keycloak.AdminClient
	permissionService *services.PermissionService
	logger            *zap.Logger
}

func NewRBACMiddleware(keycloakAdmin *keycloak.AdminClient, logger *zap.Logger) *RBACMiddleware {
	permissionService := services.NewPermissionService(keycloakAdmin, logger)
	return &RBACMiddleware{
		keycloakAdmin:     keycloakAdmin,
		permissionService: permissionService,
		logger:            logger,
	}
}

func (r *RBACMiddleware) RequireAuthentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
				"code":  "AUTHENTICATION_REQUIRED",
			})
			c.Abort()
			return
		}

		if userID == nil || userID.(string) == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authentication",
				"code":  "INVALID_AUTHENTICATION",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (r *RBACMiddleware) RequirePermissionScopes(scopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User context required",
				"code":  "USER_CONTEXT_REQUIRED",
			})
			c.Abort()
			return
		}

		realmName := r.extractRealmFromContext(c)
		if realmName == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Realm context required",
				"code":  "REALM_CONTEXT_REQUIRED",
			})
			c.Abort()
			return
		}

		for _, scope := range scopes {
			hasPermission, err := r.keycloakAdmin.HasPermissionScope(
				c.Request.Context(),
				realmName,
				userID.(string),
				scope,
				realmName,
			)

			if err != nil {
				r.logger.Error("Failed to check permission scope",
					zap.Error(err),
					zap.String("user_id", userID.(string)),
					zap.String("realm", realmName),
					zap.String("scope", scope))

				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Permission check failed",
					"code":  "PERMISSION_CHECK_ERROR",
				})
				c.Abort()
				return
			}

			if !hasPermission {
				r.logger.Warn("Permission denied",
					zap.String("user_id", userID.(string)),
					zap.String("realm", realmName),
					zap.String("scope", scope))

				c.JSON(http.StatusForbidden, gin.H{
					"error": fmt.Sprintf("Permission denied: %s", scope),
					"code":  "PERMISSION_DENIED",
				})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

func (r *RBACMiddleware) RequireReadAccess() gin.HandlerFunc {
	return r.RequirePermissionScopes("view-users")
}

func (r *RBACMiddleware) RequireWriteAccess() gin.HandlerFunc {
	return r.RequirePermissionScopes("manage-users")
}

func (r *RBACMiddleware) RequireAdminAccess() gin.HandlerFunc {
	return r.RequirePermissionScopes("manage-realm")
}

func (r *RBACMiddleware) RequireMSPAdminAccess() gin.HandlerFunc {
	return r.RequirePermissionScopes("manage-realm", "manage-users")
}

func (r *RBACMiddleware) RequireAnyRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRoles, exists := c.Get("user_roles")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User roles not found",
				"code":  "USER_ROLES_REQUIRED",
			})
			c.Abort()
			return
		}

		rolesSlice := userRoles.([]string)

		for _, requiredRole := range roles {
			for _, userRole := range rolesSlice {
				if userRole == requiredRole {
					c.Next()
					return
				}
			}
		}

		r.logger.Warn("Role requirement not met",
			zap.Strings("required_roles", roles),
			zap.Strings("user_roles", rolesSlice))

		c.JSON(http.StatusForbidden, gin.H{
			"error": "Insufficient role permissions",
			"code":  "INSUFFICIENT_ROLE_PERMISSIONS",
		})
		c.Abort()
	}
}

func (r *RBACMiddleware) CrossRealmAccessMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.Next()
			return
		}

		sourceRealm := r.extractSourceRealmFromContext(c)
		targetRealm := r.extractRealmFromContext(c)

		if sourceRealm == "" || targetRealm == "" {
			c.Next()
			return
		}

		hasAccess, err := r.permissionService.ValidateCrossRealmAccess(
			c.Request.Context(),
			sourceRealm,
			userID.(string),
			targetRealm,
		)

		if err != nil {
			r.logger.Error("Failed to validate cross-realm access",
				zap.Error(err),
				zap.String("user_id", userID.(string)),
				zap.String("source_realm", sourceRealm),
				zap.String("target_realm", targetRealm))

			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Access validation failed",
				"code":  "ACCESS_VALIDATION_ERROR",
			})
			c.Abort()
			return
		}

		if !hasAccess {
			r.logger.Warn("Cross-realm access denied",
				zap.String("user_id", userID.(string)),
				zap.String("source_realm", sourceRealm),
				zap.String("target_realm", targetRealm))

			c.JSON(http.StatusForbidden, gin.H{
				"error": "Cross-realm access denied",
				"code":  "CROSS_REALM_ACCESS_DENIED",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (r *RBACMiddleware) extractRealmFromContext(c *gin.Context) string {
	// Try to get from context first
	if realmName, exists := c.Get("realm_name"); exists {
		return realmName.(string)
	}

	// Extract from URL path
	path := c.Request.URL.Path
	if strings.Contains(path, "/realms/") {
		parts := strings.Split(path, "/")
		for i, part := range parts {
			if part == "realms" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}

	// Extract from MSP/tenant paths
	if strings.Contains(path, "/msps/") {
		parts := strings.Split(path, "/")
		for i, part := range parts {
			if part == "msps" && i+1 < len(parts) {
				return parts[i+1] 
			}
		}
	}

	if strings.Contains(path, "/tenants/") {
		parts := strings.Split(path, "/")
		for i, part := range parts {
			if part == "tenants" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}

	return ""
}

func (r *RBACMiddleware) extractSourceRealmFromContext(c *gin.Context) string {
	if providerName, exists := c.Get("provider_name"); exists {
		return r.extractRealmFromProvider(providerName.(string))
	}
	return ""
}

func (r *RBACMiddleware) extractRealmFromProvider(providerName string) string {
	if strings.HasPrefix(providerName, "keycloak-") {
		parts := strings.Split(providerName, "-")
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	return "master"
}
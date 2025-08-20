package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type RBACMiddleware struct {
	keycloakAdmin *keycloak.AdminClient
	logger        *zap.Logger
}

func NewRBACMiddleware(keycloakAdmin *keycloak.AdminClient, logger *zap.Logger) *RBACMiddleware {
	return &RBACMiddleware{
		keycloakAdmin: keycloakAdmin,
		logger:        logger,
	}
}

func (r *RBACMiddleware) RequirePermission(resource, action string) gin.HandlerFunc {
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

		realmName, exists := c.Get("realm_name")
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Realm context required", 
				"code":  "REALM_CONTEXT_REQUIRED",
			})
			c.Abort()
			return
		}

		hasPermission, err := r.checkPermission(c.Request.Context(), realmName.(string), userID.(string), resource, action)
		if err != nil {
			r.logger.Error("Failed to check permission",
				zap.Error(err),
				zap.String("user_id", userID.(string)),
				zap.String("realm", realmName.(string)),
				zap.String("resource", resource),
				zap.String("action", action))
			
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
				zap.String("realm", realmName.(string)),
				zap.String("resource", resource),
				zap.String("action", action))
			
			c.JSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("Permission denied: %s:%s", resource, action),
				"code":  "PERMISSION_DENIED",
			})
			c.Abort()
			return
		}

		c.Next()
	}
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

		r.logger.Warn("Role check failed",
			zap.Strings("user_roles", rolesSlice),
			zap.Strings("required_roles", roles))

		c.JSON(http.StatusForbidden, gin.H{
			"error": fmt.Sprintf("Role required: %v", roles),
			"code":  "ROLE_REQUIRED",
		})
		c.Abort()
	}
}

func (r *RBACMiddleware) RequireAllRoles(roles ...string) gin.HandlerFunc {
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
			found := false
			for _, userRole := range rolesSlice {
				if userRole == requiredRole {
					found = true
					break
				}
			}
			if !found {
				r.logger.Warn("Role check failed - missing role",
					zap.Strings("user_roles", rolesSlice),
					zap.String("missing_role", requiredRole))

				c.JSON(http.StatusForbidden, gin.H{
					"error": fmt.Sprintf("Missing required role: %s", requiredRole),
					"code":  "ROLE_REQUIRED",
				})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

func (r *RBACMiddleware) RequireRealmAccess() gin.HandlerFunc {
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

		realmName, exists := c.Get("realm_name")
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Realm context required",
				"code":  "REALM_CONTEXT_REQUIRED",
			})
			c.Abort()
			return
		}

		hasAccess, err := r.checkRealmAccess(c.Request.Context(), realmName.(string), userID.(string))
		if err != nil {
			r.logger.Error("Failed to check realm access",
				zap.Error(err),
				zap.String("user_id", userID.(string)),
				zap.String("realm", realmName.(string)))
			
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Realm access check failed",
				"code":  "REALM_ACCESS_CHECK_ERROR",
			})
			c.Abort()
			return
		}

		if !hasAccess {
			r.logger.Warn("Realm access denied",
				zap.String("user_id", userID.(string)),
				zap.String("realm", realmName.(string)))
			
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied to this tenant",
				"code":  "REALM_ACCESS_DENIED",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (r *RBACMiddleware) checkPermission(ctx context.Context, realmName, userID, resource, action string) (bool, error) {
	return r.keycloakAdmin.CheckUserPermission(ctx, realmName, userID, resource, action)
}

func (r *RBACMiddleware) checkRealmAccess(ctx context.Context, realmName, userID string) (bool, error) {
	return r.keycloakAdmin.CheckUserRealmAccess(ctx, userID, realmName)
}

func (r *RBACMiddleware) MSPAdminRequired() gin.HandlerFunc {
	return r.RequireAnyRole("msp-admin")
}

func (r *RBACMiddleware) TenantAdminRequired() gin.HandlerFunc {
	return r.RequireAnyRole("tenant-admin", "msp-admin")
}

func (r *RBACMiddleware) TenantUserRequired() gin.HandlerFunc {
	return r.RequireAnyRole("tenant-user", "tenant-admin", "msp-admin")
}

func (r *RBACMiddleware) RequireAccessLevel(requiredLevel keycloak.RealmAccessLevel) gin.HandlerFunc {
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

		targetRealm, exists := c.Get("realm_name")
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Realm context required",
				"code":  "REALM_CONTEXT_REQUIRED",
			})
			c.Abort()
			return
		}

		providerName, _ := c.Get("provider_name")
		var sourceRealm string
		if providerName != nil {
			sourceRealm = extractRealmFromProvider(providerName.(string))
		}

		accessLevel, err := r.keycloakAdmin.GetUserRealmAccessLevel(
			c.Request.Context(),
			userID.(string),
			targetRealm.(string),
			sourceRealm,
		)
		if err != nil {
			r.logger.Error("Failed to check access level",
				zap.Error(err),
				zap.String("user_id", userID.(string)),
				zap.String("target_realm", targetRealm.(string)),
				zap.String("source_realm", sourceRealm))
			
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Access level check failed",
				"code":  "ACCESS_LEVEL_CHECK_ERROR",
			})
			c.Abort()
			return
		}

		if !r.hasRequiredAccessLevel(accessLevel, requiredLevel) {
			r.logger.Warn("Insufficient access level",
				zap.String("user_id", userID.(string)),
				zap.String("target_realm", targetRealm.(string)),
				zap.String("required_level", string(requiredLevel)),
				zap.String("actual_level", string(accessLevel)))
			
			c.JSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("Insufficient access level: %s required", requiredLevel),
				"code":  "INSUFFICIENT_ACCESS_LEVEL",
			})
			c.Abort()
			return
		}

		c.Set("access_level", accessLevel)
		c.Next()
	}
}

func (r *RBACMiddleware) hasRequiredAccessLevel(userLevel, requiredLevel keycloak.RealmAccessLevel) bool {
	levels := map[keycloak.RealmAccessLevel]int{
		keycloak.RealmAccessNone:     0,
		keycloak.RealmAccessRead:     1,
		keycloak.RealmAccessWrite:    2,
		keycloak.RealmAccessAdmin:    3,
		keycloak.RealmAccessMSPAdmin: 4,
	}

	userLevelValue := levels[userLevel]
	requiredLevelValue := levels[requiredLevel]

	return userLevelValue >= requiredLevelValue
}

// extractRealmFromProvider extracts realm name from provider name
func extractRealmFromProvider(providerName string) string {
	// For Keycloak providers, extract realm from provider name
	if strings.HasPrefix(providerName, "keycloak-") {
		return strings.TrimPrefix(providerName, "keycloak-")
	}
	return providerName
}

// Convenience methods for common access levels

// RequireReadAccess ensures user has at least read access to the realm
func (r *RBACMiddleware) RequireReadAccess() gin.HandlerFunc {
	return r.RequireAccessLevel(keycloak.RealmAccessRead)
}

// RequireWriteAccess ensures user has at least write access to the realm
func (r *RBACMiddleware) RequireWriteAccess() gin.HandlerFunc {
	return r.RequireAccessLevel(keycloak.RealmAccessWrite)
}

// RequireAdminAccess ensures user has admin access to the realm
func (r *RBACMiddleware) RequireAdminAccess() gin.HandlerFunc {
	return r.RequireAccessLevel(keycloak.RealmAccessAdmin)
}

// RequireMSPAdminAccess ensures user has MSP admin access
func (r *RBACMiddleware) RequireMSPAdminAccess() gin.HandlerFunc {
	return r.RequireAccessLevel(keycloak.RealmAccessMSPAdmin)
}

// CrossRealmAccessMiddleware validates cross-realm access for API endpoints
func (r *RBACMiddleware) CrossRealmAccessMiddleware() gin.HandlerFunc {
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

		targetRealm, exists := c.Get("realm_name")
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Realm context required",
				"code":  "REALM_CONTEXT_REQUIRED",
			})
			c.Abort()
			return
		}

		providerName, _ := c.Get("provider_name")
		var sourceRealm string
		if providerName != nil {
			sourceRealm = extractRealmFromProvider(providerName.(string))
		}

		hasAccess, err := r.keycloakAdmin.ValidateRealmAccess(
			c.Request.Context(),
			userID.(string),
			targetRealm.(string),
			sourceRealm,
		)
		if err != nil {
			r.logger.Error("Failed to validate realm access",
				zap.Error(err),
				zap.String("user_id", userID.(string)),
				zap.String("target_realm", targetRealm.(string)),
				zap.String("source_realm", sourceRealm))
			
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Realm access validation failed",
				"code":  "REALM_ACCESS_VALIDATION_ERROR",
			})
			c.Abort()
			return
		}

		if !hasAccess {
			r.logger.Warn("Cross-realm access denied",
				zap.String("user_id", userID.(string)),
				zap.String("target_realm", targetRealm.(string)),
				zap.String("source_realm", sourceRealm))
			
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied to this tenant realm",
				"code":  "CROSS_REALM_ACCESS_DENIED",
			})
			c.Abort()
			return
		}

		// Store source realm for audit logging
		c.Set("source_realm", sourceRealm)
		c.Next()
	}
}
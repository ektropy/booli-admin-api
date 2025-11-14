package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/booli/booli-admin-api/internal/auth"
	"github.com/booli/booli-admin-api/internal/constants"
	"github.com/booli/booli-admin-api/internal/utils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func OIDCAuthRequired(oidcService *auth.OIDCService, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {

		token, err := extractToken(c)
		if err != nil {
			if logger != nil {
				logger.Debug("Token extraction failed", zap.Error(err))
			}
			utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized,
				"Authentication required", nil)
			c.Abort()
			return
		}

		providerName := c.GetHeader("X-Auth-Provider")
		if providerName == "" {
			providerName = constants.DefaultProvider
		}

		if logger != nil {
			tokenPrefix := token
			if len(token) > 10 {
				tokenPrefix = token[:10] + "..."
			}
			logger.Debug("Validating token",
				zap.String("provider", providerName),
				zap.String("token_prefix", tokenPrefix))
		}


	claims, err := oidcService.ValidateToken(context.Background(), providerName, token)
	if err != nil {
		// Try all providers if the default one fails
		allProviders := oidcService.GetProviderNames()
		var lastErr error
		for _, pName := range allProviders {
			if pName == providerName {
				continue // Already tried this one
			}
			claims, lastErr = oidcService.ValidateToken(context.Background(), pName, token)
			if lastErr == nil {
				providerName = pName // Update to the working provider
				if logger != nil {
					logger.Debug("Token validated with fallback provider",
						zap.String("provider", providerName))
				}
				break
			}
		}

		if lastErr != nil {
			if logger != nil {
				logger.Info("Token validation failed",
					zap.Error(err),
					zap.String("provider", providerName))
			}
			utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeInvalidToken,
				"Invalid or expired token", err.Error())
			c.Abort()
			return
		}
	}
		realmName := extractRealmFromClaims(claims, providerName)

		c.Set("user_id", claims.Subject)
		c.Set("realm_name", realmName)
		c.Set("user_email", claims.Email)
		c.Set("user_roles", claims.RealmAccess.Roles)
		c.Set("provider_name", providerName)
		c.Set("claims", claims)

		c.Next()
	}
}

func extractRealmFromClaims(claims *auth.OIDCClaims, providerName string) string {
	if strings.HasPrefix(providerName, "keycloak-") {
		return strings.TrimPrefix(providerName, "keycloak-")
	}

	if providerName == "keycloak" && claims.Issuer != "" {
		parts := strings.Split(claims.Issuer, "/realms/")
		if len(parts) == 2 {
			return parts[1]
		}
	}

	return providerName
}

func RealmContextRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		realmName, exists := c.Get("realm_name")
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Realm context required",
				"code":  "REALM_CONTEXT_REQUIRED",
			})
			c.Abort()
			return
		}

		if realmName.(string) == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid realm name",
				"code":  "INVALID_REALM_NAME",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func SuperAdminRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		roles, exists := c.Get("user_roles")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied",
				"code":  "ACCESS_DENIED",
			})
			c.Abort()
			return
		}

		userRoles := roles.([]string)
		if !containsRole(userRoles, constants.RoleMSPAdmin) {
			utils.RespondWithError(c, http.StatusForbidden, utils.ErrCodeInsufficientPermissions,
				"MSP admin access required", "User does not have MSP admin role")
			c.Abort()
			return
		}

		c.Next()
	}
}

func TenantAdminRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		roles, exists := c.Get("user_roles")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied",
				"code":  "ACCESS_DENIED",
			})
			c.Abort()
			return
		}

		userRoles := roles.([]string)
		if !containsRole(userRoles, constants.RoleTenantAdmin) && !containsRole(userRoles, constants.RoleMSPAdmin) {
			utils.RespondWithError(c, http.StatusForbidden, utils.ErrCodeInsufficientPermissions,
				"Admin access required", "User does not have admin role")
			c.Abort()
			return
		}

		c.Next()
	}
}

func MSPRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		roles, exists := c.Get("user_roles")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied",
				"code":  "ACCESS_DENIED",
			})
			c.Abort()
			return
		}

		userRoles := roles.([]string)
		if !containsRole(userRoles, constants.RoleMSPAdmin) && !containsRole(userRoles, constants.RoleMSPPower) && !containsRole(userRoles, constants.RoleMSPBasic) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "MSP access required",
				"code":  "MSP_ACCESS_REQUIRED",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func UserCreatePermissionRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		permissions, exists := c.Get("user_permissions")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied",
				"code":  "ACCESS_DENIED",
			})
			c.Abort()
			return
		}

		userPermissions := permissions.([]string)
		if !containsPermission(userPermissions, "user:create") {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "User creation permission required (admin role)",
				"code":  "USER_CREATE_PERMISSION_REQUIRED",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func PermissionRequired(requiredPermissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		permissions, exists := c.Get("user_permissions")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied",
				"code":  "ACCESS_DENIED",
			})
			c.Abort()
			return
		}

		userPermissions := permissions.([]string)

		for _, required := range requiredPermissions {
			if !containsPermission(userPermissions, required) {
				c.JSON(http.StatusForbidden, gin.H{
					"error": fmt.Sprintf("Permission '%s' required", required),
					"code":  "INSUFFICIENT_PERMISSIONS",
				})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

func RoleRequired(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roles, exists := c.Get("user_roles")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied",
				"code":  "ACCESS_DENIED",
			})
			c.Abort()
			return
		}

		userRoles := roles.([]string)

		for _, required := range requiredRoles {
			if containsRole(userRoles, required) {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{
			"error": "Insufficient role privileges",
			"code":  "INSUFFICIENT_ROLES",
		})
		c.Abort()
	}
}

func extractToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header missing")
	}

	if !strings.HasPrefix(strings.ToLower(authHeader), strings.ToLower(constants.BearerTokenPrefix)) {
		return "", fmt.Errorf("invalid authorization header format")
	}

	parts := strings.SplitN(authHeader, " ", 3)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return parts[1], nil
}

func containsRole(userRoles []string, targetRole string) bool {
	for _, role := range userRoles {
		if role == targetRole {
			return true
		}
	}
	return false
}

func containsPermission(userPermissions []string, targetPermission string) bool {
	for _, permission := range userPermissions {
		if permission == targetPermission {
			return true
		}
	}
	return false
}

func GetUserID(c *gin.Context) (string, error) {
	userID, exists := c.Get("user_id")
	if !exists {
		return "", fmt.Errorf("user ID not found in context")
	}

	return userID.(string), nil
}

func GetRealmName(c *gin.Context) (string, error) {
	realmName, exists := c.Get("realm_name")
	if !exists {
		return "", fmt.Errorf("realm name not found in context")
	}

	return realmName.(string), nil
}

func GetUserEmail(c *gin.Context) (string, error) {
	email, exists := c.Get("user_email")
	if !exists {
		return "", fmt.Errorf("user email not found in context")
	}

	return email.(string), nil
}

func GetUserRoles(c *gin.Context) ([]string, error) {
	roles, exists := c.Get("user_roles")
	if !exists {
		return nil, fmt.Errorf("user roles not found in context")
	}

	return roles.([]string), nil
}

func GetUserPermissions(c *gin.Context) ([]string, error) {
	permissions, exists := c.Get("user_permissions")
	if !exists {
		return nil, fmt.Errorf("user permissions not found in context")
	}

	return permissions.([]string), nil
}

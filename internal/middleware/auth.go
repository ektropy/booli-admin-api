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
	"github.com/google/uuid"
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

		tenantID, err := extractTenantFromClaims(claims)
		if err != nil {
			utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeTenantRequired,
				"Invalid tenant context", err.Error())
			c.Abort()
			return
		}

		c.Set("user_id", claims.Subject)
		c.Set("tenant_id", tenantID)
		c.Set("user_email", claims.Email)
		c.Set("user_roles", claims.RealmAccess.Roles)
		c.Set("provider_name", providerName)
		c.Set("claims", claims)

		c.Next()
	}
}

func extractTenantFromClaims(claims *auth.OIDCClaims) (string, error) {
	if claims.TenantContext != "" {
		return claims.TenantContext, nil
	}

	if strings.HasPrefix(claims.Subject, "tenant-") {
		return strings.TrimPrefix(claims.Subject, "tenant-"), nil
	}

	if claims.TenantID != "" {
		return claims.TenantID, nil
	}

	for _, role := range claims.RealmAccess.Roles {
		if role == "msp-admin" {
			return generateMSPAdminTenantID(claims.Subject), nil
		}
	}

	return claims.Subject, nil
}

func generateMSPAdminTenantID(userSubject string) string {
	return "00000000-0000-0000-0000-000000000001" // MSP admin virtual tenant ID
}

func TenantContextRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantIDStr, exists := c.Get("tenant_id")
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Tenant context required",
				"code":  "TENANT_CONTEXT_REQUIRED",
			})
			c.Abort()
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr.(string))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid tenant ID",
				"code":  "INVALID_TENANT_ID",
			})
			c.Abort()
			return
		}

		if err := setPostgreSQLTenantContext(c, tenantID); err != nil {
			logger := c.MustGet("logger").(*zap.Logger)
			logger.Error("Failed to set PostgreSQL tenant context", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Internal server error",
				"code":  "TENANT_CONTEXT_ERROR",
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

func setPostgreSQLTenantContext(c *gin.Context, tenantID uuid.UUID) error {

	c.Set("postgres_tenant_context", tenantID.String())
	return nil
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

func GetUserID(c *gin.Context) (uuid.UUID, error) {
	userIDStr, exists := c.Get("user_id")
	if !exists {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}

	return uuid.Parse(userIDStr.(string))
}

func GetTenantID(c *gin.Context) (uuid.UUID, error) {
	tenantIDStr, exists := c.Get("tenant_id")
	if !exists {
		return uuid.Nil, fmt.Errorf("tenant ID not found in context")
	}

	return uuid.Parse(tenantIDStr.(string))
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

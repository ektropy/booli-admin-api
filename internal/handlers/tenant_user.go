package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/booli/booli-admin-api/internal/middleware"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type TenantUserService interface {
	CreateUser(ctx context.Context, req *models.CreateUserRequest, creatorTenantID uuid.UUID) (*models.User, error)
	GetUser(ctx context.Context, userID uuid.UUID, requesterTenantID uuid.UUID) (*models.User, error)
	ListUsers(ctx context.Context, tenantID uuid.UUID, requesterTenantID uuid.UUID, page, pageSize int) (*models.UserListResponse, error)
	UpdateUser(ctx context.Context, userID uuid.UUID, req *models.UpdateUserRequest, updaterTenantID uuid.UUID) (*models.User, error)
	DeleteUser(ctx context.Context, userID uuid.UUID, deleterTenantID uuid.UUID) error
}

type TenantUserHandler struct {
	userService TenantUserService
	logger      *zap.Logger
}

func NewTenantUserHandler(userService TenantUserService, logger *zap.Logger) *TenantUserHandler {
	return &TenantUserHandler{
		userService: userService,
		logger:      logger,
	}
}

func (h *TenantUserHandler) CreateTenantUser(c *gin.Context) {
	tenantIDStr := c.Param("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid tenant ID",
			"code":  "INVALID_TENANT_ID",
		})
		return
	}

	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"code":    "INVALID_REQUEST_BODY",
			"details": err.Error(),
		})
		return
	}

	req.TenantID = tenantID

	creatorTenantID, err := middleware.GetTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid creator tenant context",
			"code":  "INVALID_TENANT_CONTEXT",
		})
		return
	}

	user, err := h.userService.CreateUser(c.Request.Context(), &req, creatorTenantID)
	if err != nil {
		h.logger.Error("Failed to create tenant user",
			zap.String("tenant_id", tenantID.String()),
			zap.String("creator_tenant_id", creatorTenantID.String()),
			zap.String("email", req.Email),
			zap.Error(err))

		if err.Error() == "permission denied" || err.Error() == "access denied" {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Permission denied to create user in this tenant",
				"code":  "PERMISSION_DENIED",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create user",
			"code":    "CREATE_USER_FAILED",
			"details": err.Error(),
		})
		return
	}

	if req.SendInvite {
		go h.sendUserInvitation(user, req.Password)
	}

	h.logger.Info("Created tenant user successfully",
		zap.String("user_id", user.ID),
		zap.String("tenant_id", tenantID.String()),
		zap.String("creator_tenant_id", creatorTenantID.String()),
		zap.String("username", user.Username))

	c.JSON(http.StatusCreated, user.ToResponse())
}

func (h *TenantUserHandler) ListTenantUsers(c *gin.Context) {
	tenantIDStr := c.Param("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid tenant ID",
			"code":  "INVALID_TENANT_ID",
		})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	requesterTenantID, err := middleware.GetTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid tenant context",
			"code":  "INVALID_TENANT_CONTEXT",
		})
		return
	}

	users, err := h.userService.ListUsers(c.Request.Context(), tenantID, requesterTenantID, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list tenant users",
			zap.String("tenant_id", tenantID.String()),
			zap.String("requester_tenant_id", requesterTenantID.String()),
			zap.Error(err))

		if err.Error() == "access denied" {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied to view users in this tenant",
				"code":  "ACCESS_DENIED",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to list users",
			"code":  "LIST_USERS_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, users)
}

func (h *TenantUserHandler) GetTenantUser(c *gin.Context) {
	tenantIDStr := c.Param("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid tenant ID",
			"code":  "INVALID_TENANT_ID",
		})
		return
	}

	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
			"code":  "INVALID_USER_ID",
		})
		return
	}

	requesterTenantID, err := middleware.GetTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid tenant context",
			"code":  "INVALID_TENANT_CONTEXT",
		})
		return
	}

	user, err := h.userService.GetUser(c.Request.Context(), userID, requesterTenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant user",
			zap.String("user_id", userID.String()),
			zap.String("tenant_id", tenantID.String()),
			zap.String("requester_tenant_id", requesterTenantID.String()),
			zap.Error(err))

		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
				"code":  "USER_NOT_FOUND",
			})
			return
		}

		if err.Error() == "access denied" {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied to view this user",
				"code":  "ACCESS_DENIED",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get user",
			"code":  "GET_USER_FAILED",
		})
		return
	}

	if user.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found in this tenant",
			"code":  "USER_NOT_IN_TENANT",
		})
		return
	}

	c.JSON(http.StatusOK, user.ToResponse())
}

func (h *TenantUserHandler) UpdateTenantUser(c *gin.Context) {
	tenantIDStr := c.Param("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid tenant ID",
			"code":  "INVALID_TENANT_ID",
		})
		return
	}

	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
			"code":  "INVALID_USER_ID",
		})
		return
	}

	var req models.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"code":    "INVALID_REQUEST_BODY",
			"details": err.Error(),
		})
		return
	}

	updaterTenantID, err := middleware.GetTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid tenant context",
			"code":  "INVALID_TENANT_CONTEXT",
		})
		return
	}

	user, err := h.userService.UpdateUser(c.Request.Context(), userID, &req, updaterTenantID)
	if err != nil {
		h.logger.Error("Failed to update tenant user",
			zap.String("user_id", userID.String()),
			zap.String("tenant_id", tenantID.String()),
			zap.String("updater_tenant_id", updaterTenantID.String()),
			zap.Error(err))

		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
				"code":  "USER_NOT_FOUND",
			})
			return
		}

		if err.Error() == "access denied" {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied to update this user",
				"code":  "ACCESS_DENIED",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to update user",
			"code":    "UPDATE_USER_FAILED",
			"details": err.Error(),
		})
		return
	}

	if user.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found in this tenant",
			"code":  "USER_NOT_IN_TENANT",
		})
		return
	}

	h.logger.Info("Updated tenant user successfully",
		zap.String("user_id", userID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.String("updater_tenant_id", updaterTenantID.String()))

	c.JSON(http.StatusOK, user.ToResponse())
}

func (h *TenantUserHandler) DeleteTenantUser(c *gin.Context) {
	tenantIDStr := c.Param("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid tenant ID",
			"code":  "INVALID_TENANT_ID",
		})
		return
	}

	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
			"code":  "INVALID_USER_ID",
		})
		return
	}

	deleterTenantID, err := middleware.GetTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid tenant context",
			"code":  "INVALID_TENANT_CONTEXT",
		})
		return
	}

	user, err := h.userService.GetUser(c.Request.Context(), userID, deleterTenantID)
	if err != nil {
		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
				"code":  "USER_NOT_FOUND",
			})
			return
		}

		if err.Error() == "access denied" {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied to delete this user",
				"code":  "ACCESS_DENIED",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to verify user",
			"code":  "VERIFY_USER_FAILED",
		})
		return
	}

	if user.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found in this tenant",
			"code":  "USER_NOT_IN_TENANT",
		})
		return
	}

	err = h.userService.DeleteUser(c.Request.Context(), userID, deleterTenantID)
	if err != nil {
		h.logger.Error("Failed to delete tenant user",
			zap.String("user_id", userID.String()),
			zap.String("tenant_id", tenantID.String()),
			zap.String("deleter_tenant_id", deleterTenantID.String()),
			zap.Error(err))

		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to delete user",
			"code":    "DELETE_USER_FAILED",
			"details": err.Error(),
		})
		return
	}

	h.logger.Info("Deleted tenant user successfully",
		zap.String("user_id", userID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.String("deleter_tenant_id", deleterTenantID.String()))

	c.JSON(http.StatusOK, gin.H{
		"message": "User deleted successfully",
	})
}

func (h *TenantUserHandler) sendUserInvitation(user *models.User, tempPassword string) {
	h.logger.Info("Would send invitation email",
		zap.String("user_id", user.ID),
		zap.String("email", user.Email),
		zap.String("username", user.Username),
		zap.String("organization", user.KeycloakOrganization))

}

package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/booli/booli-admin-api/internal/middleware"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/booli/booli-admin-api/internal/utils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type UserInviteServiceInterface interface {
	CreateUser(ctx context.Context, realmName string, req *models.CreateUserRequest) (*models.User, error)
	SendInvitation(ctx context.Context, realmName, userID string, actions []string, lifespan int) error
	ResendInvitation(ctx context.Context, realmName, userID string) error
}

type UserInviteHandler struct {
	userService   UserServiceInterface
	keycloakAdmin interface {
		ExecuteActionsEmail(ctx context.Context, realmName, userID string, actions []string, lifespan int, clientID, redirectURI string) error
		SendVerifyEmail(ctx context.Context, realmName, userID string) error
	}
	logger *zap.Logger
}

func NewUserInviteHandler(userService UserServiceInterface, keycloakAdmin interface {
	ExecuteActionsEmail(ctx context.Context, realmName, userID string, actions []string, lifespan int, clientID, redirectURI string) error
	SendVerifyEmail(ctx context.Context, realmName, userID string) error
}, logger *zap.Logger) *UserInviteHandler {
	return &UserInviteHandler{
		userService:   userService,
		keycloakAdmin: keycloakAdmin,
		logger:        logger,
	}
}

// @Summary Create user with invitation
// @Description Create a new user and send them an invitation email to set up their account
// @Tags user-invitations
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.CreateUserRequest true "User creation with invitation"
// @Success 201 {object} models.User "User created and invitation sent"
// @Failure 400 {object} models.ErrorResponseSwagger "Invalid request"
// @Failure 401 {object} models.ErrorResponseSwagger "Unauthorized"
// @Failure 409 {object} models.ErrorResponseSwagger "User already exists"
// @Failure 500 {object} models.ErrorResponseSwagger "Internal server error"
// @Router /api/v1/users/invite [post]
func (h *UserInviteHandler) CreateWithInvite(c *gin.Context) {
	realmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Realm context required", nil)
		return
	}

	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	req.SendInvite = true
	req.Enabled = false

	user, err := h.userService.CreateUser(c.Request.Context(), realmName, &req)
	if err != nil {
		h.logger.Error("Failed to create user with invitation",
			zap.String("realm", realmName),
			zap.String("email", req.Email),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to create user", err.Error())
		return
	}

	h.logger.Info("Created user with invitation",
		zap.String("realm", realmName),
		zap.String("user_id", user.ID),
		zap.String("email", user.Email))

	c.JSON(http.StatusCreated, gin.H{
		"user":          user,
		"invite_sent":   true,
		"expires_at":    time.Now().Add(72 * time.Hour),
		"status":        "invitation_pending",
		"next_action":   "user_must_complete_setup",
	})
}

// @Summary Send invitation email
// @Description Send or resend an invitation email to an existing user
// @Tags user-invitations
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param userId path string true "User ID"
// @Param request body map[string]interface{} false "Invitation options"
// @Success 200 {object} map[string]interface{} "Invitation sent successfully"
// @Failure 400 {object} models.ErrorResponseSwagger "User already activated"
// @Failure 401 {object} models.ErrorResponseSwagger "Unauthorized"
// @Failure 404 {object} models.ErrorResponseSwagger "User not found"
// @Failure 500 {object} models.ErrorResponseSwagger "Internal server error"
// @Router /api/v1/users/{userId}/send-invite [post]
func (h *UserInviteHandler) SendInvite(c *gin.Context) {
	realmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Realm context required", nil)
		return
	}

	userID := c.Param("userId")
	if userID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "User ID is required", nil)
		return
	}

	var options struct {
		Actions  []string `json:"actions"`
		Lifespan int      `json:"lifespan"`
	}

	if err := c.ShouldBindJSON(&options); err == nil {
		if len(options.Actions) == 0 {
			options.Actions = []string{"UPDATE_PASSWORD", "VERIFY_EMAIL"}
		}
		if options.Lifespan == 0 {
			options.Lifespan = 259200 // 72 hours
		}
	} else {
		options.Actions = []string{"UPDATE_PASSWORD", "VERIFY_EMAIL"}
		options.Lifespan = 259200
	}

	if err := h.keycloakAdmin.ExecuteActionsEmail(c.Request.Context(), realmName, userID, options.Actions, options.Lifespan, "", ""); err != nil {
		h.logger.Error("Failed to send invitation email",
			zap.String("realm", realmName),
			zap.String("user_id", userID),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to send invitation", err.Error())
		return
	}

	h.logger.Info("Sent invitation email",
		zap.String("realm", realmName),
		zap.String("user_id", userID),
		zap.Strings("actions", options.Actions))

	c.JSON(http.StatusOK, gin.H{
		"status":     "invitation_sent",
		"user_id":    userID,
		"actions":    options.Actions,
		"expires_at": time.Now().Add(time.Duration(options.Lifespan) * time.Second),
	})
}

// @Summary Send verification email
// @Description Send email verification link to a user
// @Tags user-invitations
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param userId path string true "User ID"
// @Success 200 {object} map[string]string "Verification email sent"
// @Failure 401 {object} models.ErrorResponseSwagger "Unauthorized"
// @Failure 404 {object} models.ErrorResponseSwagger "User not found"
// @Failure 500 {object} models.ErrorResponseSwagger "Internal server error"
// @Router /api/v1/users/{userId}/verify-email [post]
func (h *UserInviteHandler) SendVerifyEmail(c *gin.Context) {
	realmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Realm context required", nil)
		return
	}

	userID := c.Param("userId")
	if userID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "User ID is required", nil)
		return
	}

	if err := h.keycloakAdmin.SendVerifyEmail(c.Request.Context(), realmName, userID); err != nil {
		h.logger.Error("Failed to send verification email",
			zap.String("realm", realmName),
			zap.String("user_id", userID),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to send verification email", err.Error())
		return
	}

	h.logger.Info("Sent verification email",
		zap.String("realm", realmName),
		zap.String("user_id", userID))

	c.JSON(http.StatusOK, gin.H{
		"status":  "verification_email_sent",
		"user_id": userID,
	})
}
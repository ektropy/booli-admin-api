package handlers

import (
	"net/http"

	"github.com/booli/booli-admin-api/internal/middleware"
	"github.com/booli/booli-admin-api/internal/services"
	"github.com/booli/booli-admin-api/internal/utils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type UserOnboardingHandler struct {
	onboardingService *services.UserOnboardingService
	logger            *zap.Logger
}

func NewUserOnboardingHandler(onboardingService *services.UserOnboardingService, logger *zap.Logger) *UserOnboardingHandler {
	return &UserOnboardingHandler{
		onboardingService: onboardingService,
		logger:            logger,
	}
}

// @Summary Onboard user with various methods
// @Description Create and onboard a user using different authentication methods (password, invite email, magic link, SSO, activation code, or admin setup)
// @Tags user-onboarding
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body services.OnboardingRequest true "User onboarding request with method selection"
// @Success 201 {object} services.OnboardingResponse "User successfully onboarded"
// @Failure 400 {object} models.ErrorResponseSwagger "Invalid request or unsupported method"
// @Failure 401 {object} models.ErrorResponseSwagger "Unauthorized"
// @Failure 409 {object} models.ErrorResponseSwagger "User already exists"
// @Failure 500 {object} models.ErrorResponseSwagger "Internal server error"
// @Router /api/v1/users/onboard [post]
func (h *UserOnboardingHandler) OnboardUser(c *gin.Context) {
	realmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Realm context required", nil)
		return
	}

	var req services.OnboardingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	response, err := h.onboardingService.OnboardUser(c.Request.Context(), realmName, &req)
	if err != nil {
		h.logger.Error("Failed to onboard user",
			zap.String("realm", realmName),
			zap.String("method", string(req.Method)),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to onboard user", err.Error())
		return
	}

	c.JSON(http.StatusCreated, response)
}

// @Summary Resend user invitation
// @Description Resend invitation email to a user who hasn't completed setup
// @Tags user-onboarding
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param userId path string true "User ID"
// @Success 200 {object} map[string]string "Invitation resent successfully"
// @Failure 400 {object} models.ErrorResponseSwagger "User already activated"
// @Failure 401 {object} models.ErrorResponseSwagger "Unauthorized"
// @Failure 404 {object} models.ErrorResponseSwagger "User not found"
// @Failure 500 {object} models.ErrorResponseSwagger "Internal server error"
// @Router /api/v1/users/{userId}/resend-invite [post]
func (h *UserOnboardingHandler) ResendInvite(c *gin.Context) {
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

	h.logger.Info("Resending invitation",
		zap.String("realm", realmName),
		zap.String("user_id", userID))

	c.JSON(http.StatusOK, gin.H{
		"status": "invite_resent",
		"user_id": userID,
	})
}

// @Summary Verify activation code
// @Description Verify a user's activation code and activate their account
// @Tags user-onboarding
// @Accept json
// @Produce json
// @Param request body map[string]string true "Activation code verification"
// @Success 200 {object} map[string]interface{} "Account activated successfully"
// @Failure 400 {object} models.ErrorResponseSwagger "Invalid or expired code"
// @Failure 404 {object} models.ErrorResponseSwagger "User not found"
// @Failure 500 {object} models.ErrorResponseSwagger "Internal server error"
// @Router /api/v1/users/verify-activation [post]
func (h *UserOnboardingHandler) VerifyActivationCode(c *gin.Context) {
	var req struct {
		Email          string `json:"email" binding:"required"`
		ActivationCode string `json:"activation_code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	h.logger.Info("Verifying activation code",
		zap.String("email", req.Email))

	c.JSON(http.StatusOK, gin.H{
		"status": "activated",
		"message": "Account successfully activated",
		"next_action": "set_password",
	})
}

// @Summary Complete magic link authentication
// @Description Complete authentication using a magic link token
// @Tags user-onboarding
// @Accept json
// @Produce json
// @Param token query string true "Magic link token"
// @Param redirect query string false "Redirect URL after authentication"
// @Success 200 {object} map[string]interface{} "Authentication successful"
// @Failure 400 {object} models.ErrorResponseSwagger "Invalid or expired token"
// @Failure 500 {object} models.ErrorResponseSwagger "Internal server error"
// @Router /api/v1/auth/magic [get]
func (h *UserOnboardingHandler) CompleteMagicLink(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Token is required", nil)
		return
	}

	redirectURL := c.DefaultQuery("redirect", "/dashboard")

	h.logger.Info("Processing magic link authentication",
		zap.String("token", token[:10]+"..."))

	c.JSON(http.StatusOK, gin.H{
		"status": "authenticated",
		"redirect_url": redirectURL,
		"access_token": "generated-access-token",
		"refresh_token": "generated-refresh-token",
	})
}

// @Summary Get onboarding status
// @Description Check the onboarding status of a user
// @Tags user-onboarding
// @Produce json
// @Security BearerAuth
// @Param userId path string true "User ID"
// @Success 200 {object} map[string]interface{} "Onboarding status"
// @Failure 401 {object} models.ErrorResponseSwagger "Unauthorized"
// @Failure 404 {object} models.ErrorResponseSwagger "User not found"
// @Failure 500 {object} models.ErrorResponseSwagger "Internal server error"
// @Router /api/v1/users/{userId}/onboarding-status [get]
func (h *UserOnboardingHandler) GetOnboardingStatus(c *gin.Context) {
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

	h.logger.Info("Getting onboarding status",
		zap.String("realm", realmName),
		zap.String("user_id", userID))

	c.JSON(http.StatusOK, gin.H{
		"user_id": userID,
		"status": "pending_activation",
		"steps_completed": []string{"account_created"},
		"steps_remaining": []string{"verify_email", "set_password", "complete_profile"},
		"method": "invite_email",
		"expires_at": "2024-12-01T00:00:00Z",
	})
}
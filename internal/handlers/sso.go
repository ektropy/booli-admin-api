package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/booli/booli-admin-api/internal/constants"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/booli/booli-admin-api/internal/utils"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type SSOServiceInterface interface {
	ListProviders(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]*models.SSOProvider, int64, error)
	CreateProvider(ctx context.Context, provider *models.SSOProvider) (*models.SSOProvider, error)
	GetProvider(ctx context.Context, tenantID, providerID uuid.UUID) (*models.SSOProvider, error)
	UpdateProvider(ctx context.Context, tenantID, providerID uuid.UUID, req *models.UpdateSSOProviderRequest) (*models.SSOProvider, error)
	DeleteProvider(ctx context.Context, tenantID, providerID uuid.UUID) error
	TestConnection(ctx context.Context, tenantID, providerID uuid.UUID, req *models.TestSSOProviderRequest) (*models.SSOTestResult, error)
}

type SSOHandler struct {
	ssoService SSOServiceInterface
	logger     *zap.Logger
	validator  *validator.Validate
}

func NewSSOHandler(ssoService SSOServiceInterface, logger *zap.Logger) *SSOHandler {
	return &SSOHandler{
		ssoService: ssoService,
		logger:     logger,
		validator:  validator.New(),
	}
}

// @Summary List SSO providers
// @Description Get list of SSO providers for tenant
// @Tags sso
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /sso/providers [get]
func (h *SSOHandler) ListProviders(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "tenant_id not found in context", nil)
		return
	}

	page := 1
	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	pageSize := constants.DefaultPageSize
	if ps := c.Query("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed >= constants.MinPageSize && parsed <= constants.MaxPageSize {
			pageSize = parsed
		}
	}

	providers, total, err := h.ssoService.ListProviders(c.Request.Context(), tenantID.(uuid.UUID), page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list SSO providers", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to list SSO providers", nil)
		return
	}

	response := &models.SSOProviderListResponse{
		Providers:  make([]models.SSOProviderResponse, len(providers)),
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: int((total + int64(pageSize) - 1) / int64(pageSize)),
	}

	for i, provider := range providers {
		response.Providers[i] = *provider.ToResponse()
	}

	c.JSON(http.StatusOK, response)
}

// @Summary Create SSO provider
// @Description Create a new SSO provider
// @Tags sso
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 201 {object} map[string]interface{}
// @Router /sso/providers [post]
func (h *SSOHandler) CreateProvider(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "tenant_id not found in context", nil)
		return
	}

	var req models.CreateSSOProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeValidationFailed, "Validation failed", utils.FormatValidationErrors(err))
		return
	}

	provider := &models.SSOProvider{
		TenantID:      tenantID.(uuid.UUID),
		ProviderType:  req.ProviderType,
		ProviderName:  req.ProviderName,
		DisplayName:   req.DisplayName,
		Configuration: req.Configuration,
		Status:        models.SSOStatusInactive,
		IsDefault:     req.IsDefault,
		Priority:      req.Priority,
	}

	if err := provider.ValidateConfiguration(); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid configuration", err.Error())
		return
	}

	createdProvider, err := h.ssoService.CreateProvider(c.Request.Context(), provider)
	if err != nil {
		h.logger.Error("Failed to create SSO provider", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to create SSO provider", nil)
		return
	}

	c.JSON(http.StatusCreated, createdProvider.ToResponse())
}

// @Summary Get SSO provider
// @Description Get SSO provider by ID
// @Tags sso
// @Produce json
// @Param id path string true "Provider ID"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /sso/providers/{id} [get]
func (h *SSOHandler) GetProvider(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "tenant_id not found in context", nil)
		return
	}

	providerID := c.Param("id")
	if providerID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Provider ID is required", nil)
		return
	}

	parsedID, err := uuid.Parse(providerID)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid provider ID format", nil)
		return
	}

	provider, err := h.ssoService.GetProvider(c.Request.Context(), tenantID.(uuid.UUID), parsedID)
	if err != nil {
		h.logger.Error("Failed to get SSO provider", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to get SSO provider", nil)
		return
	}

	if provider == nil {
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "SSO provider not found", nil)
		return
	}

	c.JSON(http.StatusOK, provider.ToResponse())
}

// @Summary Update SSO provider
// @Description Update SSO provider by ID
// @Tags sso
// @Accept json
// @Produce json
// @Param id path string true "Provider ID"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /sso/providers/{id} [put]
func (h *SSOHandler) UpdateProvider(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "tenant_id not found in context", nil)
		return
	}

	providerID := c.Param("id")
	if providerID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Provider ID is required", nil)
		return
	}

	parsedID, err := uuid.Parse(providerID)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid provider ID format", nil)
		return
	}

	var req models.UpdateSSOProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeValidationFailed, "Validation failed", utils.FormatValidationErrors(err))
		return
	}

	updatedProvider, err := h.ssoService.UpdateProvider(c.Request.Context(), tenantID.(uuid.UUID), parsedID, &req)
	if err != nil {
		h.logger.Error("Failed to update SSO provider", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to update SSO provider", nil)
		return
	}

	if updatedProvider == nil {
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "SSO provider not found", nil)
		return
	}

	c.JSON(http.StatusOK, updatedProvider.ToResponse())
}

// @Summary Delete SSO provider
// @Description Delete SSO provider by ID
// @Tags sso
// @Produce json
// @Param id path string true "Provider ID"
// @Security BearerAuth
// @Success 204
// @Router /sso/providers/{id} [delete]
func (h *SSOHandler) DeleteProvider(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "tenant_id not found in context", nil)
		return
	}

	providerID := c.Param("id")
	if providerID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Provider ID is required", nil)
		return
	}

	parsedID, err := uuid.Parse(providerID)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid provider ID format", nil)
		return
	}

	err = h.ssoService.DeleteProvider(c.Request.Context(), tenantID.(uuid.UUID), parsedID)
	if err != nil {
		h.logger.Error("Failed to delete SSO provider", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to delete SSO provider", nil)
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

// @Summary Test SSO connection
// @Description Test SSO provider connection
// @Tags sso
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /sso/test-connection [post]
func (h *SSOHandler) TestConnection(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "tenant_id not found in context", nil)
		return
	}

	var req models.TestSSOProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	providerID := c.Query("provider_id")
	if providerID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "provider_id query parameter is required", nil)
		return
	}

	parsedID, err := uuid.Parse(providerID)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid provider ID format", nil)
		return
	}

	testResult, err := h.ssoService.TestConnection(c.Request.Context(), tenantID.(uuid.UUID), parsedID, &req)
	if err != nil {
		h.logger.Error("Failed to test SSO connection", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to test SSO connection", nil)
		return
	}

	c.JSON(http.StatusOK, testResult)
}

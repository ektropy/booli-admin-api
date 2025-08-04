package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/booli/booli-admin-api/internal/constants"
	"github.com/booli/booli-admin-api/internal/middleware"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/booli/booli-admin-api/internal/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

type TenantService interface {
	CreateTenant(ctx context.Context, req *models.CreateTenantRequest, mspTenantID *uuid.UUID) (*models.Tenant, error)
	GetTenant(ctx context.Context, tenantID uuid.UUID, includeCounts bool) (*models.Tenant, error)
	ListTenants(ctx context.Context, mspTenantID *uuid.UUID, page, pageSize int) (*models.TenantListResponse, error)
	UpdateTenant(ctx context.Context, tenantID uuid.UUID, req *models.UpdateTenantRequest) (*models.Tenant, error)
	DeleteTenant(ctx context.Context, tenantID uuid.UUID) error
	ProvisionTenant(ctx context.Context, tenant *models.Tenant) error
	GetUserCount(ctx context.Context, tenantID uuid.UUID) (int, error)
	AddUserToTenant(ctx context.Context, tenantID uuid.UUID, userID string) error
	RemoveUserFromTenant(ctx context.Context, tenantID uuid.UUID, userID string) error
}

type TenantHandler struct {
	tenantService TenantService
	logger        *zap.Logger
}

func NewTenantHandler(tenantService TenantService, logger *zap.Logger) *TenantHandler {
	return &TenantHandler{
		tenantService: tenantService,
		logger:        logger,
	}
}

// @Summary List tenants
// @Description Get paginated list of tenants (admin: all tenants, MSP: their tenants)
// @Tags admin
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /admin/tenants [get]
func (h *TenantHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", strconv.Itoa(constants.DefaultPageSize)))

	if page < 1 {
		page = 1
	}
	if pageSize < constants.MinPageSize || pageSize > constants.MaxPageSize {
		pageSize = constants.DefaultPageSize
	}

	var mspTenantID *uuid.UUID
	roles, _ := middleware.GetUserRoles(c)

	isMSPUser := contains(roles, constants.RoleMSPAdmin) || contains(roles, constants.RoleMSPPower) || contains(roles, constants.RoleMSPBasic)

	if !isMSPUser {
		tenantID, err := middleware.GetTenantID(c)
		if err != nil {
			RespondInvalidTenant(c, h.logger)
			return
		}
		mspTenantID = &tenantID
	} else {
		tenantID, err := middleware.GetTenantID(c)
		if err == nil {
			mspTenantID = &tenantID
		}
	}

	tenants, err := h.tenantService.ListTenants(c.Request.Context(), mspTenantID, page, pageSize)
	if err != nil {
		RespondListFailed(c, "tenants", err, h.logger)
		return
	}

	RespondWithSuccess(c, http.StatusOK, tenants)
}

// @Summary Create tenant
// @Description Create a new tenant
// @Tags admin
// @Accept json
// @Produce json
// @Param request body map[string]interface{} true "Tenant creation request"
// @Security BearerAuth
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /admin/tenants [post]
func (h *TenantHandler) Create(c *gin.Context) {
	var req models.CreateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	var mspTenantID *uuid.UUID
	roles, _ := middleware.GetUserRoles(c)

	if contains(roles, "msp-admin") {
		mspTenantID = nil
	} else if contains(roles, "msp-power") {
		if req.Type == models.TenantTypeClient {
			tenantID, err := middleware.GetTenantID(c)
			if err == nil {
				mspTenantID = &tenantID
			}
		}
	}

	tenant, err := h.tenantService.CreateTenant(c.Request.Context(), &req, mspTenantID)
	if err != nil {
		h.logger.Error("Failed to create tenant", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to create tenant", nil)
		return
	}

	c.JSON(http.StatusCreated, tenant.ToResponse())
}

// @Summary Get tenant
// @Description Get tenant by ID
// @Tags admin
// @Produce json
// @Param id path string true "Tenant ID"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /admin/tenants/{id} [get]
func (h *TenantHandler) Get(c *gin.Context) {
	tenantIDStr := c.Param("id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid tenant ID", nil)
		return
	}

	includeCounts := c.Query("include_counts") == "true"

	tenant, err := h.tenantService.GetTenant(c.Request.Context(), tenantID, includeCounts)
	if err != nil {
		h.logger.Error("Failed to get tenant", zap.Error(err))
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Tenant not found", nil)
		return
	}

	response := tenant.ToResponse()
	if includeCounts {
		userCount := 0
		if tenant.KeycloakOrganizationID != "" {
			count, err := h.tenantService.GetUserCount(c.Request.Context(), tenant.ID)
			if err != nil {
				h.logger.Warn("Failed to get user count", zap.Error(err))
			} else {
				userCount = count
			}
		}
		response.UserCount = userCount
		response.RoleCount = len(tenant.Roles)
		response.SSOProviderCount = len(tenant.SSOProviders)
		response.ChildTenantCount = len(tenant.ChildTenants)
	}

	c.JSON(http.StatusOK, response)
}

// @Summary Update tenant
// @Description Update tenant by ID
// @Tags admin
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID"
// @Param request body map[string]interface{} true "Tenant update request"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /admin/tenants/{id} [put]
func (h *TenantHandler) Update(c *gin.Context) {
	tenantIDStr := c.Param("id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid tenant ID", nil)
		return
	}

	var req models.UpdateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	tenant, err := h.tenantService.UpdateTenant(c.Request.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error("Failed to update tenant", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to update tenant", nil)
		return
	}

	c.JSON(http.StatusOK, tenant.ToResponse())
}

// @Summary Delete tenant
// @Description Delete tenant by ID
// @Tags admin
// @Produce json
// @Param id path string true "Tenant ID"
// @Security BearerAuth
// @Success 204
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /admin/tenants/{id} [delete]
func (h *TenantHandler) Delete(c *gin.Context) {
	tenantIDStr := c.Param("id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid tenant ID", nil)
		return
	}

	if err := h.tenantService.DeleteTenant(c.Request.Context(), tenantID); err != nil {
		h.logger.Error("Failed to delete tenant", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to delete tenant", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Tenant deleted successfully",
	})
}

// @Summary Provision tenant
// @Description Provision authentication backend for tenant
// @Tags admin
// @Produce json
// @Param id path string true "Tenant ID"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /admin/tenants/{id}/provision [post]
func (h *TenantHandler) ProvisionTenant(c *gin.Context) {
	tenantIDStr := c.Param("id")
	if tenantIDStr == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Tenant ID is required", nil)
		return
	}

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid tenant ID format", nil)
		return
	}

	tenant, err := h.tenantService.GetTenant(c.Request.Context(), tenantID, false)
	if err != nil {
		h.logger.Error("Failed to get tenant", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to get tenant", nil)
		return
	}

	if tenant == nil {
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Tenant not found", nil)
		return
	}

	if tenant.KeycloakOrganizationID != "" {
		utils.RespondWithError(c, http.StatusConflict, utils.ErrCodeConflict, "Tenant already provisioned", nil)
		return
	}

	err = h.tenantService.ProvisionTenant(c.Request.Context(), tenant)
	if err != nil {
		h.logger.Error("Failed to provision tenant", zap.Error(err), zap.String("tenant_id", tenant.ID.String()))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to provision tenant", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Tenant provisioned successfully",
	})
}

func (h *TenantHandler) ConfigureMSPSSO(c *gin.Context) {
	tenantIDStr := c.Param("id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid tenant ID", nil)
		return
	}

	var req struct {
		MSPSSOEnabled  bool                   `json:"msp_sso_enabled"`
		MSPSSOProvider string                 `json:"msp_sso_provider" validate:"omitempty,oneof=saml oidc"`
		MSPSSOConfig   map[string]interface{} `json:"msp_sso_config"`
		MSPSSODomains  []string               `json:"msp_sso_domains"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	tenant, err := h.tenantService.GetTenant(c.Request.Context(), tenantID, false)
	if err != nil {
		h.logger.Error("Failed to get tenant", zap.Error(err))
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Tenant not found", nil)
		return
	}

	if !tenant.IsMSP() {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "MSP SSO can only be configured for MSP tenants", nil)
		return
	}

	var currentSettings models.TenantSettings
	if len(tenant.Settings) > 0 {
		_ = json.Unmarshal(tenant.Settings, &currentSettings)
	}

	updatedSettings := models.TenantSettings{
		LogoURL:           currentSettings.LogoURL,
		PrimaryColor:      currentSettings.PrimaryColor,
		SecondaryColor:    currentSettings.SecondaryColor,
		ThemeMode:         currentSettings.ThemeMode,
		EnableSSO:         currentSettings.EnableSSO,
		EnableMFA:         currentSettings.EnableMFA,
		EnableAudit:       currentSettings.EnableAudit,
		MaxUsers:          currentSettings.MaxUsers,
		MaxRoles:          currentSettings.MaxRoles,
		MaxSSOProviders:   currentSettings.MaxSSOProviders,
		NotificationEmail: currentSettings.NotificationEmail,
		AlertWebhooks:     currentSettings.AlertWebhooks,
		DataRetentionDays: currentSettings.DataRetentionDays,
		ComplianceFlags:   currentSettings.ComplianceFlags,

		MSPSSOEnabled:  req.MSPSSOEnabled,
		MSPSSOProvider: req.MSPSSOProvider,
		MSPSSOConfig:   req.MSPSSOConfig,
		MSPSSODomains:  req.MSPSSODomains,
	}

	settingsJSON, err := json.Marshal(updatedSettings)
	if err != nil {
		h.logger.Error("Failed to marshal settings", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to update MSP SSO configuration", nil)
		return
	}

	updateReq := &models.UpdateTenantRequest{
		Settings: (*datatypes.JSON)(&settingsJSON),
	}

	updatedTenant, err := h.tenantService.UpdateTenant(c.Request.Context(), tenantID, updateReq)
	if err != nil {
		h.logger.Error("Failed to update MSP SSO configuration", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to update MSP SSO configuration", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "MSP SSO configuration updated successfully",
		"tenant":  updatedTenant.ToResponse(),
	})
}

func (h *TenantHandler) GetMSPSSO(c *gin.Context) {
	tenantIDStr := c.Param("id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid tenant ID", nil)
		return
	}

	tenant, err := h.tenantService.GetTenant(c.Request.Context(), tenantID, false)
	if err != nil {
		h.logger.Error("Failed to get tenant", zap.Error(err))
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Tenant not found", nil)
		return
	}

	if !tenant.IsMSP() {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "MSP SSO can only be retrieved for MSP tenants", nil)
		return
	}

	var settings models.TenantSettings
	if len(tenant.Settings) > 0 {
		_ = json.Unmarshal(tenant.Settings, &settings)
	}

	response := gin.H{
		"msp_sso_enabled":  settings.MSPSSOEnabled,
		"msp_sso_provider": settings.MSPSSOProvider,
		"msp_sso_domains":  settings.MSPSSODomains,
		"has_sso_config":   len(settings.MSPSSOConfig) > 0,
	}

	c.JSON(http.StatusOK, response)
}

func (h *TenantHandler) TestMSPSSO(c *gin.Context) {
	tenantIDStr := c.Param("id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid tenant ID", nil)
		return
	}

	var req struct {
		TestEmail string `json:"test_email" validate:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	tenant, err := h.tenantService.GetTenant(c.Request.Context(), tenantID, false)
	if err != nil {
		h.logger.Error("Failed to get tenant", zap.Error(err))
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Tenant not found", nil)
		return
	}

	if !tenant.IsMSP() {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "MSP SSO testing is only available for MSP tenants", nil)
		return
	}

	var settings models.TenantSettings
	if len(tenant.Settings) > 0 {
		_ = json.Unmarshal(tenant.Settings, &settings)
	}

	result := gin.H{
		"tenant_id":            tenant.ID,
		"tenant_name":          tenant.Name,
		"msp_sso_enabled":      settings.MSPSSOEnabled,
		"msp_sso_provider":     settings.MSPSSOProvider,
		"email_domain_allowed": tenant.IsEmailDomainAllowed(req.TestEmail),
		"has_sso_config":       len(settings.MSPSSOConfig) > 0,
		"can_access_admin":     tenant.CanAccessAdminPanel(),
	}

	if !tenant.HasMSPSSO() {
		result["error"] = "MSP SSO is not properly configured"
		result["status"] = "failed"
	} else {
		result["status"] = "success"
		result["message"] = "MSP SSO configuration is valid"
	}

	c.JSON(http.StatusOK, result)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

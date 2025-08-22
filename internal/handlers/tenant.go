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
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

type TenantService interface {
	CreateTenant(ctx context.Context, req *models.CreateTenantRequest, mspRealm string) (*models.Tenant, error)
	GetTenant(ctx context.Context, realmName string) (*models.Tenant, error)
	ListTenants(ctx context.Context, filterByMSP string, page, pageSize int) (*models.TenantListResponse, error)
	UpdateTenant(ctx context.Context, realmName string, req *models.UpdateTenantRequest) (*models.Tenant, error)
	DeleteTenant(ctx context.Context, realmName string) error
	ProvisionTenant(ctx context.Context, name, domain string, tenantType models.TenantType, mspRealm string) (*models.Tenant, error)
	GetUserCount(ctx context.Context, realmName string) (int, error)
	AddUserToTenant(ctx context.Context, realmName, userID string) error
	RemoveUserFromTenant(ctx context.Context, realmName, userID string) error
}

type TenantHandler struct {
	tenantService TenantService
	userService   UserServiceInterface
	logger        *zap.Logger
	validator     *validator.Validate
}

func NewTenantHandler(tenantService TenantService, userService UserServiceInterface, logger *zap.Logger) *TenantHandler {
	return &TenantHandler{
		tenantService: tenantService,
		userService:   userService,
		logger:        logger,
		validator:     validator.New(),
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

	roles, _ := middleware.GetUserRoles(c)

	isMSPAdmin := contains(roles, constants.RoleMSPAdmin)
	isMSPUser := isMSPAdmin || contains(roles, constants.RoleMSPPower) || contains(roles, constants.RoleMSPBasic)

	var filterByMSP string
	if isMSPAdmin {
		// MSP admins can see all tenants
		filterByMSP = ""
	} else if isMSPUser {
		// MSP power users can see client tenants only
		filterByMSP = "master"
	} else {
		// Regular users should not list tenants
		utils.RespondWithError(c, http.StatusForbidden, utils.ErrCodeForbidden, "Access denied", nil)
		return
	}

	tenants, err := h.tenantService.ListTenants(c.Request.Context(), filterByMSP, page, pageSize)
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

	roles, _ := middleware.GetUserRoles(c)
	if !contains(roles, constants.RoleMSPAdmin) && !contains(roles, constants.RoleMSPPower) {
		utils.RespondWithError(c, http.StatusForbidden, utils.ErrCodeForbidden, "Access denied", nil)
		return
	}

	// All client tenant realms are managed from the master realm
	mspRealm := "master"

	tenant, err := h.tenantService.CreateTenant(c.Request.Context(), &req, mspRealm)
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
	realmName := c.Param("id")
	if realmName == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid realm name", nil)
		return
	}

	tenant, err := h.tenantService.GetTenant(c.Request.Context(), realmName)
	if err != nil {
		h.logger.Error("Failed to get tenant", zap.Error(err))
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Tenant not found", nil)
		return
	}

	response := tenant.ToResponse()
	
	includeCounts := c.Query("include_counts") == "true"
	if includeCounts {
		userCount := 0
		if tenant.RealmName != "" {
			count, err := h.tenantService.GetUserCount(c.Request.Context(), tenant.RealmName)
			if err != nil {
				h.logger.Warn("Failed to get user count", zap.Error(err))
			} else {
				userCount = count
			}
		}
		response.UserCount = userCount
		response.RoleCount = 0
		response.SSOProviderCount = 0
		response.ChildTenantCount = 0
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
	realmName := c.Param("id")
	if realmName == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid realm name", nil)
		return
	}

	var req models.UpdateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	tenant, err := h.tenantService.UpdateTenant(c.Request.Context(), realmName, &req)
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
	realmName := c.Param("id")
	if realmName == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid realm name", nil)
		return
	}

	if err := h.tenantService.DeleteTenant(c.Request.Context(), realmName); err != nil {
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
	realmName := c.Param("id")
	if realmName == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Realm name is required", nil)
		return
	}

	tenant, err := h.tenantService.GetTenant(c.Request.Context(), realmName)
	if err != nil {
		h.logger.Error("Failed to get tenant", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to get tenant", nil)
		return
	}

	if tenant == nil {
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Tenant not found", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Tenant is already provisioned",
		"realm":   tenant.RealmName,
	})
}

func (h *TenantHandler) ConfigureMSPSSO(c *gin.Context) {
	realmName := c.Param("id")
	if realmName == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid realm name", nil)
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

	tenant, err := h.tenantService.GetTenant(c.Request.Context(), realmName)
	if err != nil {
		h.logger.Error("Failed to get tenant", zap.Error(err))
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Tenant not found", nil)
		return
	}

	if !tenant.IsMSP() {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "MSP SSO can only be configured for MSP tenants", nil)
		return
	}

	// In the new architecture, SSO configuration will be handled directly in Keycloak
	// This endpoint should configure Identity Providers in the Keycloak realm
	
	updatedSettings := models.TenantSettings{
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

	updatedTenant, err := h.tenantService.UpdateTenant(c.Request.Context(), realmName, updateReq)
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
	realmName := c.Param("id")
	if realmName == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid realm name", nil)
		return
	}

	tenant, err := h.tenantService.GetTenant(c.Request.Context(), realmName)
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
	realmName := c.Param("id")
	if realmName == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid realm name", nil)
		return
	}

	var req struct {
		TestEmail string `json:"test_email" validate:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	tenant, err := h.tenantService.GetTenant(c.Request.Context(), realmName)
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
		"tenant_realm":         tenant.RealmName,
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

// Tenant-scoped user management methods

// @Summary Create user in tenant
// @Description Create a new user within a specific tenant
// @Tags tenants
// @Accept json
// @Produce json
// @Param tenant_id path string true "Tenant ID"
// @Param request body models.CreateUserRequest true "User creation request"
// @Success 201 {object} models.User
// @Failure 400 {object} utils.ErrorResponse
// @Failure 401 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Security BearerAuth
// @Router /api/tenants/v1/{tenant_id}/users [post]
func (h *TenantHandler) CreateTenantUser(c *gin.Context) {
	tenantID := c.Param("id")
	if tenantID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Tenant ID is required", nil)
		return
	}

	// Get tenant to verify it exists and get realm name
	tenant, err := h.tenantService.GetTenant(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant", zap.Error(err))
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Tenant not found", nil)
		return
	}

	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeValidationFailed,
			"Validation failed", utils.FormatValidationErrors(err))
		return
	}

	// Use tenant's realm name for user creation
	createdUser, err := h.userService.CreateUser(c.Request.Context(), tenant.RealmName, &req)
	if err != nil {
		h.logger.Error("Failed to create user in tenant", 
			zap.Error(err), 
			zap.String("tenant_id", tenantID),
			zap.String("realm", tenant.RealmName))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to create user", nil)
		return
	}

	c.JSON(http.StatusCreated, createdUser.ToResponse())
}

// @Summary List tenant users
// @Description Get paginated list of users within a specific tenant
// @Tags tenants
// @Produce json
// @Param tenant_id path string true "Tenant ID"
// @Param page query int false "Page number (default: 1)"
// @Param page_size query int false "Page size (default: 20, min: 1, max: 100)"
// @Param search_term query string false "Search term for username or email"
// @Param status query string false "Filter by user status (active, inactive)"
// @Param role query string false "Filter by user role"
// @Success 200 {object} models.UserListResponse
// @Failure 400 {object} utils.ErrorResponse
// @Failure 401 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Security BearerAuth
// @Router /api/tenants/v1/{tenant_id}/users [get]
func (h *TenantHandler) ListTenantUsers(c *gin.Context) {
	tenantID := c.Param("id")
	if tenantID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Tenant ID is required", nil)
		return
	}

	// Get tenant to verify it exists and get realm name
	tenant, err := h.tenantService.GetTenant(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant", zap.Error(err))
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Tenant not found", nil)
		return
	}

	var req models.UserSearchRequest
	req.Page = 1
	req.PageSize = constants.DefaultPageSize

	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			req.Page = parsed
		}
	}

	if ps := c.Query("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed >= constants.MinPageSize && parsed <= constants.MaxPageSize {
			req.PageSize = parsed
		}
	}

	if query := c.Query("search_term"); query != "" {
		req.SearchTerm = query
	}

	if status := c.Query("status"); status != "" {
		req.Status = status
	}

	if role := c.Query("role"); role != "" {
		req.Role = role
	}

	if err := h.validator.Struct(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeValidationFailed,
			"Validation failed", utils.FormatValidationErrors(err))
		return
	}

	users, total, err := h.userService.ListUsers(c.Request.Context(), tenant.RealmName, &req)
	if err != nil {
		h.logger.Error("Failed to list tenant users", 
			zap.Error(err),
			zap.String("tenant_id", tenantID),
			zap.String("realm", tenant.RealmName))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError,
			"Failed to list users", err.Error())
		return
	}

	response := &models.UserListResponse{
		Users:      users,
		Total:      total,
		Page:       req.Page,
		PageSize:   req.PageSize,
		TotalPages: int((total + int64(req.PageSize) - 1) / int64(req.PageSize)),
	}

	c.JSON(http.StatusOK, response)
}

// @Summary Get tenant user
// @Description Get user details within a specific tenant
// @Tags tenants
// @Produce json
// @Param tenant_id path string true "Tenant ID"
// @Param user_id path string true "User ID"
// @Success 200 {object} models.User
// @Failure 400 {object} utils.ErrorResponse
// @Failure 401 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Security BearerAuth
// @Router /api/tenants/v1/{tenant_id}/users/{user_id} [get]
func (h *TenantHandler) GetTenantUser(c *gin.Context) {
	tenantID := c.Param("id")
	userID := c.Param("user_id")
	
	if tenantID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Tenant ID is required", nil)
		return
	}
	
	if userID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "User ID is required", nil)
		return
	}

	// Get tenant to verify it exists and get realm name
	tenant, err := h.tenantService.GetTenant(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant", zap.Error(err))
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Tenant not found", nil)
		return
	}

	user, err := h.userService.GetUser(c.Request.Context(), tenant.RealmName, userID)
	if err != nil {
		h.logger.Error("Failed to get tenant user", 
			zap.Error(err),
			zap.String("tenant_id", tenantID),
			zap.String("user_id", userID),
			zap.String("realm", tenant.RealmName))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to get user", nil)
		return
	}

	if user == nil {
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "User not found", nil)
		return
	}

	c.JSON(http.StatusOK, user.ToResponse())
}

// @Summary Update tenant user
// @Description Update user information within a specific tenant
// @Tags tenants
// @Accept json
// @Produce json
// @Param tenant_id path string true "Tenant ID"
// @Param user_id path string true "User ID"
// @Param request body models.UpdateUserRequest true "User update request"
// @Success 200 {object} models.User
// @Failure 400 {object} utils.ErrorResponse
// @Failure 401 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Security BearerAuth
// @Router /api/tenants/v1/{tenant_id}/users/{user_id} [put]
func (h *TenantHandler) UpdateTenantUser(c *gin.Context) {
	tenantID := c.Param("id")
	userID := c.Param("user_id")
	
	if tenantID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Tenant ID is required", nil)
		return
	}
	
	if userID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "User ID is required", nil)
		return
	}

	// Get tenant to verify it exists and get realm name
	tenant, err := h.tenantService.GetTenant(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant", zap.Error(err))
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Tenant not found", nil)
		return
	}

	var req models.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeValidationFailed,
			"Validation failed", utils.FormatValidationErrors(err))
		return
	}

	user, err := h.userService.UpdateUser(c.Request.Context(), tenant.RealmName, userID, &req)
	if err != nil {
		h.logger.Error("Failed to update tenant user", 
			zap.Error(err),
			zap.String("tenant_id", tenantID),
			zap.String("user_id", userID),
			zap.String("realm", tenant.RealmName))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to update user", nil)
		return
	}

	if user == nil {
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "User not found", nil)
		return
	}

	c.JSON(http.StatusOK, user.ToResponse())
}

// @Summary Delete tenant user
// @Description Delete user within a specific tenant
// @Tags tenants
// @Param tenant_id path string true "Tenant ID"
// @Param user_id path string true "User ID"
// @Success 204
// @Failure 400 {object} utils.ErrorResponse
// @Failure 401 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Security BearerAuth
// @Router /api/tenants/v1/{tenant_id}/users/{user_id} [delete]
func (h *TenantHandler) DeleteTenantUser(c *gin.Context) {
	tenantID := c.Param("id")
	userID := c.Param("user_id")
	
	if tenantID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Tenant ID is required", nil)
		return
	}
	
	if userID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "User ID is required", nil)
		return
	}

	// Get tenant to verify it exists and get realm name
	tenant, err := h.tenantService.GetTenant(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant", zap.Error(err))
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Tenant not found", nil)
		return
	}

	err = h.userService.DeleteUser(c.Request.Context(), tenant.RealmName, userID)
	if err != nil {
		h.logger.Error("Failed to delete tenant user", 
			zap.Error(err),
			zap.String("tenant_id", tenantID),
			zap.String("user_id", userID),
			zap.String("realm", tenant.RealmName))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to delete user", nil)
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

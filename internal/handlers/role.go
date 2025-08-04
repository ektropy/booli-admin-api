package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/booli/booli-admin-api/internal/models"
	"github.com/booli/booli-admin-api/internal/services"
	"github.com/booli/booli-admin-api/internal/utils"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

type RoleHandler struct {
	roleService *services.RoleService
	logger      *zap.Logger
	validator   *validator.Validate
}

func NewRoleHandler(roleService *services.RoleService, logger *zap.Logger) *RoleHandler {
	return &RoleHandler{
		roleService: roleService,
		logger:      logger,
		validator:   validator.New(),
	}
}

// @Summary List roles
// @Description Get list of roles
// @Tags roles
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /roles [get]
// @Router /admin/roles [get]
func (h *RoleHandler) List(c *gin.Context) {
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

	pageSize := 10
	if ps := c.Query("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	includeSystem := c.Query("include_system") == "true"

	roles, total, err := h.roleService.ListRoles(c.Request.Context(), tenantID.(uuid.UUID), page, pageSize, includeSystem)
	if err != nil {
		h.logger.Error("Failed to list roles", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to list roles", nil)
		return
	}

	response := &models.RoleListResponse{
		Roles:      make([]models.RoleResponse, len(roles)),
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: int((total + int64(pageSize) - 1) / int64(pageSize)),
	}

	for i, role := range roles {
		response.Roles[i] = *role.ToResponse()
	}

	c.JSON(http.StatusOK, response)
}

// @Summary Create role
// @Description Create a new role
// @Tags roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 201 {object} map[string]interface{}
// @Router /roles [post]
// @Router /admin/roles [post]
func (h *RoleHandler) Create(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "tenant_id not found in context", nil)
		return
	}

	var req models.CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeValidationFailed, "Validation failed", utils.FormatValidationErrors(err))
		return
	}

	permissionsJSON, _ := json.Marshal(req.Permissions)
	role := &models.Role{
		TenantID:    tenantID.(uuid.UUID),
		Name:        req.Name,
		Description: req.Description,
		Permissions: datatypes.JSON(permissionsJSON),
		IsSystem:    false,
	}

	createdRole, err := h.roleService.CreateRole(c.Request.Context(), role)
	if err != nil {
		h.logger.Error("Failed to create role", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to create role", nil)
		return
	}

	c.JSON(http.StatusCreated, createdRole.ToResponse())
}

// @Summary Get role
// @Description Get role by ID
// @Tags roles
// @Produce json
// @Param id path string true "Role ID"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /roles/{id} [get]
// @Router /admin/roles/{id} [get]
func (h *RoleHandler) Get(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "tenant_id not found in context", nil)
		return
	}

	roleID := c.Param("id")
	if roleID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Role ID is required", nil)
		return
	}

	parsedID, err := uuid.Parse(roleID)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid role ID format", nil)
		return
	}

	role, err := h.roleService.GetRole(c.Request.Context(), tenantID.(uuid.UUID), parsedID)
	if err != nil {
		h.logger.Error("Failed to get role", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to get role", nil)
		return
	}

	if role == nil {
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Role not found", nil)
		return
	}

	c.JSON(http.StatusOK, role.ToResponse())
}

// @Summary Update role
// @Description Update role by ID
// @Tags roles
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /roles/{id} [put]
// @Router /admin/roles/{id} [put]
func (h *RoleHandler) Update(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "tenant_id not found in context", nil)
		return
	}

	roleID := c.Param("id")
	if roleID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Role ID is required", nil)
		return
	}

	parsedID, err := uuid.Parse(roleID)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid role ID format", nil)
		return
	}

	var req models.UpdateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := h.validator.Struct(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeValidationFailed, "Validation failed", utils.FormatValidationErrors(err))
		return
	}

	updatedRole, err := h.roleService.UpdateRole(c.Request.Context(), tenantID.(uuid.UUID), parsedID, &req)
	if err != nil {
		h.logger.Error("Failed to update role", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to update role", nil)
		return
	}

	if updatedRole == nil {
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Role not found", nil)
		return
	}

	c.JSON(http.StatusOK, updatedRole.ToResponse())
}

// @Summary Delete role
// @Description Delete role by ID
// @Tags roles
// @Produce json
// @Param id path string true "Role ID"
// @Security BearerAuth
// @Success 204
// @Router /roles/{id} [delete]
// @Router /admin/roles/{id} [delete]
func (h *RoleHandler) Delete(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "tenant_id not found in context", nil)
		return
	}

	roleID := c.Param("id")
	if roleID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Role ID is required", nil)
		return
	}

	parsedID, err := uuid.Parse(roleID)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid role ID format", nil)
		return
	}

	err = h.roleService.DeleteRole(c.Request.Context(), tenantID.(uuid.UUID), parsedID)
	if err != nil {
		h.logger.Error("Failed to delete role", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to delete role", nil)
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

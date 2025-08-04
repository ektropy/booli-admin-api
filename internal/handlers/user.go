package handlers

import (
	"bytes"
	"context"
	"encoding/csv"
	"io"
	"net/http"
	"strconv"

	"github.com/booli/booli-admin-api/internal/constants"
	"github.com/booli/booli-admin-api/internal/middleware"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/booli/booli-admin-api/internal/services"
	"github.com/booli/booli-admin-api/internal/utils"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type UserServiceInterface interface {
	ListUsers(ctx context.Context, tenantID uuid.UUID, req *models.UserSearchRequest) ([]models.User, int64, error)
	CreateUser(ctx context.Context, req *models.CreateUserRequest) (*models.User, error)
	GetUser(ctx context.Context, tenantID uuid.UUID, userID string) (*models.User, error)
	UpdateUser(ctx context.Context, tenantID uuid.UUID, userID string, req *models.UpdateUserRequest) (*models.User, error)
	DeleteUser(ctx context.Context, tenantID uuid.UUID, userID string) error
	BulkCreateUsers(ctx context.Context, tenantID uuid.UUID, req *models.BulkCreateUserRequest) ([]models.User, error)
	ImportUsersFromCSV(ctx context.Context, tenantID uuid.UUID, records [][]string) (*services.CSVImportResult, error)
}

type UserHandler struct {
	userService UserServiceInterface
	logger      *zap.Logger
	validator   *validator.Validate
}

func NewUserHandler(userService UserServiceInterface, logger *zap.Logger) *UserHandler {
	return &UserHandler{
		userService: userService,
		logger:      logger,
		validator:   validator.New(),
	}
}

func (h *UserHandler) List(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeTenantRequired,
			"Tenant context required", nil)
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

	if department := c.Query("department"); department != "" {
		req.Department = department
	}

	if role := c.Query("role"); role != "" {
		req.Role = role
	}

	req.SortBy = c.Query("sort_by")
	req.SortOrder = c.Query("sort_order")

	if err := h.validator.Struct(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeValidationFailed,
			"Validation failed", utils.FormatValidationErrors(err))
		return
	}

	users, total, err := h.userService.ListUsers(c.Request.Context(), tenantID.(uuid.UUID), &req)
	if err != nil {
		h.logger.Error("Failed to list users", zap.Error(err))
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

// @Summary Create user
// @Description Create a new user
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 201 {object} map[string]interface{}
// @Router /users [post]
// @Router /admin/users [post]
func (h *UserHandler) Create(c *gin.Context) {
	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	roles, _ := middleware.GetUserRoles(c)
	isMSPAdmin := false
	for _, role := range roles {
		if role == constants.RoleMSPAdmin || role == constants.RoleMSPPower {
			isMSPAdmin = true
			break
		}
	}

	if !isMSPAdmin {
		tenantID, exists := c.Get("tenant_id")
		if !exists {
			utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeTenantRequired, "Tenant context required", nil)
			return
		}
		req.TenantID = tenantID.(uuid.UUID)
	} else {
		if req.TenantID == uuid.Nil && req.TenantName == "" && req.TenantDomain == "" {
			utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "tenant_name or tenant_domain is required for MSP admin user creation", nil)
			return
		}
	}

	if err := h.validator.Struct(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeValidationFailed,
			"Validation failed", utils.FormatValidationErrors(err))
		return
	}

	createdUser, err := h.userService.CreateUser(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("Failed to create user", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to create user", nil)
		return
	}

	c.JSON(http.StatusCreated, createdUser.ToResponse())
}

// @Summary Get user
// @Description Get user by ID
// @Tags users
// @Produce json
// @Param id path string true "User ID"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /users/{id} [get]
// @Router /admin/users/{id} [get]
func (h *UserHandler) Get(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeTenantRequired,
			"Tenant context required", nil)
		return
	}

	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	user, err := h.userService.GetUser(c.Request.Context(), tenantID.(uuid.UUID), userID)
	if err != nil {
		h.logger.Error("Failed to get user", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		return
	}

	if user == nil {
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "User not found", nil)
		return
	}

	c.JSON(http.StatusOK, user.ToResponse())
}

// @Summary Update user
// @Description Update user information
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /users/{id} [put]
// @Router /admin/users/{id} [put]
func (h *UserHandler) Update(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeTenantRequired,
			"Tenant context required", nil)
		return
	}

	userID := c.Param("id")
	if userID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "User ID is required", nil)
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

	user, err := h.userService.UpdateUser(c.Request.Context(), tenantID.(uuid.UUID), userID, &req)
	if err != nil {
		h.logger.Error("Failed to update user", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to update user", nil)
		return
	}

	if user == nil {
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "User not found", nil)
		return
	}

	c.JSON(http.StatusOK, user.ToResponse())
}

// @Summary Delete user
// @Description Delete user by ID
// @Tags users
// @Param id path string true "User ID"
// @Security BearerAuth
// @Success 204
// @Router /users/{id} [delete]
// @Router /admin/users/{id} [delete]
func (h *UserHandler) Delete(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "User ID is required", nil)
		return
	}

	roles, _ := middleware.GetUserRoles(c)
	isMSPAdmin := false
	for _, role := range roles {
		if role == constants.RoleMSPAdmin || role == constants.RoleMSPPower {
			isMSPAdmin = true
			break
		}
	}

	var err error
	if isMSPAdmin {
		err = h.userService.DeleteUser(c.Request.Context(), uuid.Nil, userID)
	} else {
		tenantID, exists := c.Get("tenant_id")
		if !exists {
			utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeTenantRequired, "Tenant context required", nil)
			return
		}
		err = h.userService.DeleteUser(c.Request.Context(), tenantID.(uuid.UUID), userID)
	}

	if err != nil {
		h.logger.Error("Failed to delete user", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to delete user", nil)
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

// @Summary Bulk create users
// @Description Create multiple users at once
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 201 {object} map[string]interface{}
// @Router /users/bulk-create [post]
func (h *UserHandler) BulkCreate(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeTenantRequired,
			"Tenant context required", nil)
		return
	}

	var req models.BulkCreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	for i := range req.Users {
		req.Users[i].TenantID = tenantID.(uuid.UUID)
	}

	if err := h.validator.Struct(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeValidationFailed,
			"Validation failed", utils.FormatValidationErrors(err))
		return
	}

	results, err := h.userService.BulkCreateUsers(c.Request.Context(), tenantID.(uuid.UUID), &req)
	if err != nil {
		h.logger.Error("Failed to bulk create users", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to bulk create users", nil)
		return
	}

	c.JSON(http.StatusCreated, gin.H{"results": results})
}

// @Summary Import users from CSV
// @Description Import users from CSV file
// @Tags users
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "CSV file"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /users/import-csv [post]
func (h *UserHandler) ImportCSV(c *gin.Context) {
	_, exists := c.Get("tenant_id")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeTenantRequired, "Tenant context required", nil)
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "File is required", nil)
		return
	}
	defer file.Close()

	if header.Header.Get("Content-Type") != "text/csv" && !bytes.HasSuffix([]byte(header.Filename), []byte(".csv")) {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "File must be a CSV", nil)
		return
	}

	data, err := io.ReadAll(file)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Failed to read file", nil)
		return
	}

	reader := csv.NewReader(bytes.NewReader(data))
	records, err := reader.ReadAll()
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Failed to parse CSV", nil)
		return
	}

	if len(records) < 2 {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "CSV must contain at least a header and one data row", nil)
		return
	}

	tenantIDValue, exists := c.Get("tenant_id")
	if !exists {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeTenantRequired, "Tenant context required", nil)
		return
	}

	tenantID, ok := tenantIDValue.(uuid.UUID)
	if !ok {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid tenant_id format", nil)
		return
	}

	result, err := h.userService.ImportUsersFromCSV(c.Request.Context(), tenantID, records)
	if err != nil {
		h.logger.Error("Failed to import users from CSV", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to import users from CSV", err.Error())
		return
	}

	c.JSON(http.StatusOK, result)
}

package handlers

import (
	"bytes"
	"context"
	"encoding/csv"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/booli/booli-admin-api/internal/constants"
	"github.com/booli/booli-admin-api/internal/middleware"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/booli/booli-admin-api/internal/utils"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"
)

type UserServiceInterface interface {
	ListUsers(ctx context.Context, realmName string, req *models.UserSearchRequest) ([]models.User, int64, error)
	CreateUser(ctx context.Context, realmName string, req *models.CreateUserRequest) (*models.User, error)
	GetUser(ctx context.Context, realmName, userID string) (*models.User, error)
	UpdateUser(ctx context.Context, realmName, userID string, req *models.UpdateUserRequest) (*models.User, error)
	DeleteUser(ctx context.Context, realmName, userID string) error
	
	// Bulk operations
	BulkCreateUsers(ctx context.Context, realmName string, users []models.CreateUserRequest) (*models.BulkCreateResult, error)
	ImportUsersFromCSV(ctx context.Context, realmName string, csvRecords [][]string) (*models.CSVImportResult, error)
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

// @Summary List users
// @Description Get paginated list of users with optional search and filtering
// @Tags users
// @Produce json
// @Param page query int false "Page number (default: 1)"
// @Param page_size query int false "Page size (default: 20, min: 1, max: 100)"
// @Param search_term query string false "Search term for username or email"
// @Param status query string false "Filter by user status (active, inactive)"
// @Param role query string false "Filter by user role"
// @Success 200 {object} models.UserListResponse
// @Failure 400 {object} utils.ErrorResponse
// @Failure 401 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Security BearerAuth
// @Router /users [get]
// @Router /admin/users [get]
func (h *UserHandler) List(c *gin.Context) {
	realmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized,
			"Realm context required", nil)
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

	users, total, err := h.userService.ListUsers(c.Request.Context(), realmName, &req)
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
// @Param request body models.CreateUserRequest true "User creation request"
// @Success 201 {object} models.User
// @Failure 400 {object} utils.ErrorResponse
// @Failure 401 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Security BearerAuth
// @Router /users [post]
// @Router /admin/users [post]
func (h *UserHandler) Create(c *gin.Context) {
	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	var realmName string
	if req.TenantRealm != "" {
		realmName = req.TenantRealm
	} else {
		var err error
		realmName, err = middleware.GetRealmName(c)
		if err != nil {
			utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Realm context required", nil)
			return
		}
	}

	if err := h.validator.Struct(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeValidationFailed,
			"Validation failed", utils.FormatValidationErrors(err))
		return
	}

	createdUser, err := h.userService.CreateUser(c.Request.Context(), realmName, &req)
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
// @Success 200 {object} models.User
// @Failure 400 {object} utils.ErrorResponse
// @Failure 401 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /users/{id} [get]
// @Router /admin/users/{id} [get]
func (h *UserHandler) Get(c *gin.Context) {
	realmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized,
			"Realm context required", nil)
		return
	}

	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	user, err := h.userService.GetUser(c.Request.Context(), realmName, userID)
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
// @Param request body models.UpdateUserRequest true "User update request"
// @Security BearerAuth
// @Success 200 {object} models.User
// @Failure 400 {object} utils.ErrorResponse
// @Failure 401 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /users/{id} [put]
// @Router /admin/users/{id} [put]
func (h *UserHandler) Update(c *gin.Context) {
	realmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized,
			"Realm context required", nil)
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

	user, err := h.userService.UpdateUser(c.Request.Context(), realmName, userID, &req)
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
// @Failure 400 {object} utils.ErrorResponse
// @Failure 401 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /users/{id} [delete]
// @Router /admin/users/{id} [delete]
func (h *UserHandler) Delete(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "User ID is required", nil)
		return
	}

	var realmName string
	if tenantRealm := c.Query("tenant_realm"); tenantRealm != "" {
		realmName = tenantRealm
	} else {
		var err error
		realmName, err = middleware.GetRealmName(c)
		if err != nil {
			utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Realm context required", nil)
			return
		}
	}

	err := h.userService.DeleteUser(c.Request.Context(), realmName, userID)

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
// @Param request body models.BulkCreateUserRequest true "Bulk user creation request"
// @Security BearerAuth
// @Success 201 {object} models.BulkCreateResult
// @Failure 400 {object} utils.ErrorResponse
// @Failure 401 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /users/bulk-create [post]
func (h *UserHandler) BulkCreate(c *gin.Context) {
	realmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Realm context required", nil)
		return
	}

	var req models.BulkCreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	if len(req.Users) == 0 {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "No users provided", nil)
		return
	}

	if len(req.Users) > 100 {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Too many users (max 100 per request)", nil)
		return
	}

	result, err := h.userService.BulkCreateUsers(c.Request.Context(), realmName, req.Users)
	if err != nil {
		h.logger.Error("Bulk create failed", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Bulk create failed", nil)
		return
	}

	c.JSON(http.StatusCreated, result)
}

// @Summary Import users from CSV
// @Description Import users from CSV file
// @Tags users
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "CSV file"
// @Security BearerAuth
// @Success 200 {object} models.CSVImportResult
// @Failure 400 {object} utils.ErrorResponse
// @Failure 401 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /users/import-csv [post]
func (h *UserHandler) ImportCSV(c *gin.Context) {
	realmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Realm context required", nil)
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "File is required", nil)
		return
	}
	defer file.Close()

	// Validate file type
	if !strings.HasSuffix(strings.ToLower(header.Filename), ".csv") {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "File must be a CSV", nil)
		return
	}

	// Validate file size (e.g., 10MB max)
	const maxSize = 10 * 1024 * 1024
	if header.Size > maxSize {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "File too large (max 10MB)", nil)
		return
	}

	// Read and parse CSV
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

	// Process CSV import
	result, err := h.userService.ImportUsersFromCSV(c.Request.Context(), realmName, records)
	if err != nil {
		h.logger.Error("CSV import failed", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "CSV import failed", err.Error())
		return
	}

	c.JSON(http.StatusOK, result)
}

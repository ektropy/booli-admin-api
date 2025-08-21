package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/booli/booli-admin-api/internal/models"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type MSPService interface {
	CreateMSP(ctx context.Context, req *models.CreateMSPRequest) (*models.MSP, error)
	GetMSP(ctx context.Context, realmName string) (*models.MSP, error)
	ListMSPs(ctx context.Context, page, pageSize int) (*models.MSPListResponse, error)
	UpdateMSP(ctx context.Context, realmName string, req *models.UpdateMSPRequest) (*models.MSP, error)
	DeleteMSP(ctx context.Context, realmName string) error
	AddMSPStaff(ctx context.Context, mspRealm string, req *models.AddMSPStaffRequest) (*models.MSPStaffMember, error)
	CreateClientTenant(ctx context.Context, mspRealm string, req *models.CreateClientTenantRequest) (*models.Tenant, error)
	GetMSPClientTenants(ctx context.Context, mspRealm string, page, pageSize int) (*models.ClientTenantListResponse, error)
}

type MSPHandler struct {
	mspService MSPService
	logger     *zap.Logger
}

func NewMSPHandler(mspService MSPService, logger *zap.Logger) *MSPHandler {
	return &MSPHandler{
		mspService: mspService,
		logger:     logger,
	}
}

// @Summary Create MSP
// @Description Create a new Managed Service Provider
// @Tags MSP
// @Accept json
// @Produce json
// @Param request body models.CreateMSPRequest true "MSP creation request"
// @Security BearerAuth
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/msps/v1/ [post]
func (h *MSPHandler) CreateMSP(c *gin.Context) {
	var req models.CreateMSPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid request body", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
			"code":  "INVALID_REQUEST_BODY",
		})
		return
	}

	msp, err := h.mspService.CreateMSP(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("Failed to create MSP", zap.Error(err), zap.String("name", req.Name))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create MSP",
			"code":  "MSP_CREATION_FAILED",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "MSP created successfully",
		"msp":     msp,
	})
}

// @Summary List MSPs
// @Description Get paginated list of MSPs
// @Tags MSP
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/msps/v1/ [get]
func (h *MSPHandler) ListMSPs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	response, err := h.mspService.ListMSPs(c.Request.Context(), page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list MSPs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to list MSPs",
			"code":  "MSP_LIST_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// @Summary Get MSP
// @Description Get MSP details by realm name
// @Tags MSP
// @Produce json
// @Param msp_id path string true "MSP realm name"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/msps/v1/{msp_id} [get]
func (h *MSPHandler) GetMSP(c *gin.Context) {
	realmName := c.Param("msp_id")
	if realmName == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "MSP ID is required",
			"code":  "MISSING_MSP_ID",
		})
		return
	}

	msp, err := h.mspService.GetMSP(c.Request.Context(), realmName)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "MSP not found",
				"code":  "MSP_NOT_FOUND",
			})
			return
		}

		h.logger.Error("Failed to get MSP", zap.Error(err), zap.String("realm_name", realmName))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get MSP",
			"code":  "MSP_GET_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msp": msp,
	})
}

// @Summary Update MSP
// @Description Update MSP details
// @Tags MSP
// @Accept json
// @Produce json
// @Param msp_id path string true "MSP realm name"
// @Param request body models.UpdateMSPRequest true "MSP update request"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/msps/v1/{msp_id} [put]
func (h *MSPHandler) UpdateMSP(c *gin.Context) {
	realmName := c.Param("msp_id")
	if realmName == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "MSP ID is required",
			"code":  "MISSING_MSP_ID",
		})
		return
	}

	var req models.UpdateMSPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid request body", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
			"code":  "INVALID_REQUEST_BODY",
		})
		return
	}

	msp, err := h.mspService.UpdateMSP(c.Request.Context(), realmName, &req)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "MSP not found",
				"code":  "MSP_NOT_FOUND",
			})
			return
		}

		h.logger.Error("Failed to update MSP", zap.Error(err), zap.String("realm_name", realmName))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update MSP",
			"code":  "MSP_UPDATE_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "MSP updated successfully",
		"msp":     msp,
	})
}

// @Summary Delete MSP
// @Description Delete MSP and all associated data
// @Tags MSP
// @Produce json
// @Param msp_id path string true "MSP realm name"
// @Security BearerAuth
// @Success 204
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/msps/v1/{msp_id} [delete]
func (h *MSPHandler) DeleteMSP(c *gin.Context) {
	realmName := c.Param("msp_id")
	if realmName == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "MSP ID is required",
			"code":  "MISSING_MSP_ID",
		})
		return
	}

	err := h.mspService.DeleteMSP(c.Request.Context(), realmName)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "MSP not found",
				"code":  "MSP_NOT_FOUND",
			})
			return
		}

		h.logger.Error("Failed to delete MSP", zap.Error(err), zap.String("realm_name", realmName))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete MSP",
			"code":  "MSP_DELETE_FAILED",
		})
		return
	}

	c.Status(http.StatusNoContent)
}

// @Summary Add MSP Staff
// @Description Add staff member to MSP
// @Tags MSP
// @Accept json
// @Produce json
// @Param msp_id path string true "MSP realm name"
// @Param request body models.AddMSPStaffRequest true "Staff member request"
// @Security BearerAuth
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/msps/v1/{msp_id}/staff [post]
func (h *MSPHandler) AddMSPStaff(c *gin.Context) {
	mspRealm := c.Param("msp_id")
	if mspRealm == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "MSP ID is required",
			"code":  "MISSING_MSP_ID",
		})
		return
	}

	var req models.AddMSPStaffRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid request body", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
			"code":  "INVALID_REQUEST_BODY",
		})
		return
	}

	staffMember, err := h.mspService.AddMSPStaff(c.Request.Context(), mspRealm, &req)
	if err != nil {
		h.logger.Error("Failed to add MSP staff", zap.Error(err), zap.String("msp_realm", mspRealm))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to add MSP staff",
			"code":  "MSP_STAFF_ADD_FAILED",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Staff member added successfully",
		"staff":   staffMember,
	})
}

// @Summary Create Client Tenant
// @Description Create a new client tenant for MSP
// @Tags MSP
// @Accept json
// @Produce json
// @Param msp_id path string true "MSP realm name"
// @Param request body models.CreateClientTenantRequest true "Client tenant request"
// @Security BearerAuth
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/msps/v1/{msp_id}/clients [post]
func (h *MSPHandler) CreateClientTenant(c *gin.Context) {
	mspRealm := c.Param("msp_id")
	if mspRealm == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "MSP ID is required",
			"code":  "MISSING_MSP_ID",
		})
		return
	}

	var req models.CreateClientTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid request body", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
			"code":  "INVALID_REQUEST_BODY",
		})
		return
	}

	tenant, err := h.mspService.CreateClientTenant(c.Request.Context(), mspRealm, &req)
	if err != nil {
		h.logger.Error("Failed to create client tenant", zap.Error(err), zap.String("msp_realm", mspRealm))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create client tenant",
			"code":  "CLIENT_TENANT_CREATE_FAILED",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Client tenant created successfully",
		"tenant":  tenant,
	})
}

// @Summary List MSP Client Tenants
// @Description Get paginated list of client tenants for MSP
// @Tags MSP
// @Produce json
// @Param msp_id path string true "MSP realm name"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/msps/v1/{msp_id}/clients [get]
func (h *MSPHandler) ListMSPClients(c *gin.Context) {
	mspRealm := c.Param("msp_id")
	if mspRealm == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "MSP ID is required",
			"code":  "MISSING_MSP_ID",
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

	response, err := h.mspService.GetMSPClientTenants(c.Request.Context(), mspRealm, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list client tenants", zap.Error(err), zap.String("msp_realm", mspRealm))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to list client tenants",
			"code":  "CLIENT_TENANT_LIST_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, response)
}
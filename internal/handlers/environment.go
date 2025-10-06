package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/booli/booli-admin-api/internal/middleware"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/booli/booli-admin-api/internal/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type EnvironmentService interface {
	CreateTenantEnvironment(ctx context.Context, req *models.CreateTenantEnvironmentRequest, userTenantRealm string) (*models.TenantEnvironment, error)
	GetTenantEnvironment(ctx context.Context, environmentID uuid.UUID, userTenantRealm string) (*models.TenantEnvironment, error)
	ListTenantEnvironments(ctx context.Context, tenantRealm, userTenantRealm string, page, pageSize int) (*models.TenantEnvironmentListResponse, error)
	UpdateTenantEnvironment(ctx context.Context, environmentID uuid.UUID, req *models.UpdateTenantEnvironmentRequest, userTenantRealm string) (*models.TenantEnvironment, error)
	DeleteTenantEnvironment(ctx context.Context, environmentID uuid.UUID, userTenantRealm string) error
	GrantTenantAccess(ctx context.Context, req *models.CreateTenantAccessGrantRequest, granterTenantRealm string) (*models.TenantAccessGrant, error)
	RevokeAccess(ctx context.Context, grantID uuid.UUID, revokerTenantRealm string) error
	GetSIEMEnrichmentData(ctx context.Context, tenantRealm, userTenantRealm string) (*models.SIEMEnrichmentData, error)
}

type EnvironmentHandler struct {
	environmentService EnvironmentService
	logger             *zap.Logger
}

func NewEnvironmentHandler(environmentService EnvironmentService, logger *zap.Logger) *EnvironmentHandler {
	return &EnvironmentHandler{
		environmentService: environmentService,
		logger:             logger,
	}
}

// @Summary Create environment
// @Description Create a new tenant environment with network ranges, IPs, domains, and infrastructure
// @Tags environments
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.CreateTenantEnvironmentRequestSwagger true "Environment creation request"
// @Success 201 {object} models.TenantEnvironmentSwagger
// @Failure 400 {object} models.ErrorResponseSwagger
// @Failure 401 {object} models.ErrorResponseSwagger
// @Failure 500 {object} models.ErrorResponseSwagger
// @Router /environments [post]
func (h *EnvironmentHandler) CreateEnvironment(c *gin.Context) {
	var req models.CreateTenantEnvironmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	userRealmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
		return
	}

	environment, err := h.environmentService.CreateTenantEnvironment(c.Request.Context(), &req, userRealmName)
	if err != nil {
		h.logger.Error("Failed to create environment",
			zap.String("realm_name", userRealmName),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to create environment", nil)
		return
	}

	c.JSON(http.StatusCreated, environment)
}

// @Summary Get environment
// @Description Get tenant environment by ID
// @Tags environments
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Environment ID (UUID)"
// @Success 200 {object} models.TenantEnvironmentSwagger
// @Failure 400 {object} models.ErrorResponseSwagger
// @Failure 401 {object} models.ErrorResponseSwagger
// @Failure 404 {object} models.ErrorResponseSwagger
// @Router /environments/{id} [get]
func (h *EnvironmentHandler) GetEnvironment(c *gin.Context) {
	environmentIDStr := c.Param("id")
	if environmentIDStr == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Environment ID is required", nil)
		return
	}

	environmentID, err := uuid.Parse(environmentIDStr)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid environment ID format", nil)
		return
	}

	userRealmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
		return
	}

	environment, err := h.environmentService.GetTenantEnvironment(c.Request.Context(), environmentID, userRealmName)
	if err != nil {
		h.logger.Error("Failed to get environment",
			zap.String("environment_id", environmentID.String()),
			zap.String("user_realm_name", userRealmName),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Environment not found", nil)
		return
	}

	c.JSON(http.StatusOK, environment)
}

// @Summary List environments
// @Description Get paginated list of tenant environments
// @Tags environments
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param page query integer false "Page number" default(1)
// @Param page_size query integer false "Page size" default(20) minimum(1) maximum(100)
// @Success 200 {object} models.TenantEnvironmentListResponseSwagger
// @Failure 401 {object} models.ErrorResponseSwagger
// @Failure 500 {object} models.ErrorResponseSwagger
// @Router /environments [get]
func (h *EnvironmentHandler) ListEnvironments(c *gin.Context) {
	userRealmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
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

	environments, err := h.environmentService.ListTenantEnvironments(c.Request.Context(), userRealmName, userRealmName, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list environments",
			zap.String("user_realm_name", userRealmName),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to list environments", nil)
		return
	}

	c.JSON(http.StatusOK, environments)
}

// @Summary Update environment
// @Description Update tenant environment by ID
// @Tags environments
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Environment ID (UUID)"
// @Param request body models.UpdateTenantEnvironmentRequestSwagger true "Environment update request"
// @Success 200 {object} models.TenantEnvironmentSwagger
// @Failure 400 {object} models.ErrorResponseSwagger
// @Failure 401 {object} models.ErrorResponseSwagger
// @Failure 404 {object} models.ErrorResponseSwagger
// @Failure 500 {object} models.ErrorResponseSwagger
// @Router /environments/{id} [put]
func (h *EnvironmentHandler) UpdateEnvironment(c *gin.Context) {
	environmentIDStr := c.Param("id")
	if environmentIDStr == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Environment ID is required", nil)
		return
	}

	environmentID, err := uuid.Parse(environmentIDStr)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid environment ID format", nil)
		return
	}

	var req models.UpdateTenantEnvironmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	userRealmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
		return
	}

	environment, err := h.environmentService.UpdateTenantEnvironment(c.Request.Context(), environmentID, &req, userRealmName)
	if err != nil {
		h.logger.Error("Failed to update environment",
			zap.String("environment_id", environmentID.String()),
			zap.String("user_realm_name", userRealmName),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to update environment", nil)
		return
	}

	c.JSON(http.StatusOK, environment)
}

// @Summary Delete environment
// @Description Delete tenant environment by ID
// @Tags environments
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Environment ID (UUID)"
// @Success 204 "No Content"
// @Failure 400 {object} models.ErrorResponseSwagger
// @Failure 401 {object} models.ErrorResponseSwagger
// @Failure 404 {object} models.ErrorResponseSwagger
// @Failure 500 {object} models.ErrorResponseSwagger
// @Router /environments/{id} [delete]
func (h *EnvironmentHandler) DeleteEnvironment(c *gin.Context) {
	environmentIDStr := c.Param("id")
	if environmentIDStr == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Environment ID is required", nil)
		return
	}

	environmentID, err := uuid.Parse(environmentIDStr)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid environment ID format", nil)
		return
	}

	userRealmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
		return
	}

	err = h.environmentService.DeleteTenantEnvironment(c.Request.Context(), environmentID, userRealmName)
	if err != nil {
		h.logger.Error("Failed to delete environment",
			zap.String("environment_id", environmentID.String()),
			zap.String("user_realm_name", userRealmName),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to delete environment", nil)
		return
	}

	c.JSON(http.StatusNoContent, gin.H{
		"message": "Environment deleted successfully",
	})
}

// @Summary Grant environment access
// @Description Grant access to an environment for another user or tenant
// @Tags environments
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.CreateTenantAccessGrantRequestSwagger true "Access grant request"
// @Success 201 {object} models.TenantAccessGrantSwagger
// @Failure 400 {object} models.ErrorResponseSwagger
// @Failure 401 {object} models.ErrorResponseSwagger
// @Failure 500 {object} models.ErrorResponseSwagger
// @Router /environments/access [post]
func (h *EnvironmentHandler) GrantAccess(c *gin.Context) {
	var req models.CreateTenantAccessGrantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	granterRealmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	userID, _ := middleware.GetUserID(c)
	if userUUID, err := uuid.Parse(userID); err == nil {
		req.GrantedBy = userUUID
	} else {
		req.GrantedBy = uuid.New()
	}

	grant, err := h.environmentService.GrantTenantAccess(c.Request.Context(), &req, granterRealmName)
	if err != nil {
		h.logger.Error("Failed to grant access",
			zap.String("granter_realm_name", granterRealmName),
			zap.String("environment_id", req.EnvironmentID.String()),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to grant access", nil)
		return
	}

	c.JSON(http.StatusCreated, grant)
}

// @Summary Revoke environment access
// @Description Revoke access grant to an environment
// @Tags environments
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param grant_id path string true "Access Grant ID (UUID)"
// @Success 200 {object} map[string]string "Access revoked successfully"
// @Failure 400 {object} models.ErrorResponseSwagger
// @Failure 401 {object} models.ErrorResponseSwagger
// @Failure 404 {object} models.ErrorResponseSwagger
// @Failure 500 {object} models.ErrorResponseSwagger
// @Router /environments/access/{grant_id} [delete]
func (h *EnvironmentHandler) RevokeAccess(c *gin.Context) {
	grantIDStr := c.Param("grant_id")
	if grantIDStr == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Grant ID is required", nil)
		return
	}

	grantID, err := uuid.Parse(grantIDStr)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid grant ID format", nil)
		return
	}

	revokerRealmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
		return
	}

	err = h.environmentService.RevokeAccess(c.Request.Context(), grantID, revokerRealmName)
	if err != nil {
		h.logger.Error("Failed to revoke access",
			zap.String("grant_id", grantID.String()),
			zap.String("revoker_realm_name", revokerRealmName),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to revoke access", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Access revoked successfully",
	})
}

// @Summary Get SIEM enrichment data
// @Description Get security information and event management (SIEM) enrichment data including network ranges, IPs, domains, and infrastructure
// @Tags environments
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.SIEMEnrichmentDataSwagger
// @Failure 401 {object} models.ErrorResponseSwagger
// @Failure 500 {object} models.ErrorResponseSwagger
// @Router /environments/security-data [get]
func (h *EnvironmentHandler) GetSIEMEnrichmentData(c *gin.Context) {
	userRealmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
		return
	}

	enrichmentData, err := h.environmentService.GetSIEMEnrichmentData(c.Request.Context(), userRealmName, userRealmName)
	if err != nil {
		h.logger.Error("Failed to get SIEM enrichment data",
			zap.String("user_realm_name", userRealmName),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to get SIEM enrichment data", nil)
		return
	}

	c.JSON(http.StatusOK, enrichmentData)
}

// @Summary Lookup enrichment data
// @Description Lookup enrichment data for a specific IP address or domain
// @Tags environments
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param q query string true "Query string (IP address or domain)"
// @Success 200 {object} map[string]interface{} "Enrichment lookup result"
// @Failure 400 {object} models.ErrorResponseSwagger
// @Failure 401 {object} models.ErrorResponseSwagger
// @Failure 500 {object} models.ErrorResponseSwagger
// @Router /environments/lookup [get]
func (h *EnvironmentHandler) LookupEnrichment(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Query parameter 'q' is required", nil)
		return
	}

	userRealmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
		return
	}

	result, found, err := h.lookupEnrichmentData(c.Request.Context(), query, userRealmName)
	if err != nil {
		h.logger.Error("Failed to lookup enrichment data", zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to lookup enrichment data", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"query":  query,
		"result": result,
		"found":  found,
	})
}

// @Summary Get network ranges
// @Description Get all network ranges for the tenant's environments
// @Tags environments
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Network ranges with metadata"
// @Failure 401 {object} models.ErrorResponseSwagger
// @Failure 500 {object} models.ErrorResponseSwagger
// @Router /environments/networks [get]
func (h *EnvironmentHandler) GetNetworkRanges(c *gin.Context) {
	userRealmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
		return
	}

	enrichmentData, err := h.environmentService.GetSIEMEnrichmentData(c.Request.Context(), userRealmName, userRealmName)
	if err != nil {
		h.logger.Error("Failed to get network ranges",
			zap.String("user_realm_name", userRealmName),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to get network ranges", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"realm_name":     userRealmName,
		"network_ranges": enrichmentData.NetworkRanges,
		"total":          len(enrichmentData.NetworkRanges),
		"last_updated":   enrichmentData.LastUpdated,
	})
}

// @Summary Get infrastructure IPs
// @Description Get all infrastructure IPs for the tenant's environments
// @Tags environments
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Infrastructure IPs with metadata"
// @Failure 401 {object} models.ErrorResponseSwagger
// @Failure 500 {object} models.ErrorResponseSwagger
// @Router /environments/infrastructure [get]
func (h *EnvironmentHandler) GetInfrastructureIPs(c *gin.Context) {
	userRealmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
		return
	}

	enrichmentData, err := h.environmentService.GetSIEMEnrichmentData(c.Request.Context(), userRealmName, userRealmName)
	if err != nil {
		h.logger.Error("Failed to get infrastructure IPs",
			zap.String("user_realm_name", userRealmName),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to get infrastructure IPs", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"realm_name":         userRealmName,
		"infrastructure_ips": enrichmentData.InfrastructureIPs,
		"total":              len(enrichmentData.InfrastructureIPs),
		"last_updated":       enrichmentData.LastUpdated,
	})
}

func (h *EnvironmentHandler) lookupEnrichmentData(ctx context.Context, query string, realmName string) (*models.EnrichmentLookupResult, bool, error) {
	enrichmentData, err := h.environmentService.GetSIEMEnrichmentData(ctx, realmName, realmName)
	if err != nil {
		return nil, false, err
	}

	for _, networkRange := range enrichmentData.NetworkRanges {
		if strings.Contains(networkRange.CIDR, query) {
			return &models.EnrichmentLookupResult{
				Type:            "network",
				Value:           query,
				TenantRealm:     realmName,
				EnvironmentID:   networkRange.EnvironmentID,
				EnvironmentName: networkRange.Name,
				Classification:  networkRange.NetworkType,
				Purpose:         networkRange.Description,
				IsPrivate:       networkRange.NetworkType == "internal",
				IsCritical:      networkRange.IsMonitored,
				AdditionalInfo: map[string]interface{}{
					"cidr":        networkRange.CIDR,
					"description": networkRange.Description,
					"vlan":        networkRange.VLAN,
				},
			}, true, nil
		}
	}

	for _, ip := range enrichmentData.InfrastructureIPs {
		if query == ip.IPAddress {
			return &models.EnrichmentLookupResult{
				Type:            "ip",
				Value:           query,
				TenantRealm:     realmName,
				EnvironmentID:   ip.EnvironmentID,
				EnvironmentName: ip.Hostname,
				Classification:  string(ip.ServiceType),
				Purpose:         ip.Description,
				IsPrivate:       !ip.IsActive,
				IsCritical:      ip.IsCritical,
				AdditionalInfo: map[string]interface{}{
					"hostname":    ip.Hostname,
					"description": ip.Description,
					"port":        ip.Port,
				},
			}, true, nil
		}
	}

	for _, domain := range enrichmentData.Domains {
		if query == domain.DomainName || strings.Contains(query, domain.DomainName) {
			return &models.EnrichmentLookupResult{
				Type:            "domain",
				Value:           query,
				TenantRealm:     realmName,
				EnvironmentID:   domain.EnvironmentID,
				EnvironmentName: domain.DomainName,
				Classification:  domain.DomainType,
				Purpose:         domain.Purpose,
				IsPrivate:       domain.Purpose == "internal",
				IsCritical:      domain.IsActive,
				AdditionalInfo: map[string]interface{}{
					"domain_name": domain.DomainName,
					"purpose":     domain.Purpose,
				},
			}, true, nil
		}
	}

	return &models.EnrichmentLookupResult{
		Type:           "unknown",
		Value:          query,
		TenantRealm:    realmName,
		Classification: "unknown",
		AdditionalInfo: map[string]interface{}{
			"status": "not_found",
			"query":  query,
		},
	}, false, nil
}

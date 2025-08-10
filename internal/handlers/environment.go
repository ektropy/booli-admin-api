package handlers

import (
	"context"
	"crypto/sha256"
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
	CreateTenantEnvironment(ctx context.Context, req *models.CreateTenantEnvironmentRequest, userTenantID uuid.UUID) (*models.TenantEnvironment, error)
	GetTenantEnvironment(ctx context.Context, environmentID uuid.UUID, userTenantID uuid.UUID) (*models.TenantEnvironment, error)
	ListTenantEnvironments(ctx context.Context, tenantID, userTenantID uuid.UUID, page, pageSize int) (*models.TenantEnvironmentListResponse, error)
	UpdateTenantEnvironment(ctx context.Context, environmentID uuid.UUID, req *models.UpdateTenantEnvironmentRequest, userTenantID uuid.UUID) (*models.TenantEnvironment, error)
	DeleteTenantEnvironment(ctx context.Context, environmentID uuid.UUID, userTenantID uuid.UUID) error
	GrantTenantAccess(ctx context.Context, req *models.CreateTenantAccessGrantRequest, granterTenantID uuid.UUID) (*models.TenantAccessGrant, error)
	RevokeAccess(ctx context.Context, grantID uuid.UUID, revokerTenantID uuid.UUID) error
	GetSIEMEnrichmentData(ctx context.Context, tenantID, userTenantID uuid.UUID) (*models.SIEMEnrichmentData, error)
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

// realmNameToUUID creates a deterministic UUID from a realm name for backward compatibility
// This is a temporary solution during the architectural transition
func (h *EnvironmentHandler) realmNameToUUID(realmName string) uuid.UUID {
	hash := sha256.Sum256([]byte(realmName))
	// Use the first 16 bytes of the hash to create a UUID
	var bytes [16]byte
	copy(bytes[:], hash[:16])
	// Set version (4) and variant bits to make it a valid UUID
	bytes[6] = (bytes[6] & 0x0f) | 0x40 // Version 4
	bytes[8] = (bytes[8] & 0x3f) | 0x80 // Variant 10
	return uuid.UUID(bytes)
}

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

	// Convert realm name to UUID for environment service compatibility
	userTenantID := h.realmNameToUUID(userRealmName)

	environment, err := h.environmentService.CreateTenantEnvironment(c.Request.Context(), &req, userTenantID)
	if err != nil {
		h.logger.Error("Failed to create environment",
			zap.String("realm_name", userRealmName),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to create environment", nil)
		return
	}

	c.JSON(http.StatusCreated, environment)
}

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

	// Convert realm name to UUID for environment service compatibility
	userTenantID := h.realmNameToUUID(userRealmName)

	environment, err := h.environmentService.GetTenantEnvironment(c.Request.Context(), environmentID, userTenantID)
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

	// Convert realm name to UUID for environment service compatibility
	userTenantID := h.realmNameToUUID(userRealmName)

	environments, err := h.environmentService.ListTenantEnvironments(c.Request.Context(), userTenantID, userTenantID, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list environments",
			zap.String("user_realm_name", userRealmName),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to list environments", nil)
		return
	}

	c.JSON(http.StatusOK, environments)
}

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

	// Convert realm name to UUID for environment service compatibility
	userTenantID := h.realmNameToUUID(userRealmName)

	environment, err := h.environmentService.UpdateTenantEnvironment(c.Request.Context(), environmentID, &req, userTenantID)
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

	// Convert realm name to UUID for environment service compatibility
	userTenantID := h.realmNameToUUID(userRealmName)

	err = h.environmentService.DeleteTenantEnvironment(c.Request.Context(), environmentID, userTenantID)
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
	// Convert string userID to UUID for legacy model compatibility
	if userUUID, err := uuid.Parse(userID); err == nil {
		req.GrantedBy = userUUID
	} else {
		req.GrantedBy = uuid.New() // fallback for non-UUID user IDs
	}

	// Convert realm name to UUID for environment service compatibility
	granterTenantID := h.realmNameToUUID(granterRealmName)

	grant, err := h.environmentService.GrantTenantAccess(c.Request.Context(), &req, granterTenantID)
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

	// Convert realm name to UUID for environment service compatibility
	revokerTenantID := h.realmNameToUUID(revokerRealmName)

	err = h.environmentService.RevokeAccess(c.Request.Context(), grantID, revokerTenantID)
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

func (h *EnvironmentHandler) GetSIEMEnrichmentData(c *gin.Context) {
	userRealmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
		return
	}

	// Convert realm name to UUID for environment service compatibility
	userTenantID := h.realmNameToUUID(userRealmName)
	enrichmentData, err := h.environmentService.GetSIEMEnrichmentData(c.Request.Context(), userTenantID, userTenantID)
	if err != nil {
		h.logger.Error("Failed to get SIEM enrichment data",
			zap.String("user_realm_name", userRealmName),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to get SIEM enrichment data", nil)
		return
	}

	c.JSON(http.StatusOK, enrichmentData)
}

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

func (h *EnvironmentHandler) GetNetworkRanges(c *gin.Context) {
	userRealmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
		return
	}

	// Convert realm name to UUID for environment service compatibility
	userTenantID := h.realmNameToUUID(userRealmName)
	enrichmentData, err := h.environmentService.GetSIEMEnrichmentData(c.Request.Context(), userTenantID, userTenantID)
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

func (h *EnvironmentHandler) GetInfrastructureIPs(c *gin.Context) {
	userRealmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
		return
	}

	// Convert realm name to UUID for environment service compatibility
	userTenantID := h.realmNameToUUID(userRealmName)
	enrichmentData, err := h.environmentService.GetSIEMEnrichmentData(c.Request.Context(), userTenantID, userTenantID)
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

	tenantID := h.realmNameToUUID(realmName)
	enrichmentData, err := h.environmentService.GetSIEMEnrichmentData(ctx, tenantID, tenantID)
	if err != nil {
		return nil, false, err
	}

	for _, networkRange := range enrichmentData.NetworkRanges {
		if strings.Contains(networkRange.CIDR, query) {
			return &models.EnrichmentLookupResult{
				Type:            "network",
				Value:           query,
				TenantID:        uuid.New(), // Legacy field, use RealmName instead
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
				TenantID:        uuid.New(), // Legacy field, use RealmName instead
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
				TenantID:        uuid.New(), // Legacy field, use RealmName instead
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
		TenantID:       uuid.New(), // Legacy field, use RealmName instead
		Classification: "unknown",
		AdditionalInfo: map[string]interface{}{
			"status": "not_found",
			"query":  query,
		},
	}, false, nil
}

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/booli/booli-admin-api/internal/config"
	"github.com/booli/booli-admin-api/internal/constants"
	"github.com/booli/booli-admin-api/internal/initialization"
	"github.com/booli/booli-admin-api/internal/utils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type HealthHandler struct {
	logger      *zap.Logger
	config      *config.Config
	initializer *initialization.KeycloakInitializer
	buildInfo   BuildInfo
}

func NewHealthHandler(logger *zap.Logger, cfg *config.Config, buildInfo BuildInfo) *HealthHandler {
	return &HealthHandler{
		logger:    logger,
		config:    cfg,
		buildInfo: buildInfo,
	}
}

func (h *HealthHandler) SetInitializer(initializer *initialization.KeycloakInitializer) {
	h.initializer = initializer
}

// @Summary Health check
// @Description Get application health status
// @Tags health
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /health [get]
func (h *HealthHandler) Check(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"service":   "booli-admin-api",
		"version":   h.buildInfo.Version,
	})
}

// @Summary Keycloak health check
// @Description Validate Keycloak configuration and connectivity
// @Tags health
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 503 {object} map[string]interface{}
// @Router /health/keycloak [get]
func (h *HealthHandler) ValidateKeycloak(c *gin.Context) {
	if h.initializer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":  "error",
			"message": "Keycloak validator not available",
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), constants.DefaultTimeout)
	defer cancel()

	var initConfig *initialization.InitializationConfig
	if h.config.Environment == "test" || h.config.Environment == "development" {
		callbackURL := h.config.Keycloak.CallbackURL
		if callbackURL == "" {
			callbackURL = fmt.Sprintf("http://localhost:%s%s", h.config.Server.Port, constants.PathAuthCallback)
		}
		initConfig = initialization.GetDefaultTestConfig(h.config.Keycloak.URL, callbackURL)
	} else {
		if envConfig, err := initialization.ParseConfigFromEnv(); err == nil && envConfig != nil {
			initConfig = envConfig
		}
	}

	if initConfig == nil {
		c.JSON(http.StatusOK, gin.H{
			"status":      "healthy",
			"message":     "No Keycloak configuration validation required",
			"environment": h.config.Environment,
		})
		return
	}

	if err := h.initializer.TestAuthentication(ctx); err != nil {
		h.logger.Error("Keycloak authentication test failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":      "unhealthy",
			"message":     "Keycloak authentication failed - check credentials",
			"error":       err.Error(),
			"environment": h.config.Environment,
		})
		return
	}

	if err := h.initializer.ValidateConfiguration(ctx, initConfig); err != nil {
		h.logger.Error("Keycloak configuration validation failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":      "unhealthy",
			"message":     "Keycloak configuration validation failed",
			"error":       err.Error(),
			"environment": h.config.Environment,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":      "healthy",
		"message":     "Keycloak configuration validated successfully",
		"environment": h.config.Environment,
		"realms":      len(initConfig.Realms),
		"clients":     len(initConfig.Clients),
		"providers":   len(initConfig.OIDCProviders),
	})
}

// @Summary Get API version info
// @Description Get information about the current API version using Calendar Versioning (CalVer)
// @Tags health
// @Produce json
// @Success 200 {object} map[string]interface{} "API version information"
// @Router /version [get]
func (h *HealthHandler) GetVersionInfo(c *gin.Context) {
	versionInfo := utils.GetAPIVersionInfo(constants.APIVersion)
	versionInfo["app_version"] = h.buildInfo.Version
	versionInfo["build_date"] = h.buildInfo.BuildDate
	versionInfo["commit"] = h.buildInfo.Commit
	versionInfo["built_by"] = h.buildInfo.BuiltBy
	versionInfo["environment"] = h.config.Environment
	
	c.JSON(http.StatusOK, versionInfo)
}

package handlers

import (
	"net/http"
	"strings"

	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/booli/booli-admin-api/internal/middleware"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/booli/booli-admin-api/internal/utils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type IdentityProviderHandler struct {
	identityProviderService *keycloak.IdentityProviderService
	logger                  *zap.Logger
}

func NewIdentityProviderHandler(identityProviderService *keycloak.IdentityProviderService, logger *zap.Logger) *IdentityProviderHandler {
	return &IdentityProviderHandler{
		identityProviderService: identityProviderService,
		logger:                  logger,
	}
}

// CreateIdentityProvider creates a new identity provider for a tenant realm
// @Summary Create identity provider
// @Description Create a new identity provider for federated authentication. Supports OIDC, OAuth2, SAML, and Microsoft Azure AD providers. Each provider type has specific configuration requirements. Client secrets are automatically masked in responses for security.
// @Description
// @Description **Supported Provider Types:**
// @Description - **oidc**: OpenID Connect providers (requires issuer_url, client_id, client_secret)
// @Description - **oauth2**: OAuth 2.0 providers (requires authorization_url, token_url, client_id, client_secret)  
// @Description - **saml**: SAML 2.0 providers (requires sso_service_url, entity_id)
// @Description - **microsoft**: Microsoft Azure AD (requires client_id, client_secret, azure_tenant_id)
// @Description
// @Description **Features:**
// @Description - Automatic attribute mapping creation
// @Description - Protocol-specific validation
// @Description - Secure client secret handling
// @Description - Support for custom scopes and configurations
// @Tags identity-providers
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.CreateIdentityProviderRequest true "Identity provider configuration"
// @Success 201 {object} models.IdentityProviderResponse "Successfully created identity provider"
// @Failure 400 {object} models.ErrorResponseSwagger "Invalid request body or unsupported provider type"
// @Failure 401 {object} models.ErrorResponseSwagger "Unauthorized access"
// @Failure 403 {object} models.ErrorResponseSwagger "Forbidden - insufficient permissions"
// @Failure 409 {object} models.ErrorResponseSwagger "Conflict - provider alias already exists"
// @Failure 500 {object} models.ErrorResponseSwagger "Internal server error"
// @Router /identity-providers [post]
func (h *IdentityProviderHandler) CreateIdentityProvider(c *gin.Context) {
	realmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
		return
	}

	var req models.CreateIdentityProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", utils.FormatValidationErrors(err))
		return
	}

	// Validate protocol-specific configuration requirements
	if err := req.ValidateConfiguration(); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, err.Error(), nil)
		return
	}

	keycloakProvider := req.ToKeycloakRepresentation()
	if keycloakProvider == nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid identity provider configuration", nil)
		return
	}
	
	// Add mappers to the provider for creation
	keycloakProvider.Mappers = req.BuildAttributeMappers()
	
	err = h.identityProviderService.CreateIdentityProvider(c.Request.Context(), realmName, keycloakProvider)
	if err != nil {
		h.logger.Error("Failed to create identity provider",
			zap.String("realm", realmName),
			zap.String("alias", req.Alias),
			zap.String("type", string(req.Type)),
			zap.Error(err))
			
		// Check if it's a conflict error (provider already exists)
		if strings.Contains(err.Error(), "already exists") {
			utils.RespondWithError(c, http.StatusConflict, utils.ErrCodeConflict, err.Error(), nil)
		} else {
			utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to create identity provider", nil)
		}
		return
	}

	createdProvider, err := h.identityProviderService.GetIdentityProvider(c.Request.Context(), realmName, req.Alias)
	if err != nil {
		h.logger.Warn("Identity provider created but failed to retrieve details",
			zap.String("realm", realmName),
			zap.String("alias", req.Alias),
			zap.Error(err))
	}

	response := models.IdentityProviderResponse{
		Alias:       req.Alias,
		DisplayName: req.DisplayName,
		Type:        req.Type,
		Enabled:     req.Enabled,
	}

	if createdProvider != nil {
		response.Config = createdProvider.Config
		for _, mapper := range createdProvider.Mappers {
			response.Mappers = append(response.Mappers, models.AttributeMappingResponse{
				ID:     mapper.ID,
				Name:   mapper.Name,
				Type:   mapper.IdentityProviderMapper,
				Config: mapper.Config,
			})
		}
	}

	c.JSON(http.StatusCreated, response)
}

// GetIdentityProvider retrieves an identity provider by alias
// @Summary Get identity provider
// @Description Get details of a specific identity provider by alias. Client secrets are automatically masked as "**********" for security purposes.
// @Tags identity-providers
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param alias path string true "Identity provider alias"
// @Success 200 {object} models.IdentityProviderResponse "Successfully retrieved identity provider"
// @Failure 400 {object} models.ErrorResponseSwagger "Bad request - invalid alias"
// @Failure 401 {object} models.ErrorResponseSwagger "Unauthorized access"
// @Failure 404 {object} models.ErrorResponseSwagger "Identity provider not found"
// @Failure 500 {object} models.ErrorResponseSwagger "Internal server error"
// @Router /identity-providers/{alias} [get]
func (h *IdentityProviderHandler) GetIdentityProvider(c *gin.Context) {
	alias := c.Param("alias")
	
	if alias == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Alias is required", nil)
		return
	}

	realmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
		return
	}

	provider, err := h.identityProviderService.GetIdentityProvider(c.Request.Context(), realmName, alias)
	if err != nil {
		h.logger.Error("Failed to get identity provider",
			zap.String("realm", realmName),
			zap.String("alias", alias),
			zap.Error(err))
		
		if err.Error() == "identity provider not found" {
			utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, "Identity provider not found", nil)
			return
		}
		
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to get identity provider", nil)
		return
	}

	response := models.IdentityProviderResponse{
		Alias:       provider.Alias,
		DisplayName: provider.DisplayName,
		Type:        models.IdentityProviderType(provider.ProviderId),
		Enabled:     provider.Enabled,
		Config:      provider.Config,
	}

	for _, mapper := range provider.Mappers {
		response.Mappers = append(response.Mappers, models.AttributeMappingResponse{
			ID:     mapper.ID,
			Name:   mapper.Name,
			Type:   mapper.IdentityProviderMapper,
			Config: mapper.Config,
		})
	}

	c.JSON(http.StatusOK, response)
}

// UpdateIdentityProvider updates an existing identity provider
// @Summary Update identity provider
// @Description Update an existing identity provider configuration. All fields can be updated including provider type, configuration, and attribute mappings. Client secrets are automatically masked in responses.
// @Tags identity-providers
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param alias path string true "Identity provider alias"
// @Param request body models.CreateIdentityProviderRequest true "Updated identity provider configuration"
// @Success 200 {object} models.IdentityProviderResponse "Successfully updated identity provider"
// @Failure 400 {object} models.ErrorResponseSwagger "Bad request - invalid configuration"
// @Failure 401 {object} models.ErrorResponseSwagger "Unauthorized access"
// @Failure 404 {object} models.ErrorResponseSwagger "Identity provider not found"
// @Failure 500 {object} models.ErrorResponseSwagger "Internal server error"
// @Router /identity-providers/{alias} [put]
func (h *IdentityProviderHandler) UpdateIdentityProvider(c *gin.Context) {
	alias := c.Param("alias")
	
	if alias == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Alias is required", nil)
		return
	}

	var req models.CreateIdentityProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", utils.FormatValidationErrors(err))
		return
	}

	// Validate protocol-specific configuration requirements
	if err := req.ValidateConfiguration(); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, err.Error(), nil)
		return
	}

	realmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
		return
	}

	keycloakProvider := req.ToKeycloakRepresentation()
	if keycloakProvider == nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid identity provider configuration", nil)
		return
	}
	keycloakProvider.Alias = alias
	
	// Add mappers to the provider for update
	keycloakProvider.Mappers = req.BuildAttributeMappers()
	
	err = h.identityProviderService.UpdateIdentityProvider(c.Request.Context(), realmName, alias, keycloakProvider)
	if err != nil {
		h.logger.Error("Failed to update identity provider",
			zap.String("realm", realmName),
			zap.String("alias", alias),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to update identity provider", nil)
		return
	}

	updatedProvider, err := h.identityProviderService.GetIdentityProvider(c.Request.Context(), realmName, alias)
	if err != nil {
		h.logger.Warn("Identity provider updated but failed to retrieve details",
			zap.String("realm", realmName),
			zap.String("alias", alias),
			zap.Error(err))
	}

	response := models.IdentityProviderResponse{
		Alias:       alias,
		DisplayName: req.DisplayName,
		Type:        req.Type,
		Enabled:     req.Enabled,
	}

	if updatedProvider != nil {
		response.Config = updatedProvider.Config
		for _, mapper := range updatedProvider.Mappers {
			response.Mappers = append(response.Mappers, models.AttributeMappingResponse{
				ID:     mapper.ID,
				Name:   mapper.Name,
				Type:   mapper.IdentityProviderMapper,
				Config: mapper.Config,
			})
		}
	}

	c.JSON(http.StatusOK, response)
}

// DeleteIdentityProvider deletes an identity provider
// @Summary Delete identity provider
// @Description Delete an identity provider from the tenant realm. This action cannot be undone and will remove all associated configurations and attribute mappings.
// @Tags identity-providers
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param alias path string true "Identity provider alias"
// @Success 204 "Identity provider deleted successfully"
// @Failure 400 {object} models.ErrorResponseSwagger "Bad request - invalid alias"
// @Failure 401 {object} models.ErrorResponseSwagger "Unauthorized access"
// @Failure 404 {object} models.ErrorResponseSwagger "Identity provider not found"
// @Failure 500 {object} models.ErrorResponseSwagger "Internal server error"
// @Router /identity-providers/{alias} [delete]
func (h *IdentityProviderHandler) DeleteIdentityProvider(c *gin.Context) {
	alias := c.Param("alias")
	
	if alias == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Alias is required", nil)
		return
	}

	realmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
		return
	}

	err = h.identityProviderService.DeleteIdentityProvider(c.Request.Context(), realmName, alias)
	if err != nil {
		h.logger.Error("Failed to delete identity provider",
			zap.String("realm", realmName),
			zap.String("alias", alias),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to delete identity provider", nil)
		return
	}

	c.Status(http.StatusNoContent)
}

// ListIdentityProviders lists all identity providers for a tenant realm
// @Summary List identity providers
// @Description Get a list of all identity providers configured for a tenant realm. Returns all provider types (OIDC, OAuth2, SAML, Microsoft) with their configurations. Client secrets are automatically masked for security.
// @Tags identity-providers
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {array} models.IdentityProviderResponse "Successfully retrieved list of identity providers"
// @Failure 400 {object} models.ErrorResponseSwagger "Bad request"
// @Failure 401 {object} models.ErrorResponseSwagger "Unauthorized access"
// @Failure 500 {object} models.ErrorResponseSwagger "Internal server error"
// @Router /identity-providers [get]
func (h *IdentityProviderHandler) ListIdentityProviders(c *gin.Context) {
	realmName, err := middleware.GetRealmName(c)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid realm context", nil)
		return
	}

	providers, err := h.identityProviderService.ListIdentityProviders(c.Request.Context(), realmName)
	if err != nil {
		h.logger.Error("Failed to list identity providers",
			zap.String("realm", realmName),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to list identity providers", nil)
		return
	}

	var response []models.IdentityProviderResponse
	for _, provider := range providers {
		providerResponse := models.IdentityProviderResponse{
			Alias:       provider.Alias,
			DisplayName: provider.DisplayName,
			Type:        models.IdentityProviderType(provider.ProviderId),
			Enabled:     provider.Enabled,
			Config:      provider.Config,
		}

		for _, mapper := range provider.Mappers {
			providerResponse.Mappers = append(providerResponse.Mappers, models.AttributeMappingResponse{
				ID:     mapper.ID,
				Name:   mapper.Name,
				Type:   mapper.IdentityProviderMapper,
				Config: mapper.Config,
			})
		}

		response = append(response, providerResponse)
	}

	c.JSON(http.StatusOK, response)
}
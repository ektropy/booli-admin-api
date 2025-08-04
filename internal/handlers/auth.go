package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/booli/booli-admin-api/internal/auth"
	"github.com/booli/booli-admin-api/internal/utils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type OIDCProviderInterface interface {
	GetWellKnownConfig(ctx context.Context) (map[string]interface{}, error)
	GenerateAuthURL(state string) string
	ExchangeCodeForToken(ctx context.Context, code string) (*oauth2.Token, error)
	VerifyIDToken(ctx context.Context, rawIDToken string) (*auth.OIDCClaims, error)
	VerifyAccessToken(ctx context.Context, accessToken string) (*auth.OIDCClaims, error)
	GetClientCredentialsToken(ctx context.Context, scopes []string) (*oauth2.Token, error)
}

type OIDCServiceInterface interface {
	GetProviderNames() []string
	GetProvider(name string) (*auth.OIDCProvider, error)
	ValidateToken(ctx context.Context, providerName, token string) (*auth.OIDCClaims, error)
	ValidateServiceToken(ctx context.Context, providerName, token string) (*auth.OIDCClaims, error)
}

type AuthHandler struct {
	oidcService OIDCServiceInterface
	logger      *zap.Logger
}

func NewAuthHandler(oidcService OIDCServiceInterface, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{
		oidcService: oidcService,
		logger:      logger,
	}
}

// @Summary Get authentication providers
// @Description Get list of available OIDC authentication providers
// @Tags authentication
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /auth/providers [get]
func (h *AuthHandler) GetProviders(c *gin.Context) {
	providers := h.oidcService.GetProviderNames()

	c.JSON(http.StatusOK, gin.H{
		"providers": providers,
		"default":   "keycloak",
	})
}

// @Summary Get provider well-known configuration
// @Description Get OIDC well-known configuration for a specific provider
// @Tags authentication
// @Produce json
// @Param provider path string true "Provider name"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/providers/{provider}/.well-known [get]
func (h *AuthHandler) GetWellKnown(c *gin.Context) {
	providerName := c.Param("provider")
	if providerName == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Provider name is required", nil)
		return
	}

	provider, err := h.oidcService.GetProvider(providerName)
	if err != nil {
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, fmt.Sprintf("Provider '%s' not found", providerName), nil)
		return
	}

	config, err := provider.GetWellKnownConfig(c.Request.Context())
	if err != nil {
		h.logger.Error("Failed to get well-known configuration",
			zap.String("provider", providerName),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to retrieve well-known configuration", nil)
		return
	}

	c.JSON(http.StatusOK, config)
}

// @Summary Initiate login
// @Description Start OAuth2/OIDC login flow
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body object{provider=string,redirect_uri=string,state=string} true "Login request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /auth/login [post]
func (h *AuthHandler) InitiateLogin(c *gin.Context) {
	var req struct {
		Provider    string `json:"provider" binding:"required"`
		RedirectURI string `json:"redirect_uri"`
		State       string `json:"state"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	provider, err := h.oidcService.GetProvider(req.Provider)
	if err != nil {
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, fmt.Sprintf("Provider '%s' not found", req.Provider), nil)
		return
	}

	authURL := provider.GenerateAuthURL(req.State)

	c.JSON(http.StatusOK, gin.H{
		"auth_url": authURL,
		"provider": req.Provider,
		"state":    req.State,
	})
}

// @Summary Handle OAuth callback
// @Description Handle OAuth2/OIDC callback and exchange code for tokens
// @Tags authentication
// @Produce json
// @Param provider query string false "Provider name"
// @Param code query string true "Authorization code"
// @Param state query string false "State parameter"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/callback [get]
func (h *AuthHandler) HandleCallback(c *gin.Context) {
	providerName := c.Query("provider")
	if providerName == "" {
		providerName = "keycloak"
	}

	code := c.Query("code")
	state := c.Query("state")
	errorParam := c.Query("error")

	if errorParam != "" {
		errorDesc := c.Query("error_description")
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, errorParam, errorDesc)
		return
	}

	if code == "" {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Authorization code is required", nil)
		return
	}

	provider, err := h.oidcService.GetProvider(providerName)
	if err != nil {
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, fmt.Sprintf("Provider '%s' not found", providerName), nil)
		return
	}

	token, err := provider.ExchangeCodeForToken(c.Request.Context(), code)
	if err != nil {
		h.logger.Error("Failed to exchange code for token",
			zap.String("provider", providerName),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to exchange authorization code", nil)
		return
	}

	rawIDToken := ""
	if extra := token.Extra("id_token"); extra != nil {
		if idToken, ok := extra.(string); ok {
			rawIDToken = idToken
		}
	}

	if rawIDToken == "" {
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "ID token not found in response", nil)
		return
	}

	claims, err := provider.VerifyIDToken(c.Request.Context(), rawIDToken)
	if err != nil {
		h.logger.Error("Failed to verify ID token",
			zap.String("provider", providerName),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid ID token", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  token.AccessToken,
		"id_token":      rawIDToken,
		"refresh_token": token.RefreshToken,
		"token_type":    token.TokenType,
		"expires_in":    int64(token.Expiry.Unix()),
		"user": gin.H{
			"sub":            claims.Subject,
			"email":          claims.Email,
			"name":           claims.Name,
			"given_name":     claims.GivenName,
			"family_name":    claims.FamilyName,
			"email_verified": claims.EmailVerified,
			"roles":          claims.RealmAccess.Roles,
		},
		"provider": providerName,
		"state":    state,
	})
}

// @Summary Validate token
// @Description Validate an access token or ID token
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body object{token=string,provider=string} true "Token validation request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Router /auth/validate [post]
func (h *AuthHandler) ValidateToken(c *gin.Context) {
	var req struct {
		Token    string `json:"token" binding:"required"`
		Provider string `json:"provider"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Provider == "" {
		req.Provider = "keycloak"
	}

	claims, err := h.oidcService.ValidateToken(c.Request.Context(), req.Provider, req.Token)
	if err != nil {
		h.logger.Error("Token validation failed",
			zap.String("provider", req.Provider),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Token validation failed", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid": true,
		"user": gin.H{
			"sub":            claims.Subject,
			"email":          claims.Email,
			"name":           claims.Name,
			"given_name":     claims.GivenName,
			"family_name":    claims.FamilyName,
			"email_verified": claims.EmailVerified,
			"roles":          claims.RealmAccess.Roles,
		},
		"provider": req.Provider,
	})
}

// @Summary Logout
// @Description Logout user and invalidate tokens
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body object{token=string,provider=string} true "Logout request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	var req struct {
		Provider              string `json:"provider"`
		IDTokenHint           string `json:"id_token_hint"`
		PostLogoutRedirectURI string `json:"post_logout_redirect_uri"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Provider == "" {
		req.Provider = "keycloak"
	}

	provider, err := h.oidcService.GetProvider(req.Provider)
	if err != nil {
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, fmt.Sprintf("Provider '%s' not found", req.Provider), nil)
		return
	}

	config, err := provider.GetWellKnownConfig(c.Request.Context())
	if err != nil {
		h.logger.Error("Failed to get well-known configuration for logout",
			zap.String("provider", req.Provider),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to get logout endpoint", nil)
		return
	}

	endSessionEndpoint, ok := config["end_session_endpoint"].(string)
	if !ok {
		c.JSON(http.StatusOK, gin.H{
			"message":  "Logout successful (no end session endpoint)",
			"provider": req.Provider,
		})
		return
	}

	logoutURL, err := url.Parse(endSessionEndpoint)
	if err != nil {
		h.logger.Error("Failed to parse logout URL",
			zap.String("provider", req.Provider),
			zap.String("endpoint", endSessionEndpoint),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Invalid logout endpoint", nil)
		return
	}

	query := logoutURL.Query()
	if req.IDTokenHint != "" {
		query.Set("id_token_hint", req.IDTokenHint)
	}
	if req.PostLogoutRedirectURI != "" {
		query.Set("post_logout_redirect_uri", req.PostLogoutRedirectURI)
	}
	logoutURL.RawQuery = query.Encode()

	c.JSON(http.StatusOK, gin.H{
		"logout_url": logoutURL.String(),
		"provider":   req.Provider,
	})
}

// @Summary Get user info
// @Description Get user information from access token
// @Tags authentication
// @Produce json
// @Param provider query string false "Provider name"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/userinfo [get]
func (h *AuthHandler) GetUserInfo(c *gin.Context) {
	providerName := c.Query("provider")
	if providerName == "" {
		providerName = "keycloak"
	}

	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Authorization header required", nil)
		return
	}

	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Invalid authorization header format", nil)
		return
	}

	accessToken := authHeader[len(bearerPrefix):]

	provider, err := h.oidcService.GetProvider(providerName)
	if err != nil {
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, fmt.Sprintf("Provider '%s' not found", providerName), nil)
		return
	}

	claims, err := provider.VerifyAccessToken(context.Background(), accessToken)
	if err != nil {
		h.logger.Error("Failed to get user info",
			zap.String("provider", providerName),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Failed to get user information", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"sub":            claims.Subject,
		"email":          claims.Email,
		"name":           claims.Name,
		"given_name":     claims.GivenName,
		"family_name":    claims.FamilyName,
		"email_verified": claims.EmailVerified,
		"roles":          claims.RealmAccess.Roles,
		"provider":       providerName,
	})
}

// @Summary Get service token
// @Description Get service-to-service authentication token
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body object{client_id=string,client_secret=string,scope=string} true "Service token request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Router /auth/service-token [post]
func (h *AuthHandler) GetServiceToken(c *gin.Context) {
	var req struct {
		Provider string   `json:"provider"`
		Scopes   []string `json:"scopes"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Provider == "" {
		req.Provider = "keycloak"
	}

	if len(req.Scopes) == 0 {
		req.Scopes = []string{"openid"}
	}

	provider, err := h.oidcService.GetProvider(req.Provider)
	if err != nil {
		utils.RespondWithError(c, http.StatusNotFound, utils.ErrCodeNotFound, fmt.Sprintf("Provider '%s' not found", req.Provider), nil)
		return
	}

	token, err := provider.GetClientCredentialsToken(c.Request.Context(), req.Scopes)
	if err != nil {
		h.logger.Error("Failed to get service token",
			zap.String("provider", req.Provider),
			zap.Strings("scopes", req.Scopes),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusInternalServerError, utils.ErrCodeInternalError, "Failed to get service token", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": token.AccessToken,
		"token_type":   token.TokenType,
		"expires_in":   int64(token.Expiry.Unix()),
		"scope":        req.Scopes,
		"provider":     req.Provider,
	})
}

// @Summary Validate service token
// @Description Validate a service-to-service token
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body object{token=string,provider=string} true "Service token validation request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Router /auth/service-validate [post]
func (h *AuthHandler) ValidateServiceToken(c *gin.Context) {
	var req struct {
		Token    string `json:"token" binding:"required"`
		Provider string `json:"provider"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, utils.ErrCodeBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Provider == "" {
		req.Provider = "keycloak"
	}

	claims, err := h.oidcService.ValidateServiceToken(c.Request.Context(), req.Provider, req.Token)
	if err != nil {
		h.logger.Error("Service token validation failed",
			zap.String("provider", req.Provider),
			zap.Error(err))
		utils.RespondWithError(c, http.StatusUnauthorized, utils.ErrCodeUnauthorized, "Service token validation failed", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":    true,
		"sub":      claims.Subject,
		"provider": req.Provider,
		"type":     "service_account",
	})
}

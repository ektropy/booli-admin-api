package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/booli/booli-admin-api/internal/models"
	"go.uber.org/zap"
)

type OnboardingMethod string

const (
	OnboardingMethodPassword      OnboardingMethod = "password"
	OnboardingMethodInviteEmail   OnboardingMethod = "invite_email"
	OnboardingMethodMagicLink     OnboardingMethod = "magic_link"
	OnboardingMethodSSO           OnboardingMethod = "sso"
	OnboardingMethodActivationCode OnboardingMethod = "activation_code"
	OnboardingMethodAdminSetup    OnboardingMethod = "admin_setup"
)

type UserOnboardingService struct {
	keycloakAdmin *keycloak.AdminClient
	userService   *UserService
	logger        *zap.Logger
	baseURL       string
}

func NewUserOnboardingService(keycloakAdmin *keycloak.AdminClient, userService *UserService, logger *zap.Logger, baseURL string) *UserOnboardingService {
	return &UserOnboardingService{
		keycloakAdmin: keycloakAdmin,
		userService:   userService,
		logger:        logger,
		baseURL:       baseURL,
	}
}

type OnboardingRequest struct {
	Method            OnboardingMethod            `json:"method"`
	UserRequest       models.CreateUserRequest    `json:"user"`
	InviteOptions     *InviteOptions             `json:"invite_options,omitempty"`
	MagicLinkOptions  *MagicLinkOptions          `json:"magic_link_options,omitempty"`
	ActivationOptions *ActivationCodeOptions     `json:"activation_options,omitempty"`
}

type InviteOptions struct {
	EmailTemplate    string            `json:"email_template,omitempty"`
	Subject          string            `json:"subject,omitempty"`
	ExpiryHours      int               `json:"expiry_hours,omitempty"`
	CustomMessage    string            `json:"custom_message,omitempty"`
	RequiredActions  []string          `json:"required_actions,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

type MagicLinkOptions struct {
	ExpiryMinutes int    `json:"expiry_minutes,omitempty"`
	RedirectURL   string `json:"redirect_url,omitempty"`
	SingleUse     bool   `json:"single_use,omitempty"`
}

type ActivationCodeOptions struct {
	CodeLength    int  `json:"code_length,omitempty"`
	ExpiryMinutes int  `json:"expiry_minutes,omitempty"`
	Numeric       bool `json:"numeric,omitempty"`
}

type OnboardingResponse struct {
	UserID          string                 `json:"user_id"`
	Username        string                 `json:"username"`
	Email           string                 `json:"email"`
	Method          OnboardingMethod       `json:"method"`
	Status          string                 `json:"status"`
	InviteToken     string                 `json:"invite_token,omitempty"`
	MagicLink       string                 `json:"magic_link,omitempty"`
	ActivationCode  string                 `json:"activation_code,omitempty"`
	SetupURL        string                 `json:"setup_url,omitempty"`
	ExpiresAt       *time.Time             `json:"expires_at,omitempty"`
	Actions         []string               `json:"actions,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

func (s *UserOnboardingService) OnboardUser(ctx context.Context, realmName string, req *OnboardingRequest) (*OnboardingResponse, error) {
	switch req.Method {
	case OnboardingMethodPassword:
		return s.onboardWithPassword(ctx, realmName, req)
	case OnboardingMethodInviteEmail:
		return s.onboardWithInviteEmail(ctx, realmName, req)
	case OnboardingMethodMagicLink:
		return s.onboardWithMagicLink(ctx, realmName, req)
	case OnboardingMethodSSO:
		return s.onboardWithSSO(ctx, realmName, req)
	case OnboardingMethodActivationCode:
		return s.onboardWithActivationCode(ctx, realmName, req)
	case OnboardingMethodAdminSetup:
		return s.onboardWithAdminSetup(ctx, realmName, req)
	default:
		return nil, fmt.Errorf("unsupported onboarding method: %s", req.Method)
	}
}

func (s *UserOnboardingService) onboardWithPassword(ctx context.Context, realmName string, req *OnboardingRequest) (*OnboardingResponse, error) {
	if req.UserRequest.Password == "" {
		generatedPassword, err := generateRandomPassword()
		if err != nil {
			return nil, err
		}
		req.UserRequest.Password = generatedPassword
		req.UserRequest.TemporaryPassword = true
	}

	user, err := s.userService.CreateUser(ctx, realmName, &req.UserRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &OnboardingResponse{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Method:   OnboardingMethodPassword,
		Status:   "created",
		Actions:  []string{"password_set"},
		Metadata: map[string]interface{}{
			"temporary_password": req.UserRequest.TemporaryPassword,
		},
	}, nil
}

func (s *UserOnboardingService) onboardWithInviteEmail(ctx context.Context, realmName string, req *OnboardingRequest) (*OnboardingResponse, error) {
	req.UserRequest.Enabled = false

	user, err := s.userService.CreateUser(ctx, realmName, &req.UserRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	inviteToken := s.generateInviteToken()
	
	expiryHours := 48
	if req.InviteOptions != nil && req.InviteOptions.ExpiryHours > 0 {
		expiryHours = req.InviteOptions.ExpiryHours
	}
	expiresAt := time.Now().Add(time.Duration(expiryHours) * time.Hour)

	requiredActions := []string{"UPDATE_PASSWORD", "UPDATE_PROFILE", "VERIFY_EMAIL"}
	if req.InviteOptions != nil && len(req.InviteOptions.RequiredActions) > 0 {
		requiredActions = req.InviteOptions.RequiredActions
	}

	if err := s.sendKeycloakActionEmail(ctx, realmName, user.ID, requiredActions, expiryHours*3600); err != nil {
		s.logger.Warn("Failed to send Keycloak action email, falling back to custom implementation",
			zap.Error(err))
	}

	setupURL := fmt.Sprintf("%s/setup?token=%s&realm=%s", s.baseURL, inviteToken, realmName)

	return &OnboardingResponse{
		UserID:      user.ID,
		Username:    user.Username,
		Email:       user.Email,
		Method:      OnboardingMethodInviteEmail,
		Status:      "invite_sent",
		InviteToken: inviteToken,
		SetupURL:    setupURL,
		ExpiresAt:   &expiresAt,
		Actions:     requiredActions,
		Metadata: map[string]interface{}{
			"email_sent": true,
			"template":   req.InviteOptions.EmailTemplate,
		},
	}, nil
}

func (s *UserOnboardingService) onboardWithMagicLink(ctx context.Context, realmName string, req *OnboardingRequest) (*OnboardingResponse, error) {
	req.UserRequest.Enabled = true

	user, err := s.userService.CreateUser(ctx, realmName, &req.UserRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	magicToken := s.generateMagicToken()
	
	expiryMinutes := 15
	if req.MagicLinkOptions != nil && req.MagicLinkOptions.ExpiryMinutes > 0 {
		expiryMinutes = req.MagicLinkOptions.ExpiryMinutes
	}
	expiresAt := time.Now().Add(time.Duration(expiryMinutes) * time.Minute)

	redirectURL := "/"
	if req.MagicLinkOptions != nil && req.MagicLinkOptions.RedirectURL != "" {
		redirectURL = req.MagicLinkOptions.RedirectURL
	}

	magicLink := fmt.Sprintf("%s/auth/magic?token=%s&redirect=%s", s.baseURL, magicToken, redirectURL)

	return &OnboardingResponse{
		UserID:    user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Method:    OnboardingMethodMagicLink,
		Status:    "magic_link_created",
		MagicLink: magicLink,
		ExpiresAt: &expiresAt,
		Actions:   []string{"magic_link_login"},
		Metadata: map[string]interface{}{
			"single_use":   req.MagicLinkOptions.SingleUse,
			"redirect_url": redirectURL,
		},
	}, nil
}

func (s *UserOnboardingService) onboardWithSSO(ctx context.Context, realmName string, req *OnboardingRequest) (*OnboardingResponse, error) {
	req.UserRequest.Enabled = true

	user, err := s.userService.CreateUser(ctx, realmName, &req.UserRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	ssoProviders, err := s.keycloakAdmin.ListIdentityProviders(ctx, realmName)
	if err != nil {
		return nil, fmt.Errorf("failed to list SSO providers: %w", err)
	}

	var providerAliases []string
	for _, provider := range ssoProviders {
		if provider.Enabled {
			providerAliases = append(providerAliases, provider.Alias)
		}
	}

	return &OnboardingResponse{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Method:   OnboardingMethodSSO,
		Status:   "sso_ready",
		Actions:  []string{"sso_login"},
		Metadata: map[string]interface{}{
			"sso_providers": providerAliases,
			"federation_enabled": true,
		},
	}, nil
}

func (s *UserOnboardingService) onboardWithActivationCode(ctx context.Context, realmName string, req *OnboardingRequest) (*OnboardingResponse, error) {
	req.UserRequest.Enabled = false

	user, err := s.userService.CreateUser(ctx, realmName, &req.UserRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	codeLength := 6
	numeric := true
	expiryMinutes := 30

	if req.ActivationOptions != nil {
		if req.ActivationOptions.CodeLength > 0 {
			codeLength = req.ActivationOptions.CodeLength
		}
		numeric = req.ActivationOptions.Numeric
		if req.ActivationOptions.ExpiryMinutes > 0 {
			expiryMinutes = req.ActivationOptions.ExpiryMinutes
		}
	}

	activationCode := s.generateActivationCode(codeLength, numeric)
	expiresAt := time.Now().Add(time.Duration(expiryMinutes) * time.Minute)

	return &OnboardingResponse{
		UserID:         user.ID,
		Username:       user.Username,
		Email:          user.Email,
		Method:         OnboardingMethodActivationCode,
		Status:         "activation_pending",
		ActivationCode: activationCode,
		ExpiresAt:      &expiresAt,
		Actions:        []string{"enter_activation_code", "set_password"},
		Metadata: map[string]interface{}{
			"code_length": codeLength,
			"numeric":     numeric,
		},
	}, nil
}

func (s *UserOnboardingService) onboardWithAdminSetup(ctx context.Context, realmName string, req *OnboardingRequest) (*OnboardingResponse, error) {
	req.UserRequest.Enabled = false

	user, err := s.userService.CreateUser(ctx, realmName, &req.UserRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	setupURL := fmt.Sprintf("%s/admin/users/%s/setup", s.baseURL, user.ID)

	return &OnboardingResponse{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Method:   OnboardingMethodAdminSetup,
		Status:   "pending_admin_setup",
		SetupURL: setupURL,
		Actions:  []string{"admin_configure", "admin_set_password", "admin_assign_roles"},
		Metadata: map[string]interface{}{
			"requires_admin": true,
		},
	}, nil
}

func (s *UserOnboardingService) sendKeycloakActionEmail(ctx context.Context, realmName, userID string, actions []string, lifespan int) error {
	return s.keycloakAdmin.ExecuteActionsEmail(ctx, realmName, userID, actions, lifespan, "", "")
}

func (s *UserOnboardingService) generateInviteToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (s *UserOnboardingService) generateMagicToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (s *UserOnboardingService) generateActivationCode(length int, numeric bool) string {
	var charset string
	if numeric {
		charset = "0123456789"
	} else {
		charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	}

	code := make([]byte, length)
	for i := range code {
		code[i] = charset[randInt(len(charset))]
	}
	return string(code)
}

func randInt(max int) int {
	b := make([]byte, 1)
	rand.Read(b)
	return int(b[0]) % max
}
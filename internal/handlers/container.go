package handlers

import (
	"github.com/booli/booli-admin-api/internal/auth"
	"github.com/booli/booli-admin-api/internal/config"
	"github.com/booli/booli-admin-api/internal/services"
	"go.uber.org/zap"
)

type Container struct {
	Health           *HealthHandler
	Auth             *AuthHandler
	Tenant           *TenantHandler
	User             *UserHandler
	SSO              *SSOHandler
	Audit            *AuditHandler
	Environment      *EnvironmentHandler
	IdentityProvider *IdentityProviderHandler
}

func NewContainer(services *services.Container, oidcService *auth.OIDCService, logger *zap.Logger, cfg *config.Config, version string) *Container {
	return &Container{
		Health:           NewHealthHandler(logger, cfg, version),
		Auth:             NewAuthHandler(oidcService, logger),
		Tenant:           NewTenantHandler(services.Tenant, logger),
		User:             NewUserHandler(services.User, logger),
		SSO:              NewSSOHandler(services.SSO, logger),
		Audit:            NewAuditHandler(services.Audit, logger),
		Environment:      NewEnvironmentHandler(services.Environment, logger),
		IdentityProvider: NewIdentityProviderHandler(services.IdentityProvider, logger),
	}
}

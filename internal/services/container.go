package services

import (
	"github.com/booli/booli-admin-api/internal/cache"
	"github.com/booli/booli-admin-api/internal/config"
	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type Container struct {
	Tenant           *TenantService
	User             *UserService
	SSO              *SSOService
	Audit            *AuditService
	Environment      *EnvironmentService
	IdentityProvider *keycloak.IdentityProviderService
	MSP              *MSPService
}

func NewContainer(db *gorm.DB, redis *redis.Client, keycloakAdmin *keycloak.AdminClient, logger *zap.Logger, cfg *config.Config) *Container {
	valkeyCache, err := cache.NewValkeyCache(cache.Config{
		Host:     cfg.Redis.Host,
		Port:     cfg.Redis.Port,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
		Prefix:   cfg.Redis.Prefix,
	}, logger)
	if err != nil {
		logger.Fatal("Failed to create Valkey cache", zap.Error(err))
	}

	return &Container{
		Tenant:           NewTenantService(keycloakAdmin, logger),
		User:             NewUserService(keycloakAdmin, logger),
		SSO:              NewSSOService(keycloakAdmin, logger),
		Audit:            NewAuditService(db, logger, cfg),
		Environment:      NewEnvironmentService(db, valkeyCache, logger),
		IdentityProvider: keycloak.NewIdentityProviderService(keycloakAdmin, logger),
		MSP:              NewMSPService(db, keycloakAdmin, logger),
	}
}

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
	Tenant      *TenantService
	User        *UserService
	Role        *RoleService
	SSO         *SSOService
	Audit       *AuditService
	Environment *EnvironmentService
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
		Tenant:      NewTenantService(db, redis, keycloakAdmin, logger, cfg),
		User:        NewUserService(db, redis, keycloakAdmin, logger, cfg),
		Role:        NewRoleService(db, redis, logger, cfg),
		SSO:         NewSSOService(db, redis, logger, cfg),
		Audit:       NewAuditService(db, redis, logger, cfg),
		Environment: NewEnvironmentService(db, valkeyCache, logger),
	}
}

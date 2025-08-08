package database

import (
	"context"
	"fmt"
	"time"

	"github.com/booli/booli-admin-api/internal/config"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Connect(cfg config.DatabaseConfig) (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s connect_timeout=10",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode,
	)

	gormLogger := logger.Default.LogMode(logger.Info)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormLogger,
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	sqlDB.SetMaxOpenConns(cfg.MaxConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdle)
	sqlDB.SetConnMaxLifetime(time.Hour)
	sqlDB.SetConnMaxIdleTime(time.Minute * 5)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

func ConnectRedis(cfg config.RedisConfig) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return client, nil
}

func SetupRowLevelSecurity(db *gorm.DB) error {

	roleSetup := []string{
		`DO $$
		BEGIN
			IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'application_role') THEN
				CREATE ROLE application_role;
			END IF;
		END
		$$;`,
		`GRANT USAGE ON SCHEMA public TO application_role;`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO application_role;`,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO application_role;`,
	}

	for _, roleSQL := range roleSetup {
		if err := db.Exec(roleSQL).Error; err != nil {
			return fmt.Errorf("failed to setup application role: %w", err)
		}
	}

	policies := []string{
		`ALTER TABLE roles ENABLE ROW LEVEL SECURITY;`,
		`DROP POLICY IF EXISTS tenant_roles_isolation ON roles;`,
		`CREATE POLICY tenant_roles_isolation ON roles
		 FOR ALL TO application_role
		 USING (tenant_id = current_setting('app.current_tenant')::UUID);`,

		`ALTER TABLE sso_providers ENABLE ROW LEVEL SECURITY;`,
		`DROP POLICY IF EXISTS tenant_sso_isolation ON sso_providers;`,
		`CREATE POLICY tenant_sso_isolation ON sso_providers
		 FOR ALL TO application_role
		 USING (tenant_id = current_setting('app.current_tenant')::UUID);`,

		`ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;`,
		`DROP POLICY IF EXISTS tenant_audit_isolation ON audit_logs;`,
		`CREATE POLICY tenant_audit_isolation ON audit_logs
		 FOR ALL TO application_role
		 USING (tenant_id = current_setting('app.current_tenant')::UUID);`,
	}

	for _, policy := range policies {
		if err := db.Exec(policy).Error; err != nil {
			return fmt.Errorf("failed to execute RLS policy: %w", err)
		}
	}

	return nil
}

func SetTenantContext(db *gorm.DB, tenantID string) error {
	return db.Exec("SET app.current_tenant = ?", tenantID).Error
}

func CreateIndexes(db *gorm.DB) error {
	indexes := []string{
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_roles_tenant_name ON roles(tenant_id, name);`,
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_roles_tenant_created ON roles(tenant_id, created_at DESC);`,

		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sso_providers_tenant_type ON sso_providers(tenant_id, provider_type);`,
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sso_providers_tenant_status ON sso_providers(tenant_id, status);`,

		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_tenant_created ON audit_logs(tenant_id, created_at DESC);`,
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_tenant_action ON audit_logs(tenant_id, action);`,
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_tenant_user ON audit_logs(tenant_id, user_id);`,

		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tenants_domain ON tenants(domain);`,
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tenants_keycloak_organization_id ON tenants(keycloak_organization_id);`,
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tenants_status ON tenants(status);`,
	}

	for _, index := range indexes {
		if err := db.Exec(index).Error; err != nil {
			// Silently ignore index creation errors as they're often due to concurrent attempts
		}
	}

	return nil
}

func CreateExtensions(db *gorm.DB) error {
	extensions := []string{
		`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`,
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`,
	}

	for _, ext := range extensions {
		if err := db.Exec(ext).Error; err != nil {
			return fmt.Errorf("failed to create extension: %w", err)
		}
	}

	return nil
}

func HealthCheck(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}

	return sqlDB.Ping()
}

func HealthCheckRedis(client *redis.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	return client.Ping(ctx).Err()
}

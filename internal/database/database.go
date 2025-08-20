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
	return ConnectWithEnv(cfg, "production")
}

func ConnectWithEnv(cfg config.DatabaseConfig, environment string) (*gorm.DB, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("database host is required")
	}
	if cfg.User == "" {
		return nil, fmt.Errorf("database user is required")
	}
	if cfg.DBName == "" {
		return nil, fmt.Errorf("database name (dbname) is required")
	}
	if cfg.SSLMode == "" {
		return nil, fmt.Errorf("database sslmode is required")
	}

	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s connect_timeout=%d",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode, cfg.ConnectTimeout,
	)

	safeDSN := fmt.Sprintf(
		"host=%s port=%d user=%s dbname=%s sslmode=%s connect_timeout=%d",
		cfg.Host, cfg.Port, cfg.User, cfg.DBName, cfg.SSLMode, cfg.ConnectTimeout,
	)
	fmt.Printf("Attempting database connection: %s\n", safeDSN)

	// Configure GORM logger based on environment
	var gormLogger logger.Interface
	if environment == "development" {
		gormLogger = logger.Default.LogMode(logger.Info)
	} else {
		// Production: only log errors and warnings, no SQL queries
		gormLogger = logger.Default.LogMode(logger.Warn)
	}

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
	sqlDB.SetConnMaxLifetime(time.Duration(cfg.MaxLifetime) * time.Second)
	sqlDB.SetConnMaxIdleTime(time.Duration(cfg.MaxIdleTime) * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.ConnectTimeout)*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

func ConnectRedis(cfg config.RedisConfig) (*redis.Client, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("redis host is required")
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	fmt.Printf("Attempting Redis connection: %s (db: %d, timeout: %ds)\n", addr, cfg.DB, cfg.DialTimeout)

	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  time.Duration(cfg.DialTimeout) * time.Second,
		ReadTimeout:  time.Duration(cfg.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.WriteTimeout) * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.DialTimeout)*time.Second)
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

	policies := []string{}

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
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);`,
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);`,

		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tenants_domain ON tenants(domain);`,
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tenants_status ON tenants(status);`,
	}

	for _, index := range indexes {
		if err := db.Exec(index).Error; err != nil {
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

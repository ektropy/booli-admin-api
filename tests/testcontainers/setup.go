package testcontainers

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	postgresContainer "github.com/testcontainers/testcontainers-go/modules/postgres"
	valkeyContainer "github.com/testcontainers/testcontainers-go/modules/valkey"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type TestContainerSetup struct {
	PostgresContainer testcontainers.Container
	ValkeyContainer   testcontainers.Container
	KeycloakContainer testcontainers.Container
	DB                *gorm.DB
	Valkey            *redis.Client
	PostgresDSN       string
	ValkeyAddr        string
	KeycloakURL       string
	Logger            *zap.Logger
}

func SetupTestContainers(ctx context.Context) (*TestContainerSetup, error) {
	logger, _ := zap.NewDevelopment()

	setup := &TestContainerSetup{
		Logger: logger,
	}

	if err := setup.setupPostgresContainer(ctx); err != nil {
		return nil, fmt.Errorf("failed to setup postgres container: %w", err)
	}

	if err := setup.setupValkeyContainer(ctx); err != nil {
		setup.Cleanup(ctx)
		return nil, fmt.Errorf("failed to setup valkey container: %w", err)
	}

	if err := setup.setupKeycloakContainer(ctx); err != nil {
		setup.Cleanup(ctx)
		return nil, fmt.Errorf("failed to setup keycloak container: %w", err)
	}

	if err := setup.connectToPostgres(); err != nil {
		setup.Cleanup(ctx)
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	if err := setup.connectToValkey(ctx); err != nil {
		setup.Cleanup(ctx)
		return nil, fmt.Errorf("failed to connect to valkey: %w", err)
	}

	return setup, nil
}

func (s *TestContainerSetup) setupPostgresContainer(ctx context.Context) error {
	container, err := postgresContainer.Run(ctx,
		"postgres:18-alpine",
		postgresContainer.WithDatabase("booli_admin_test"),
		postgresContainer.WithUsername("test"),
		postgresContainer.WithPassword("test"),
		postgresContainer.WithInitScripts("../../scripts/init-test-db.sql"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		return err
	}

	s.PostgresContainer = container

	host, err := container.Host(ctx)
	if err != nil {
		return err
	}

	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		return err
	}

	s.PostgresDSN = fmt.Sprintf("host=%s port=%s user=test password=test dbname=booli_admin_test sslmode=disable",
		host, port.Port())

	return nil
}

func (s *TestContainerSetup) setupValkeyContainer(ctx context.Context) error {
	container, err := valkeyContainer.Run(ctx,
		"valkey/valkey:8.0-alpine",
		testcontainers.WithWaitStrategy(
			wait.ForLog("Ready to accept connections").
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		return err
	}

	s.ValkeyContainer = container

	host, err := container.Host(ctx)
	if err != nil {
		return err
	}

	port, err := container.MappedPort(ctx, "6379")
	if err != nil {
		return err
	}

	s.ValkeyAddr = fmt.Sprintf("%s:%s", host, port.Port())

	return nil
}

func (s *TestContainerSetup) setupKeycloakContainer(ctx context.Context) error {
	req := testcontainers.ContainerRequest{
		Image:        "quay.io/keycloak/keycloak:26.0",
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"KEYCLOAK_ADMIN":          "admin",
			"KEYCLOAK_ADMIN_PASSWORD": "admin",
		},
		Cmd: []string{"start-dev", "--http-port=8080"},
		WaitingFor: wait.ForHTTP("/").
			WithPort("8080/tcp").
			WithStartupTimeout(2 * time.Minute),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return err
	}

	s.KeycloakContainer = container

	host, err := container.Host(ctx)
	if err != nil {
		return err
	}

	port, err := container.MappedPort(ctx, "8080")
	if err != nil {
		return err
	}

	s.KeycloakURL = fmt.Sprintf("http://%s:%s", host, port.Port())

	return nil
}

func (s *TestContainerSetup) connectToPostgres() error {
	gormLogger := logger.Default.LogMode(logger.Silent)

	db, err := gorm.Open(postgres.Open(s.PostgresDSN), &gorm.Config{
		Logger: gormLogger,
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		return err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return err
	}

	sqlDB.SetMaxOpenConns(10)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(time.Minute)

	if err := sqlDB.Ping(); err != nil {
		return err
	}

	s.DB = db
	return nil
}

func (s *TestContainerSetup) connectToValkey(ctx context.Context) error {
	client := redis.NewClient(&redis.Options{
		Addr:     s.ValkeyAddr,
		Password: "",
		DB:       0,
	})

	maxRetries := 5
	var err error
	for i := 0; i < maxRetries; i++ {
		err = client.Ping(ctx).Err()
		if err == nil {
			break
		}
		if i < maxRetries-1 {
			time.Sleep(time.Second)
		}
	}

	if err != nil {
		return err
	}

	s.Valkey = client
	return nil
}

func (s *TestContainerSetup) Cleanup(ctx context.Context) {
	if s.Valkey != nil {
		_ = s.Valkey.Close()
	}

	if s.DB != nil {
		if sqlDB, err := s.DB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}

	if s.KeycloakContainer != nil {
		_ = s.KeycloakContainer.Terminate(ctx)
	}

	if s.ValkeyContainer != nil {
		_ = s.ValkeyContainer.Terminate(ctx)
	}

	if s.PostgresContainer != nil {
		_ = s.PostgresContainer.Terminate(ctx)
	}
}

func (s *TestContainerSetup) ResetDatabase() error {
	tables := []string{
		"audit_logs",
		"user_roles",
		"sso_providers",
		"roles",
		"users",
		"tenants",
	}

	for _, table := range tables {
		if err := s.DB.Exec(fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table)).Error; err != nil {
			continue
		}
	}

	return nil
}

func (s *TestContainerSetup) ResetValkey(ctx context.Context) error {
	return s.Valkey.FlushAll(ctx).Err()
}

func (s *TestContainerSetup) RunMigrations() error {
	return s.DB.Exec(`
		-- Create extensions (PostgreSQL 18+ has built-in uuidv7() function)
		CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
		CREATE EXTENSION IF NOT EXISTS "pgcrypto";

		-- Create application role
		DO $$
		BEGIN
			IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'application_role') THEN
				CREATE ROLE application_role;
			END IF;
		END
		$$;

		-- Grant permissions
		GRANT CONNECT ON DATABASE booli_admin_test TO application_role;
		GRANT USAGE ON SCHEMA public TO application_role;
		GRANT CREATE ON SCHEMA public TO application_role;
	`).Error
}

func (s *TestContainerSetup) CreateTestTenant() error {
	return s.DB.Exec(`
		INSERT INTO tenants (id, name, domain, keycloak_realm, status, settings, created_at, updated_at)
		VALUES (
			uuidv7(),
			'Test Tenant',
			'test.example.com',
			'test-realm',
			'active',
			'{"enable_sso": true, "enable_mfa": false, "max_users": 1000}',
			NOW(),
			NOW()
		)
		ON CONFLICT DO NOTHING
	`).Error
}

func (s *TestContainerSetup) SetTenantContext(tenantID string) error {
	return s.DB.Exec("SET app.current_tenant = '" + tenantID + "'").Error
}

func (s *TestContainerSetup) GetTestDSN() string {
	return s.PostgresDSN
}

func (s *TestContainerSetup) GetTestValkeyAddr() string {
	return s.ValkeyAddr
}

func (s *TestContainerSetup) GetKeycloakURL() string {
	return s.KeycloakURL
}

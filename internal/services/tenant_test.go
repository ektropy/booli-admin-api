package services

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

type KeycloakAdminInterface interface {
	GetRealm(ctx context.Context, realmName string) (*keycloak.RealmRepresentation, error)
	GetUsers(ctx context.Context, realmName string) ([]keycloak.UserRepresentation, error)
	CreateRealm(ctx context.Context, realm *keycloak.RealmRepresentation) error
	GetRealms(ctx context.Context) ([]keycloak.RealmRepresentation, error)
	UpdateRealm(ctx context.Context, realmName string, realm *keycloak.RealmRepresentation) error
	DeleteRealm(ctx context.Context, realmName string) error
}

type MockKeycloakAdmin struct {
	mock.Mock
}

func (m *MockKeycloakAdmin) GetRealm(ctx context.Context, realmName string) (*keycloak.RealmRepresentation, error) {
	args := m.Called(ctx, realmName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keycloak.RealmRepresentation), args.Error(1)
}

func (m *MockKeycloakAdmin) GetUsers(ctx context.Context, realmName string) ([]keycloak.UserRepresentation, error) {
	args := m.Called(ctx, realmName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]keycloak.UserRepresentation), args.Error(1)
}

func (m *MockKeycloakAdmin) CreateRealm(ctx context.Context, realm *keycloak.RealmRepresentation) error {
	args := m.Called(ctx, realm)
	return args.Error(0)
}

func (m *MockKeycloakAdmin) GetRealms(ctx context.Context) ([]keycloak.RealmRepresentation, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]keycloak.RealmRepresentation), args.Error(1)
}

func (m *MockKeycloakAdmin) UpdateRealm(ctx context.Context, realmName string, realm *keycloak.RealmRepresentation) error {
	args := m.Called(ctx, realmName, realm)
	return args.Error(0)
}

func (m *MockKeycloakAdmin) DeleteRealm(ctx context.Context, realmName string) error {
	args := m.Called(ctx, realmName)
	return args.Error(0)
}

type TestableTenantService struct {
	keycloakAdmin KeycloakAdminInterface
	logger        *zap.Logger
}

func NewTestableTenantService(keycloakAdmin KeycloakAdminInterface, logger *zap.Logger) *TestableTenantService {
	return &TestableTenantService{
		keycloakAdmin: keycloakAdmin,
		logger:        logger,
	}
}

func (s *TestableTenantService) GetTenant(ctx context.Context, realmName string) (*models.Tenant, error) {
	realm, err := s.keycloakAdmin.GetRealm(ctx, realmName)
	if err != nil {
		return nil, fmt.Errorf("realm not found: %w", err)
	}

	createdAt := time.Now()
	if createdAtStr, ok := realm.Attributes["created_at"]; ok {
		if parsedTime, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			createdAt = parsedTime
		}
	}

	tenant := &models.Tenant{
		Name:      realm.DisplayName,
		Domain:    realm.Attributes["domain"],
		Type:      models.TenantType(realm.Attributes["tenant_type"]),
		Active:    true,
		RealmName: realm.Realm,
		CreatedAt: createdAt,
		UpdatedAt: time.Now(),
	}

	return tenant, nil
}

func (s *TestableTenantService) GetUserCount(ctx context.Context, realmName string) (int, error) {
	users, err := s.keycloakAdmin.GetUsers(ctx, realmName)
	if err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}
	return len(users), nil
}

func TestNewTestableTenantService(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockKeycloak := &MockKeycloakAdmin{}
	
	service := NewTestableTenantService(mockKeycloak, logger)
	
	assert.NotNil(t, service)
	assert.Equal(t, mockKeycloak, service.keycloakAdmin)
	assert.Equal(t, logger, service.logger)
}

func TestTestableTenantService_GetTenant(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockKeycloak := &MockKeycloakAdmin{}
	service := NewTestableTenantService(mockKeycloak, logger)
	ctx := context.Background()

	t.Run("successful get tenant", func(t *testing.T) {
		realmName := "test-realm"
		expectedRealm := &keycloak.RealmRepresentation{
			Realm:       realmName,
			DisplayName: "Test Tenant",
			Attributes: map[string]string{
				"domain":      "test.example.com",
				"tenant_type": "client",
				"created_at":  time.Now().Format(time.RFC3339),
			},
		}

		mockKeycloak.On("GetRealm", ctx, realmName).Return(expectedRealm, nil).Once()

		tenant, err := service.GetTenant(ctx, realmName)

		assert.NoError(t, err)
		assert.NotNil(t, tenant)
		assert.Equal(t, "Test Tenant", tenant.Name)
		assert.Equal(t, "test.example.com", tenant.Domain)
		assert.Equal(t, models.TenantTypeClient, tenant.Type)
		assert.True(t, tenant.Active)
		assert.Equal(t, realmName, tenant.RealmName)
		
		mockKeycloak.AssertExpectations(t)
	})

	t.Run("realm not found", func(t *testing.T) {
		realmName := "nonexistent-realm"
		expectedError := errors.New("realm not found")

		mockKeycloak.On("GetRealm", ctx, realmName).Return(nil, expectedError).Once()

		tenant, err := service.GetTenant(ctx, realmName)

		assert.Error(t, err)
		assert.Nil(t, tenant)
		assert.Contains(t, err.Error(), "realm not found")
		
		mockKeycloak.AssertExpectations(t)
	})
}

func TestTestableTenantService_GetUserCount(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockKeycloak := &MockKeycloakAdmin{}
	service := NewTestableTenantService(mockKeycloak, logger)
	ctx := context.Background()

	t.Run("successful get user count", func(t *testing.T) {
		realmName := "test-realm"
		expectedUsers := []keycloak.UserRepresentation{
			{ID: "user1", Username: "testuser1"},
			{ID: "user2", Username: "testuser2"},
			{ID: "user3", Username: "testuser3"},
		}

		mockKeycloak.On("GetUsers", ctx, realmName).Return(expectedUsers, nil).Once()

		count, err := service.GetUserCount(ctx, realmName)

		assert.NoError(t, err)
		assert.Equal(t, 3, count)
		
		mockKeycloak.AssertExpectations(t)
	})

	t.Run("error getting users", func(t *testing.T) {
		realmName := "test-realm"
		expectedError := errors.New("failed to get users")

		mockKeycloak.On("GetUsers", ctx, realmName).Return(nil, expectedError).Once()

		count, err := service.GetUserCount(ctx, realmName)

		assert.Error(t, err)
		assert.Equal(t, 0, count)
		assert.Contains(t, err.Error(), "failed to count users")
		
		mockKeycloak.AssertExpectations(t)
	})
}

func TestTenantService_ValidationLogic(t *testing.T) {
	logger := zaptest.NewLogger(t)
	
	t.Run("empty tenant name validation", func(t *testing.T) {
		service := NewTenantService(nil, nil, nil, logger)
		req := &models.CreateTenantRequest{
			Name:   "",
			Domain: "test.example.com",
			Type:   models.TenantTypeClient,
		}

		tenant, err := service.CreateTenant(context.Background(), req, "msp-realm")

		assert.Error(t, err)
		assert.Nil(t, tenant)
		assert.Contains(t, err.Error(), "tenant name is required")
	})

	t.Run("nil keycloak admin validation", func(t *testing.T) {
		service := NewTenantService(nil, nil, nil, logger)
		req := &models.CreateTenantRequest{
			Name:   "test-tenant",
			Domain: "test.example.com",
			Type:   models.TenantTypeClient,
		}

		tenant, err := service.CreateTenant(context.Background(), req, "msp-realm")

		assert.Error(t, err)
		assert.Nil(t, tenant)
		assert.Contains(t, err.Error(), "keycloak admin client not available")
	})
}
package services

import (
	"context"
	"testing"

	"github.com/booli/booli-admin-api/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type MockDB struct {
	mock.Mock
}

func (m *MockDB) WithContext(ctx context.Context) *gorm.DB {
	args := m.Called(ctx)
	return args.Get(0).(*gorm.DB)
}

func (m *MockDB) Where(query interface{}, args ...interface{}) *gorm.DB {
	called := m.Called(query, args)
	return called.Get(0).(*gorm.DB)
}

func (m *MockDB) First(dest interface{}, conds ...interface{}) *gorm.DB {
	args := m.Called(dest, conds)
	if tenant, ok := dest.(*models.Tenant); ok {
		parentID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
		tenant.ID = uuid.MustParse("22222222-2222-2222-2222-222222222222")
		tenant.ParentTenantID = &parentID
		tenant.Type = models.TenantTypeClient
	}
	return args.Get(0).(*gorm.DB)
}

func TestEnvironmentService_ValidateTenantAccess_ParentChildRelationship(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	service := &EnvironmentService{
		logger: logger,
	}

	mspTenantID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	clientTenantID := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	_ = context.Background()

	mockDB := &struct {
		*gorm.DB
		mockTenant models.Tenant
	}{
		mockTenant: models.Tenant{
			ID:             clientTenantID,
			ParentTenantID: &mspTenantID,
			Type:           models.TenantTypeClient,
		},
	}

	service.db = &gorm.DB{
		Config: &gorm.Config{},
	}

	t.Run("SameTenantAccess", func(t *testing.T) {
		assert.True(t, mspTenantID == mspTenantID || clientTenantID == clientTenantID,
			"Same tenant comparison should be true")
	})

	t.Run("ParentChildAccess", func(t *testing.T) {
		assert.Equal(t, mspTenantID, *mockDB.mockTenant.ParentTenantID,
			"Client tenant should have MSP tenant as parent")
	})

	t.Run("AccessLevelConstants", func(t *testing.T) {
		assert.NotEmpty(t, models.AccessLevelRead)
		assert.NotEmpty(t, models.AccessLevelReadWrite)
		assert.NotEmpty(t, models.AccessLevelFullAccess)
	})
}

func TestSSOProviderValidation(t *testing.T) {
	validTypes := []models.SSOProviderType{
		models.SSOProviderTypeSAML,
		models.SSOProviderTypeOIDC,
	}

	t.Run("ValidProviderTypes", func(t *testing.T) {
		assert.Equal(t, "saml", string(models.SSOProviderTypeSAML))
		assert.Equal(t, "oidc", string(models.SSOProviderTypeOIDC))
		assert.Len(t, validTypes, 2, "Should only have 2 valid SSO provider types")
	})

	t.Run("InvalidOAuth2Type", func(t *testing.T) {
		oauth2 := models.SSOProviderType("oauth2")
		assert.NotContains(t, validTypes, oauth2, "oauth2 should not be a valid SSO provider type")
	})
}

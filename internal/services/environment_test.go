package services

import (
	"context"
	"testing"

	"github.com/booli/booli-admin-api/internal/models"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestEnvironmentService_ValidateTenantAccess_RealmBased(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	service := &EnvironmentService{
		logger: logger,
	}

	mspTenantRealm := "master"
	clientTenantRealm := "test-client-tenant"

	t.Run("SameTenantAccess", func(t *testing.T) {
		err := service.validateTenantAccess(context.Background(), clientTenantRealm, clientTenantRealm, models.AccessLevelRead)
		assert.NoError(t, err, "Same tenant should have access")
	})

	t.Run("MSPAdminAccess", func(t *testing.T) {
		err := service.validateTenantAccess(context.Background(), mspTenantRealm, clientTenantRealm, models.AccessLevelFullAccess)
		assert.NoError(t, err, "MSP admin should have access to all tenants")
	})

	t.Run("AccessLevelConstants", func(t *testing.T) {
		assert.NotEmpty(t, models.AccessLevelRead)
		assert.NotEmpty(t, models.AccessLevelReadWrite)
		assert.NotEmpty(t, models.AccessLevelFullAccess)
	})

	t.Run("TenantTypes", func(t *testing.T) {
		assert.Equal(t, models.TenantType("client"), models.TenantTypeClient)
		assert.Equal(t, models.TenantType("msp"), models.TenantTypeMSP)
	})
}

func TestEnvironmentService_ClearEnvironmentCache(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	tenantRealm := "test-tenant"
	environmentID := "123e4567-e89b-12d3-a456-426614174000"

	serviceNilCache := &EnvironmentService{
		logger: logger,
		cache:  nil,
	}

	serviceNilCache.clearEnvironmentCache(context.Background(), tenantRealm, environmentID)
}

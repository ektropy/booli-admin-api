package handlers

import (
	"testing"

	"github.com/booli/booli-admin-api/internal/keycloak"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
)

func TestNewIdentityProviderHandler(t *testing.T) {
	logger := zaptest.NewLogger(t)

	mockClient := &keycloak.AdminClient{}
	service := keycloak.NewIdentityProviderService(mockClient, logger)

	handler := NewIdentityProviderHandler(service, logger)

	assert.NotNil(t, handler)
	assert.Equal(t, service, handler.identityProviderService)
	assert.Equal(t, logger, handler.logger)
}

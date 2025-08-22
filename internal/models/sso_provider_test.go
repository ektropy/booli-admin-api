package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSSOProvider_ToResponse(t *testing.T) {
	provider := &SSOProvider{
		Alias:        "test-provider",
		DisplayName:  "Test Provider",
		ProviderType: SSOProviderTypeOIDC,
		Enabled:      true,
		Config: map[string]interface{}{
			"clientId":     "test-client",
			"clientSecret": "secret123",
			"issuer":       "https://auth.example.com",
		},
	}

	response := provider.ToResponse()

	assert.NotNil(t, response)
	assert.Equal(t, "test-provider", response.Alias)
	assert.Equal(t, "Test Provider", response.DisplayName)
	assert.Equal(t, SSOProviderTypeOIDC, response.ProviderType)
	assert.True(t, response.Enabled)
	
	expectedConfig := map[string]interface{}{
		"clientId":     "test-client",
		"clientSecret": "secret123",
		"issuer":       "https://auth.example.com",
	}
	assert.Equal(t, expectedConfig, response.Config)
}

func TestSSOProvider_ToResponse_EmptyConfig(t *testing.T) {
	provider := &SSOProvider{
		Alias:        "empty-provider",
		DisplayName:  "Empty Provider",
		ProviderType: SSOProviderTypeSAML,
		Enabled:      false,
		Config:       nil,
	}

	response := provider.ToResponse()

	assert.NotNil(t, response)
	assert.Equal(t, "empty-provider", response.Alias)
	assert.Equal(t, "Empty Provider", response.DisplayName)
	assert.Equal(t, SSOProviderTypeSAML, response.ProviderType)
	assert.False(t, response.Enabled)
	assert.Empty(t, response.Config)
}
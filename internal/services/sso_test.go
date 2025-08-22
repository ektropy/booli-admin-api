package services

import (
	"testing"

	"github.com/booli/booli-admin-api/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestConvertStringMapToInterface(t *testing.T) {
	service := &SSOService{}
	
	stringMap := map[string]string{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	}
	
	interfaceMap := service.convertStringMapToInterface(stringMap)
	
	assert.Len(t, interfaceMap, 3)
	assert.Equal(t, "value1", interfaceMap["key1"])
	assert.Equal(t, "value2", interfaceMap["key2"])
	assert.Equal(t, "value3", interfaceMap["key3"])
}

func TestConvertInterfaceMapToString(t *testing.T) {
	service := &SSOService{}
	
	interfaceMap := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
		"key3": 123,
	}
	
	stringMap := service.convertInterfaceMapToString(interfaceMap)
	
	assert.Len(t, stringMap, 3)
	assert.Equal(t, "value1", stringMap["key1"])
	assert.Equal(t, "value2", stringMap["key2"])
	assert.Equal(t, "123", stringMap["key3"])
}

func TestMapProviderType(t *testing.T) {
	service := &SSOService{}
	
	testCases := []struct {
		input    string
		expected models.SSOProviderType
	}{
		{"oidc", models.SSOProviderTypeOIDC},
		{"saml", models.SSOProviderTypeSAML},
		{"oauth", models.SSOProviderTypeOIDC},
		{"unknown", models.SSOProviderTypeOIDC},
	}
	
	for _, tc := range testCases {
		result := service.mapProviderType(tc.input)
		assert.Equal(t, tc.expected, result, "Failed for input: %s", tc.input)
	}
}
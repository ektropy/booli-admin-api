package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTenant_IsActive(t *testing.T) {
	testCases := []struct {
		name     string
		active   bool
		expected bool
	}{
		{
			name:     "active tenant",
			active:   true,
			expected: true,
		},
		{
			name:     "inactive tenant",
			active:   false,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tenant := &Tenant{Active: tc.active}
			result := tenant.IsActive()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestTenant_CanProvisionUsers(t *testing.T) {
	t.Run("tenant with no max users limit", func(t *testing.T) {
		tenant := &Tenant{Active: true}
		result := tenant.CanProvisionUsers(5)
		assert.True(t, result)
	})

	t.Run("tenant under user limit", func(t *testing.T) {
		settings := TenantSettings{MaxUsers: 10}
		settingsJSON, _ := json.Marshal(settings)
		tenant := &Tenant{
			Active:   true,
			Settings: settingsJSON,
		}
		result := tenant.CanProvisionUsers(5)
		assert.True(t, result)
	})

	t.Run("tenant at user limit", func(t *testing.T) {
		settings := TenantSettings{MaxUsers: 10}
		settingsJSON, _ := json.Marshal(settings)
		tenant := &Tenant{
			Active:   true,
			Settings: settingsJSON,
		}
		result := tenant.CanProvisionUsers(10)
		assert.False(t, result)
	})

	t.Run("tenant over user limit", func(t *testing.T) {
		settings := TenantSettings{MaxUsers: 10}
		settingsJSON, _ := json.Marshal(settings)
		tenant := &Tenant{
			Active:   true,
			Settings: settingsJSON,
		}
		result := tenant.CanProvisionUsers(15)
		assert.False(t, result)
	})
}
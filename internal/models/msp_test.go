package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMSP_IsActive(t *testing.T) {
	testCases := []struct {
		name     string
		active   bool
		expected bool
	}{
		{
			name:     "active MSP",
			active:   true,
			expected: true,
		},
		{
			name:     "inactive MSP",
			active:   false,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msp := &MSP{Active: tc.active}
			result := msp.IsActive()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestMSP_CanManageClients(t *testing.T) {
	testCases := []struct {
		name     string
		active   bool
		expected bool
	}{
		{
			name:     "active MSP can manage clients",
			active:   true,
			expected: true,
		},
		{
			name:     "inactive MSP cannot manage clients",
			active:   false,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msp := &MSP{Active: tc.active}
			result := msp.CanManageClients()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestMSP_GetClientRealmPrefix(t *testing.T) {
	testCases := []struct {
		name           string
		clientPattern  string
		realmName      string
		expectedPrefix string
	}{
		{
			name:           "custom client pattern",
			clientPattern:  "custom-pattern-",
			realmName:      "test-realm",
			expectedPrefix: "custom-pattern-",
		},
		{
			name:           "msp realm with prefix",
			clientPattern:  "",
			realmName:      "msp-example",
			expectedPrefix: "example-client-",
		},
		{
			name:           "simple realm name",
			clientPattern:  "",
			realmName:      "simple",
			expectedPrefix: "simple-client-",
		},
		{
			name:           "short msp realm",
			clientPattern:  "",
			realmName:      "msp",
			expectedPrefix: "msp-client-",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msp := &MSP{
				ClientPattern: tc.clientPattern,
				RealmName:     tc.realmName,
			}
			result := msp.GetClientRealmPrefix()
			assert.Equal(t, tc.expectedPrefix, result)
		})
	}
}

func TestMSP_IsClientRealm(t *testing.T) {
	msp := &MSP{
		RealmName: "msp-example",
	}

	testCases := []struct {
		name      string
		realmName string
		expected  bool
	}{
		{
			name:      "valid client realm",
			realmName: "example-client-tenant1",
			expected:  true,
		},
		{
			name:      "another valid client realm",
			realmName: "example-client-tenant2",
			expected:  true,
		},
		{
			name:      "not a client realm",
			realmName: "other-realm",
			expected:  false,
		},
		{
			name:      "prefix only",
			realmName: "example-client-",
			expected:  false,
		},
		{
			name:      "empty realm name",
			realmName: "",
			expected:  false,
		},
		{
			name:      "msp realm itself",
			realmName: "msp-example",
			expected:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := msp.IsClientRealm(tc.realmName)
			assert.Equal(t, tc.expected, result)
		})
	}
}
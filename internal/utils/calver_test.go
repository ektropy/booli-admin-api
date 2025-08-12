package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidateCalVer(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected bool
	}{
		{"valid date", "2025-08-01", true},
		{"valid date 2", "2023-12-31", true},
		{"invalid format - no dashes", "20240812", false},
		{"invalid format - wrong separator", "2024/08/12", false},
		{"invalid format - short year", "24-08-12", false},
		{"invalid month", "2024-13-01", false},
		{"invalid day", "2024-08-32", false},
		{"empty string", "", false},
		{"non-date", "v1.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateCalVer(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseCalVer(t *testing.T) {
	t.Run("valid version", func(t *testing.T) {
		version := "2025-08-01"
		expected := time.Date(2025, 8, 1, 0, 0, 0, 0, time.UTC)
		
		result, err := ParseCalVer(version)
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
	})

	t.Run("invalid version", func(t *testing.T) {
		version := "invalid"
		
		_, err := ParseCalVer(version)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid CalVer format")
	})
}

func TestCurrentCalVer(t *testing.T) {
	result := CurrentCalVer()
	
	// Should be a valid CalVer format
	assert.True(t, ValidateCalVer(result))
	
	// Should be parseable as today's date
	parsed, err := ParseCalVer(result)
	assert.NoError(t, err)
	
	now := time.Now().UTC()
	assert.Equal(t, now.Year(), parsed.Year())
	assert.Equal(t, now.Month(), parsed.Month())
	assert.Equal(t, now.Day(), parsed.Day())
}

func TestIsVersionDeprecated(t *testing.T) {
	today := time.Now().UTC()
	
	t.Run("recent version", func(t *testing.T) {
		recentVersion := today.AddDate(0, 0, -5).Format(CalVerFormat)
		
		deprecated, err := IsVersionDeprecated(recentVersion, 30)
		assert.NoError(t, err)
		assert.False(t, deprecated)
	})

	t.Run("old version", func(t *testing.T) {
		oldVersion := today.AddDate(0, 0, -60).Format(CalVerFormat)
		
		deprecated, err := IsVersionDeprecated(oldVersion, 30)
		assert.NoError(t, err)
		assert.True(t, deprecated)
	})

	t.Run("invalid version", func(t *testing.T) {
		_, err := IsVersionDeprecated("invalid", 30)
		assert.Error(t, err)
	})
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int
	}{
		{"v1 older", "2025-07-15", "2025-08-01", -1},
		{"v1 newer", "2025-08-15", "2025-08-01", 1},
		{"equal", "2025-08-01", "2025-08-01", 0},
		{"different years", "2023-12-31", "2024-01-01", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CompareVersions(tt.v1, tt.v2)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}

	t.Run("invalid v1", func(t *testing.T) {
		_, err := CompareVersions("invalid", "2025-08-01")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid version v1")
	})
}

func TestGetAPIVersionInfo(t *testing.T) {
	t.Run("valid version", func(t *testing.T) {
		version := "2025-08-01"
		
		info := GetAPIVersionInfo(version)
		
		assert.Equal(t, version, info["current_version"])
		assert.Equal(t, "CalVer (YYYY-MM-DD)", info["version_format"])
		assert.Contains(t, info["description"], "Calendar versioning")
		assert.Equal(t, "https://calver.org/", info["documentation"])
		assert.Contains(t, info, "version_date")
		assert.Contains(t, info, "days_since_release")
	})

	t.Run("invalid version", func(t *testing.T) {
		version := "invalid"
		
		info := GetAPIVersionInfo(version)
		
		assert.Equal(t, version, info["current_version"])
		assert.NotContains(t, info, "version_date")
		assert.NotContains(t, info, "days_since_release")
	})
}
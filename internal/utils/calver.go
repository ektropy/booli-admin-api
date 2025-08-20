package utils

import (
	"fmt"
	"regexp"
	"time"
)

// CalVerFormat represents the calendar versioning format used by the API
const CalVerFormat = "2006-01-02"

var calverRegex = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

func ValidateCalVer(version string) bool {
	if !calverRegex.MatchString(version) {
		return false
	}
	
	_, err := time.Parse(CalVerFormat, version)
	return err == nil
}

func ParseCalVer(version string) (time.Time, error) {
	if !ValidateCalVer(version) {
		return time.Time{}, fmt.Errorf("invalid CalVer format: %s, expected YYYY-MM-DD", version)
	}
	
	return time.Parse(CalVerFormat, version)
}

func CurrentCalVer() string {
	return time.Now().UTC().Format(CalVerFormat)
}

// IsVersionDeprecated checks if a CalVer version is older than the specified number of days
func IsVersionDeprecated(version string, deprecationDays int) (bool, error) {
	versionTime, err := ParseCalVer(version)
	if err != nil {
		return false, err
	}
	
	deprecationDate := time.Now().UTC().AddDate(0, 0, -deprecationDays)
	return versionTime.Before(deprecationDate), nil
}

// CompareVersions compares two CalVer versions
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func CompareVersions(v1, v2 string) (int, error) {
	t1, err := ParseCalVer(v1)
	if err != nil {
		return 0, fmt.Errorf("invalid version v1: %w", err)
	}
	
	t2, err := ParseCalVer(v2)
	if err != nil {
		return 0, fmt.Errorf("invalid version v2: %w", err)
	}
	
	if t1.Before(t2) {
		return -1, nil
	}
	if t1.After(t2) {
		return 1, nil
	}
	return 0, nil
}

func GetAPIVersionInfo(currentVersion string) map[string]interface{} {
	info := map[string]interface{}{
		"current_version": currentVersion,
		"version_format":  "CalVer (YYYY-MM-DD)",
		"description":     "Calendar versioning - each date represents a potentially breaking change version",
		"documentation":   "https://calver.org/",
	}
	
	if ValidateCalVer(currentVersion) {
		if versionTime, err := ParseCalVer(currentVersion); err == nil {
			info["version_date"] = versionTime.UTC().Format(time.RFC3339)
			info["days_since_release"] = int(time.Since(versionTime).Hours() / 24)
		}
	}
	
	return info
}
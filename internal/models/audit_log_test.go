package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAuditDetails_Value(t *testing.T) {
	details := AuditDetails{
		Method: "POST",
		Path:   "/api/users",
		Query:  map[string]string{"page": "1"},
	}

	value, err := details.Value()
	assert.NoError(t, err)
	assert.NotNil(t, value)
	
	// Verify it's valid JSON
	var unmarshalled AuditDetails
	err = json.Unmarshal(value.([]byte), &unmarshalled)
	assert.NoError(t, err)
	assert.Equal(t, "POST", unmarshalled.Method)
	assert.Equal(t, "/api/users", unmarshalled.Path)
}

func TestAuditDetails_Scan(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected AuditDetails
		hasError bool
	}{
		{"Valid JSON string", `{"method":"GET","path":"/test"}`, AuditDetails{Method: "GET", Path: "/test"}, false},
		{"Valid JSON bytes", []byte(`{"method":"POST","path":"/users"}`), AuditDetails{Method: "POST", Path: "/users"}, false},
		{"Empty string", "{}", AuditDetails{}, false},
		{"Nil", nil, AuditDetails{}, false},
		{"Invalid JSON", "invalid json", AuditDetails{}, true},
		{"Invalid type", 123, AuditDetails{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var details AuditDetails
			err := details.Scan(tt.input)
			
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected.Method, details.Method)
				assert.Equal(t, tt.expected.Path, details.Path)
			}
		})
	}
}

func TestAuditLog_IsSecurityEvent(t *testing.T) {
	tests := []struct {
		name     string
		action   string
		severity AuditSeverity
		expected bool
	}{
		{"User login", AuditActions.UserLogin, AuditSeverityInfo, true},
		{"User logout", AuditActions.UserLogout, AuditSeverityInfo, true},
		{"Password changed", AuditActions.UserPasswordChanged, AuditSeverityInfo, true},
		{"User created", AuditActions.UserCreated, AuditSeverityInfo, true},
		{"User updated", AuditActions.UserUpdated, AuditSeverityInfo, false},
		{"Error severity", "custom_action", AuditSeverityError, true},
		{"Critical severity", "custom_action", AuditSeverityCritical, true},
		{"Normal action with info", "custom_action", AuditSeverityInfo, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := &AuditLog{Action: tt.action, Severity: tt.severity}
			assert.Equal(t, tt.expected, log.IsSecurityEvent())
		})
	}
}

func TestAuditLog_IsFailure(t *testing.T) {
	tests := []struct {
		name     string
		status   AuditStatus
		expected bool
	}{
		{"Failure status", AuditStatusFailure, true},
		{"Success status", AuditStatusSuccess, false},
		{"Partial status", AuditStatusPartial, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := &AuditLog{Status: tt.status}
			assert.Equal(t, tt.expected, log.IsFailure())
		})
	}
}

func TestAuditLog_GetUserEmail(t *testing.T) {
	log := &AuditLog{
		ID:        "test-id",
		Action:    AuditActions.UserLogin,
		CreatedAt: time.Now(),
	}
	
	// GetUserEmail currently returns empty string as per implementation
	assert.Equal(t, "", log.GetUserEmail())
}

func TestAuditLog_ToResponse(t *testing.T) {
	userID := uuid.New().String()
	now := time.Now()
	
	log := &AuditLog{
		ID:             uuid.New().String(),
		RealmName:      "test-realm",
		KeycloakUserID: &userID,
		Action:         AuditActions.UserLogin,
		ResourceType:   "user",
		ResourceID:     userID,
		IPAddress:      "192.168.1.1",
		UserAgent:      "Mozilla/5.0",
		Severity:       AuditSeverityInfo,
		Status:         AuditStatusSuccess,
		CreatedAt:      now,
	}

	response := log.ToResponse()
	
	assert.Equal(t, log.ID, response.ID)
	assert.Equal(t, log.RealmName, response.RealmName)
	assert.Equal(t, userID, *response.KeycloakUserID)
	assert.Equal(t, "", response.UserEmail) // GetUserEmail returns empty string
	assert.Equal(t, log.Action, response.Action)
	assert.Equal(t, log.ResourceType, response.ResourceType)
	assert.Equal(t, log.ResourceID, response.ResourceID)
	assert.Equal(t, log.IPAddress, response.IPAddress)
	assert.Equal(t, log.UserAgent, response.UserAgent)
	assert.Equal(t, log.Severity, response.Severity)
	assert.Equal(t, log.Status, response.Status)
	assert.Equal(t, now, response.CreatedAt)
	
	// Note: IsSecurityEvent and IsFailure are methods on AuditLog, not AuditLogResponse
	assert.True(t, log.IsSecurityEvent())
	assert.False(t, log.IsFailure())
}

func TestAuditLog_ToResponse_WithNilValues(t *testing.T) {
	log := &AuditLog{
		ID:             uuid.New().String(),
		RealmName:      "test-realm",
		KeycloakUserID: nil,
		Action:         AuditActions.UserCreated,
		ResourceType:   "user",
		ResourceID:     "resource-123",
		IPAddress:      "127.0.0.1",
		UserAgent:      "test-agent",
		Severity:       AuditSeverityWarning,
		Status:         AuditStatusSuccess,
		CreatedAt:      time.Now(),
	}

	response := log.ToResponse()
	
	assert.Equal(t, log.ID, response.ID)
	assert.Nil(t, response.KeycloakUserID)
	assert.Equal(t, "", response.UserEmail)
	assert.True(t, log.IsSecurityEvent()) // user.created is a security event
	assert.False(t, log.IsFailure())
}

func TestCreateAuditLogRequest_Validation(t *testing.T) {
	userID := uuid.New().String()
	
	validRequest := CreateAuditLogRequest{
		KeycloakUserID: &userID,
		Action:         AuditActions.UserLogin,
		ResourceType:   "user",
		ResourceID:     "resource-123",
		IPAddress:      "192.168.1.1",
		UserAgent:      "Mozilla/5.0",
		Severity:       AuditSeverityInfo,
		Status:         AuditStatusSuccess,
	}
	
	// This would normally be validated by a validator instance
	assert.Equal(t, AuditActions.UserLogin, validRequest.Action)
	assert.Equal(t, "user", validRequest.ResourceType)
	assert.NotNil(t, validRequest.KeycloakUserID)
	assert.Equal(t, userID, *validRequest.KeycloakUserID)
}

func TestAuditLogSearchRequest_Defaults(t *testing.T) {
	req := AuditLogSearchRequest{
		Page:     1,
		PageSize: 50,
	}
	
	assert.Equal(t, 1, req.Page)
	assert.Equal(t, 50, req.PageSize)
	assert.Nil(t, req.KeycloakUserID)
	assert.Empty(t, req.Action)
	assert.Nil(t, req.DateFrom)
	assert.Nil(t, req.DateTo)
	assert.Nil(t, req.Severity)
}

func TestAuditLogSearchRequest_WithFilters(t *testing.T) {
	userID := "user-123"
	startDate := time.Now().Add(-24 * time.Hour)
	endDate := time.Now()
	severity := AuditSeverityWarning
	
	req := AuditLogSearchRequest{
		Page:           1,
		PageSize:       20,
		KeycloakUserID: &userID,
		Action:         AuditActions.UserLogin,
		DateFrom:       &startDate,
		DateTo:         &endDate,
		Severity:       &severity,
	}
	
	assert.Equal(t, 1, req.Page)
	assert.Equal(t, 20, req.PageSize)
	assert.NotNil(t, req.KeycloakUserID)
	assert.Equal(t, userID, *req.KeycloakUserID)
	assert.Equal(t, AuditActions.UserLogin, req.Action)
	assert.NotNil(t, req.DateFrom)
	assert.NotNil(t, req.DateTo)
	assert.Equal(t, AuditSeverityWarning, *req.Severity)
}

func TestAuditLogListResponse_Structure(t *testing.T) {
	logs := []AuditLogResponse{
		{ID: "1", Action: AuditActions.UserLogin},
		{ID: "2", Action: AuditActions.UserLogout},
	}
	
	response := AuditLogListResponse{
		Logs:       logs,
		Total:      100,
		Page:       1,
		PageSize:   50,
		TotalPages: 2,
	}
	
	assert.Len(t, response.Logs, 2)
	assert.Equal(t, int64(100), response.Total)
	assert.Equal(t, 1, response.Page)
	assert.Equal(t, 50, response.PageSize)
	assert.Equal(t, 2, response.TotalPages)
}

func TestAuditLogStatsResponse_Structure(t *testing.T) {
	stats := AuditLogStatsResponse{
		TotalEvents:       1000,
		SecurityEvents:    150,
		FailedEvents:      25,
		TopActions:        []ActionCount{{Action: "login", Count: 500}, {Action: "logout", Count: 300}},
		TopUsers:          []UserActivityCount{{KeycloakUserID: "user1", Count: 50}},
		SeverityBreakdown: map[AuditSeverity]int64{AuditSeverityInfo: 800, AuditSeverityWarning: 150},
		StatusBreakdown:   map[AuditStatus]int64{AuditStatusSuccess: 900, AuditStatusFailure: 100},
		Timeline:          []TimelinePoint{{Timestamp: time.Now(), Count: 100}},
	}
	
	assert.Equal(t, int64(1000), stats.TotalEvents)
	assert.Equal(t, int64(150), stats.SecurityEvents)
	assert.Equal(t, int64(25), stats.FailedEvents)
	assert.Len(t, stats.TopActions, 2)
	assert.Equal(t, "login", stats.TopActions[0].Action)
	assert.Equal(t, int64(500), stats.TopActions[0].Count)
	assert.Len(t, stats.TopUsers, 1)
	assert.Equal(t, "user1", stats.TopUsers[0].KeycloakUserID)
	assert.Equal(t, int64(50), stats.TopUsers[0].Count)
	assert.Equal(t, int64(800), stats.SeverityBreakdown[AuditSeverityInfo])
	assert.Equal(t, int64(900), stats.StatusBreakdown[AuditStatusSuccess])
	assert.Len(t, stats.Timeline, 1)
}

func TestUserActivityCount_Structure(t *testing.T) {
	activity := UserActivityCount{
		KeycloakUserID: "user-123",
		UserEmail:      "test@example.com",
		Count:          42,
	}
	
	assert.Equal(t, "user-123", activity.KeycloakUserID)
	assert.Equal(t, "test@example.com", activity.UserEmail)
	assert.Equal(t, int64(42), activity.Count)
}

func TestActionCount_Structure(t *testing.T) {
	action := ActionCount{
		Action: "login",
		Count:  500,
	}
	
	assert.Equal(t, "login", action.Action)
	assert.Equal(t, int64(500), action.Count)
}

func TestTimelinePoint_Structure(t *testing.T) {
	now := time.Now()
	point := TimelinePoint{
		Timestamp: now,
		Count:     42,
	}
	
	assert.Equal(t, now, point.Timestamp)
	assert.Equal(t, int64(42), point.Count)
}

func TestAuditActions_Constants(t *testing.T) {
	// Test all action constants are defined
	actions := []string{
		AuditActions.UserLogin,
		AuditActions.UserLogout,
		AuditActions.UserLoginFailed,
		AuditActions.UserCreated,
		AuditActions.UserUpdated,
		AuditActions.UserDeleted,
		AuditActions.UserSuspended,
		AuditActions.UserActivated,
		AuditActions.UserPasswordChanged,
		AuditActions.UserMFAEnabled,
		AuditActions.UserMFADisabled,
		AuditActions.RoleCreated,
		AuditActions.RoleUpdated,
		AuditActions.RoleDeleted,
		AuditActions.RoleAssigned,
		AuditActions.RoleRevoked,
		AuditActions.SSOConfigured,
		AuditActions.SSOUpdated,
		AuditActions.SSODeleted,
		AuditActions.SSOTested,
		AuditActions.SSOTestFailed,
		AuditActions.SSOActivated,
		AuditActions.SSODeactivated,
		AuditActions.TenantCreated,
		AuditActions.TenantUpdated,
		AuditActions.TenantDeleted,
		AuditActions.TenantSuspended,
		AuditActions.TenantActivated,
		AuditActions.SystemConfigChanged,
		AuditActions.AdminAccess,
		AuditActions.APIKeyCreated,
		AuditActions.APIKeyDeleted,
		AuditActions.DataExported,
		AuditActions.DataImported,
		AuditActions.DataBackedUp,
		AuditActions.DataRestored,
	}
	
	for _, action := range actions {
		assert.NotEmpty(t, action, "Action should not be empty")
		assert.True(t, len(action) > 0, "Action should have content")
	}
}

func TestAuditSeverityConstants(t *testing.T) {
	severities := []AuditSeverity{
		AuditSeverityInfo,
		AuditSeverityWarning,
		AuditSeverityError,
		AuditSeverityCritical,
	}
	
	for _, severity := range severities {
		assert.NotEmpty(t, severity, "Severity should not be empty")
		assert.True(t, len(string(severity)) > 0, "Severity should have content")
	}
	
	// Test specific values
	assert.Equal(t, AuditSeverity("info"), AuditSeverityInfo)
	assert.Equal(t, AuditSeverity("warning"), AuditSeverityWarning)
	assert.Equal(t, AuditSeverity("error"), AuditSeverityError)
	assert.Equal(t, AuditSeverity("critical"), AuditSeverityCritical)
}

func TestAuditStatusConstants(t *testing.T) {
	statuses := []AuditStatus{
		AuditStatusSuccess,
		AuditStatusFailure,
		AuditStatusPartial,
	}
	
	for _, status := range statuses {
		assert.NotEmpty(t, status, "Status should not be empty")
		assert.True(t, len(string(status)) > 0, "Status should have content")
	}
	
	// Test specific values
	assert.Equal(t, AuditStatus("success"), AuditStatusSuccess)
	assert.Equal(t, AuditStatus("failure"), AuditStatusFailure)
	assert.Equal(t, AuditStatus("partial"), AuditStatusPartial)
}
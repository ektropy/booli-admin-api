package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/booli/booli-admin-api/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

type MockAuditService struct {
	mock.Mock
}

func (m *MockAuditService) ListAuditLogs(ctx context.Context, tenantID uuid.UUID, req *models.AuditLogSearchRequest) ([]models.AuditLog, int64, error) {
	args := m.Called(ctx, tenantID, req)
	return args.Get(0).([]models.AuditLog), args.Get(1).(int64), args.Error(2)
}

func (m *MockAuditService) GetAuditLog(ctx context.Context, tenantID, logID uuid.UUID) (*models.AuditLog, error) {
	args := m.Called(ctx, tenantID, logID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AuditLog), args.Error(1)
}

func (m *MockAuditService) CreateAuditLog(ctx context.Context, tenantID uuid.UUID, req *models.CreateAuditLogRequest) (*models.AuditLog, error) {
	args := m.Called(ctx, tenantID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AuditLog), args.Error(1)
}

func (m *MockAuditService) GetAuditStats(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (*models.AuditLogStatsResponse, error) {
	args := m.Called(ctx, tenantID, from, to)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AuditLogStatsResponse), args.Error(1)
}

func setupAuditHandler() (*AuditHandler, *MockAuditService) {
	mockService := &MockAuditService{}
	logger := zap.NewNop()

	handler := &AuditHandler{
		auditService: mockService,
		logger:       logger,
		validator:    validator.New(),
	}
	return handler, mockService
}

func setupAuditGinContext(method, path string, body interface{}) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	var req *http.Request
	if body != nil {
		jsonBody, _ := json.Marshal(body)
		req = httptest.NewRequest(method, path, bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}

	c.Request = req
	return c, w
}

func TestAuditHandler_List(t *testing.T) {
	handler, mockService := setupAuditHandler()

	tenantID := uuid.New()
	userID := uuid.New()
	expectedLogs := []models.AuditLog{
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			UserID:       &userID,
			Action:       models.AuditActions.UserLogin,
			ResourceType: "user",
			ResourceID:   userID.String(),
			IPAddress:    "192.168.1.1",
			UserAgent:    "Mozilla/5.0",
			Severity:     models.AuditSeverityInfo,
			Status:       models.AuditStatusSuccess,
			CreatedAt:    time.Now(),
		},
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			UserID:       &userID,
			Action:       models.AuditActions.UserUpdated,
			ResourceType: "user",
			ResourceID:   userID.String(),
			IPAddress:    "192.168.1.1",
			Severity:     models.AuditSeverityInfo,
			Status:       models.AuditStatusSuccess,
			CreatedAt:    time.Now(),
		},
	}

	mockService.On("ListAuditLogs", mock.Anything, tenantID, mock.MatchedBy(func(req *models.AuditLogSearchRequest) bool {
		return req.Page == 1 && req.PageSize == 50
	})).Return(expectedLogs, int64(2), nil)

	c, w := setupAuditGinContext("GET", "/audit/logs?page=1&page_size=50", nil)
	c.Set("tenant_id", tenantID)

	handler.List(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.AuditLogListResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), response.Total)
	assert.Len(t, response.Logs, 2)
	assert.Equal(t, 1, response.Page)
	assert.Equal(t, 50, response.PageSize)
	assert.Equal(t, 1, response.TotalPages)

	mockService.AssertExpectations(t)
}

func TestAuditHandler_List_WithFilters(t *testing.T) {
	handler, mockService := setupAuditHandler()

	tenantID := uuid.New()
	userID := uuid.New()
	expectedLogs := []models.AuditLog{
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			UserID:       &userID,
			Action:       models.AuditActions.UserLogin,
			ResourceType: "user",
			ResourceID:   userID.String(),
			IPAddress:    "192.168.1.1",
			Severity:     models.AuditSeverityInfo,
			Status:       models.AuditStatusSuccess,
			CreatedAt:    time.Now(),
		},
	}

	dateFrom := time.Now().Add(-24 * time.Hour)
	dateTo := time.Now()

	mockService.On("ListAuditLogs", mock.Anything, tenantID, mock.MatchedBy(func(req *models.AuditLogSearchRequest) bool {
		return req.UserID != nil && *req.UserID == userID &&
			req.Action == models.AuditActions.UserLogin &&
			req.ResourceType == "user" &&
			req.Severity != nil && *req.Severity == models.AuditSeverityInfo &&
			req.Status != nil && *req.Status == models.AuditStatusSuccess &&
			req.IPAddress == "192.168.1.1"
	})).Return(expectedLogs, int64(1), nil)

	path := fmt.Sprintf("/audit/logs?user_id=%s&action=%s&resource_type=user&severity=info&status=success&ip_address=192.168.1.1&date_from=%s&date_to=%s",
		userID.String(), models.AuditActions.UserLogin, dateFrom.Format(time.RFC3339), dateTo.Format(time.RFC3339))

	c, w := setupAuditGinContext("GET", path, nil)
	c.Set("tenant_id", tenantID)

	handler.List(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.AuditLogListResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), response.Total)
	assert.Len(t, response.Logs, 1)

	mockService.AssertExpectations(t)
}

func TestAuditHandler_List_NoTenant(t *testing.T) {
	handler, _ := setupAuditHandler()

	c, w := setupAuditGinContext("GET", "/audit/logs", nil)

	handler.List(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestAuditHandler_Get(t *testing.T) {
	handler, mockService := setupAuditHandler()

	tenantID := uuid.New()
	logID := uuid.New()
	userID := uuid.New()

	expectedLog := &models.AuditLog{
		ID:           logID,
		TenantID:     tenantID,
		UserID:       &userID,
		Action:       models.AuditActions.UserLogin,
		ResourceType: "user",
		ResourceID:   userID.String(),
		IPAddress:    "192.168.1.1",
		UserAgent:    "Mozilla/5.0",
		Severity:     models.AuditSeverityInfo,
		Status:       models.AuditStatusSuccess,
		CreatedAt:    time.Now(),
	}

	mockService.On("GetAuditLog", mock.Anything, tenantID, logID).Return(expectedLog, nil)

	c, w := setupAuditGinContext("GET", "/audit/logs/"+logID.String(), nil)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: logID.String()}}

	handler.Get(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.AuditLogResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, expectedLog.ID, response.ID)
	assert.Equal(t, expectedLog.Action, response.Action)

	mockService.AssertExpectations(t)
}

func TestAuditHandler_Get_NotFound(t *testing.T) {
	handler, mockService := setupAuditHandler()

	tenantID := uuid.New()
	logID := uuid.New()

	mockService.On("GetAuditLog", mock.Anything, tenantID, logID).Return(nil, nil)

	c, w := setupAuditGinContext("GET", "/audit/logs/"+logID.String(), nil)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: logID.String()}}

	handler.Get(c)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")

	mockService.AssertExpectations(t)
}

func TestAuditHandler_Get_InvalidID(t *testing.T) {
	handler, _ := setupAuditHandler()

	tenantID := uuid.New()

	c, w := setupAuditGinContext("GET", "/audit/logs/invalid-uuid", nil)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: "invalid-uuid"}}

	handler.Get(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestAuditHandler_Export_CSV(t *testing.T) {
	handler, mockService := setupAuditHandler()

	tenantID := uuid.New()
	userID := uuid.New()
	expectedLogs := []models.AuditLog{
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			UserID:       &userID,
			Action:       models.AuditActions.UserLogin,
			ResourceType: "user",
			ResourceID:   userID.String(),
			IPAddress:    "192.168.1.1",
			UserAgent:    "Mozilla/5.0",
			Severity:     models.AuditSeverityInfo,
			Status:       models.AuditStatusSuccess,
			CreatedAt:    time.Now(),
		},
	}

	mockService.On("ListAuditLogs", mock.Anything, tenantID, mock.MatchedBy(func(req *models.AuditLogSearchRequest) bool {
		return req.Page == 1 && req.PageSize == 10000
	})).Return(expectedLogs, int64(1), nil)

	c, w := setupAuditGinContext("POST", "/audit/export?format=csv", nil)
	c.Set("tenant_id", tenantID)

	handler.Export(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/csv", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Content-Disposition"), "attachment; filename=audit-logs-export-")

	csvContent := w.Body.String()
	assert.Contains(t, csvContent, "ID,User ID,User Email,Action,Resource Type")
	assert.Contains(t, csvContent, models.AuditActions.UserLogin)

	mockService.AssertExpectations(t)
}

func TestAuditHandler_Export_JSON(t *testing.T) {
	handler, mockService := setupAuditHandler()

	tenantID := uuid.New()
	userID := uuid.New()
	expectedLogs := []models.AuditLog{
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			UserID:       &userID,
			Action:       models.AuditActions.UserLogin,
			ResourceType: "user",
			ResourceID:   userID.String(),
			IPAddress:    "192.168.1.1",
			UserAgent:    "Mozilla/5.0",
			Severity:     models.AuditSeverityInfo,
			Status:       models.AuditStatusSuccess,
			CreatedAt:    time.Now(),
		},
	}

	mockService.On("ListAuditLogs", mock.Anything, tenantID, mock.MatchedBy(func(req *models.AuditLogSearchRequest) bool {
		return req.Page == 1 && req.PageSize == 10000
	})).Return(expectedLogs, int64(1), nil)

	c, w := setupAuditGinContext("POST", "/audit/export?format=json", nil)
	c.Set("tenant_id", tenantID)

	handler.Export(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Content-Disposition"), "attachment; filename=audit-logs-export-")

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "logs")

	logs := response["logs"].([]interface{})
	assert.Len(t, logs, 1)

	mockService.AssertExpectations(t)
}

func TestAuditHandler_Export_InvalidFormat(t *testing.T) {
	handler, mockService := setupAuditHandler()

	tenantID := uuid.New()

	mockService.On("ListAuditLogs", mock.Anything, tenantID, mock.Anything).Return([]models.AuditLog{}, int64(0), nil)

	c, w := setupAuditGinContext("POST", "/audit/export?format=xml", nil)
	c.Set("tenant_id", tenantID)

	handler.Export(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")

	mockService.AssertExpectations(t)
}

func TestAuditHandler_Export_WithFilters(t *testing.T) {
	handler, mockService := setupAuditHandler()

	tenantID := uuid.New()
	userID := uuid.New()
	expectedLogs := []models.AuditLog{
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			UserID:       &userID,
			Action:       models.AuditActions.UserLogin,
			ResourceType: "user",
			ResourceID:   userID.String(),
			IPAddress:    "192.168.1.1",
			Severity:     models.AuditSeverityInfo,
			Status:       models.AuditStatusSuccess,
			CreatedAt:    time.Now(),
		},
	}

	dateFrom := time.Now().Add(-24 * time.Hour)
	dateTo := time.Now()

	mockService.On("ListAuditLogs", mock.Anything, tenantID, mock.MatchedBy(func(req *models.AuditLogSearchRequest) bool {
		return req.UserID != nil && *req.UserID == userID &&
			req.Action == models.AuditActions.UserLogin &&
			req.Severity != nil && *req.Severity == models.AuditSeverityInfo &&
			req.Status != nil && *req.Status == models.AuditStatusSuccess
	})).Return(expectedLogs, int64(1), nil)

	path := fmt.Sprintf("/audit/export?format=csv&user_id=%s&action=%s&severity=info&status=success&date_from=%s&date_to=%s",
		userID.String(), models.AuditActions.UserLogin, dateFrom.Format(time.RFC3339), dateTo.Format(time.RFC3339))

	c, w := setupAuditGinContext("POST", path, nil)
	c.Set("tenant_id", tenantID)

	handler.Export(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/csv", w.Header().Get("Content-Type"))

	csvContent := w.Body.String()
	assert.Contains(t, csvContent, models.AuditActions.UserLogin)

	mockService.AssertExpectations(t)
}

func TestAuditHandler_NoTenantContext(t *testing.T) {
	handler, _ := setupAuditHandler()

	tests := []struct {
		name     string
		method   string
		path     string
		body     interface{}
		handler  func(*gin.Context)
		expected int
	}{
		{
			name:     "List without tenant",
			method:   "GET",
			path:     "/audit/logs",
			body:     nil,
			handler:  handler.List,
			expected: http.StatusBadRequest,
		},
		{
			name:     "Get without tenant",
			method:   "GET",
			path:     "/audit/logs/123",
			body:     nil,
			handler:  handler.Get,
			expected: http.StatusBadRequest,
		},
		{
			name:     "Export without tenant",
			method:   "POST",
			path:     "/audit/export",
			body:     nil,
			handler:  handler.Export,
			expected: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, w := setupAuditGinContext(tt.method, tt.path, tt.body)

			tt.handler(c)

			assert.Equal(t, tt.expected, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, response, "error")
		})
	}
}

func TestAuditHandler_List_PaginationDefaults(t *testing.T) {
	handler, mockService := setupAuditHandler()

	tenantID := uuid.New()

	mockService.On("ListAuditLogs", mock.Anything, tenantID, mock.MatchedBy(func(req *models.AuditLogSearchRequest) bool {
		return req.Page == 1 && req.PageSize == 50
	})).Return([]models.AuditLog{}, int64(0), nil)

	c, w := setupAuditGinContext("GET", "/audit/logs", nil)
	c.Set("tenant_id", tenantID)

	handler.List(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.AuditLogListResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 1, response.Page)
	assert.Equal(t, 50, response.PageSize)

	mockService.AssertExpectations(t)
}

func TestAuditHandler_List_InvalidPagination(t *testing.T) {
	handler, mockService := setupAuditHandler()

	tenantID := uuid.New()

	mockService.On("ListAuditLogs", mock.Anything, tenantID, mock.MatchedBy(func(req *models.AuditLogSearchRequest) bool {
		return req.Page == 1 && req.PageSize == 50
	})).Return([]models.AuditLog{}, int64(0), nil)

	c, w := setupAuditGinContext("GET", "/audit/logs?page=-1&page_size=2000", nil)
	c.Set("tenant_id", tenantID)

	handler.List(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.AuditLogListResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 1, response.Page)
	assert.Equal(t, 50, response.PageSize)

	mockService.AssertExpectations(t)
}

func TestAuditHandler_Get_MissingID(t *testing.T) {
	handler, _ := setupAuditHandler()

	tenantID := uuid.New()

	c, w := setupAuditGinContext("GET", "/audit/logs/", nil)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: ""}}

	handler.Get(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestAuditHandler_Export_DefaultFormat(t *testing.T) {
	handler, mockService := setupAuditHandler()

	tenantID := uuid.New()
	expectedLogs := []models.AuditLog{
		{
			ID:        uuid.New(),
			TenantID:  tenantID,
			Action:    models.AuditActions.UserLogin,
			Severity:  models.AuditSeverityInfo,
			Status:    models.AuditStatusSuccess,
			CreatedAt: time.Now(),
		},
	}

	mockService.On("ListAuditLogs", mock.Anything, tenantID, mock.Anything).Return(expectedLogs, int64(1), nil)

	c, w := setupAuditGinContext("POST", "/audit/export", nil)
	c.Set("tenant_id", tenantID)

	handler.Export(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/csv", w.Header().Get("Content-Type"))

	mockService.AssertExpectations(t)
}

func TestAuditHandler_InvalidUserID(t *testing.T) {
	handler, mockService := setupAuditHandler()

	tenantID := uuid.New()

	mockService.On("ListAuditLogs", mock.Anything, tenantID, mock.MatchedBy(func(req *models.AuditLogSearchRequest) bool {
		return req.UserID == nil
	})).Return([]models.AuditLog{}, int64(0), nil)

	c, w := setupAuditGinContext("GET", "/audit/logs?user_id=invalid-uuid", nil)
	c.Set("tenant_id", tenantID)

	handler.List(c)

	assert.Equal(t, http.StatusOK, w.Code)

	mockService.AssertExpectations(t)
}

func TestAuditHandler_InvalidDateFormat(t *testing.T) {
	handler, mockService := setupAuditHandler()

	tenantID := uuid.New()

	mockService.On("ListAuditLogs", mock.Anything, tenantID, mock.MatchedBy(func(req *models.AuditLogSearchRequest) bool {
		return req.DateFrom == nil && req.DateTo == nil
	})).Return([]models.AuditLog{}, int64(0), nil)

	c, w := setupAuditGinContext("GET", "/audit/logs?date_from=invalid-date&date_to=invalid-date", nil)
	c.Set("tenant_id", tenantID)

	handler.List(c)

	assert.Equal(t, http.StatusOK, w.Code)

	mockService.AssertExpectations(t)
}

func TestNewAuditHandler(t *testing.T) {
	logger := zap.NewNop()
	mockService := &MockAuditService{}

	handler := NewAuditHandler(mockService, logger)

	assert.NotNil(t, handler)
	assert.Equal(t, mockService, handler.auditService)
	assert.Equal(t, logger, handler.logger)
	assert.NotNil(t, handler.validator)
}

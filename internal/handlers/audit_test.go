package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func (m *MockAuditService) ListAuditLogs(ctx context.Context, realmName string, req *models.AuditLogSearchRequest) ([]models.AuditLog, int64, error) {
	args := m.Called(ctx, realmName, req)
	return args.Get(0).([]models.AuditLog), args.Get(1).(int64), args.Error(2)
}

func (m *MockAuditService) GetAuditLog(ctx context.Context, realmName, logID string) (*models.AuditLog, error) {
	args := m.Called(ctx, realmName, logID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AuditLog), args.Error(1)
}

func (m *MockAuditService) CreateAuditLog(ctx context.Context, realmName string, req *models.CreateAuditLogRequest) (*models.AuditLog, error) {
	args := m.Called(ctx, realmName, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AuditLog), args.Error(1)
}

func (m *MockAuditService) GetAuditStats(ctx context.Context, realmName string, from, to time.Time) (*models.AuditLogStatsResponse, error) {
	args := m.Called(ctx, realmName, from, to)
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
		req = httptest.NewRequest(method, path, strings.NewReader(string(jsonBody)))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}

	c.Request = req
	return c, w
}

func TestAuditHandler_List(t *testing.T) {
	handler, mockService := setupAuditHandler()

	realmName := "test-realm"
	userID := uuid.New()
	userIDStr := userID.String()
	expectedLogs := []models.AuditLog{
		{
			ID:             uuid.New().String(),
			RealmName:      realmName,
			KeycloakUserID: &userIDStr,
			Action:         models.AuditActions.UserLogin,
			ResourceType:   "user",
			ResourceID:     userID.String(),
			IPAddress:      "192.168.1.1",
			UserAgent:      "Mozilla/5.0",
			Severity:       models.AuditSeverityInfo,
			CreatedAt:      time.Now(),
		},
	}

	mockService.On("ListAuditLogs", mock.Anything, realmName, mock.MatchedBy(func(req *models.AuditLogSearchRequest) bool {
		return req.Page == 1 && req.PageSize == 20
	})).Return(expectedLogs, int64(1), nil)

	c, w := setupAuditGinContext("GET", "/audit?page=1&page_size=20", nil)
	c.Set("realm_name", realmName)

	handler.List(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.AuditLogListResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), response.Total)
	assert.Len(t, response.Logs, 1)

	mockService.AssertExpectations(t)
}

func TestAuditHandler_Get(t *testing.T) {
	handler, mockService := setupAuditHandler()

	realmName := "test-realm"
	logID := uuid.New()
	userID := uuid.New()

	userIDStr := userID.String()
	logIDStr := logID.String()
	expectedLog := &models.AuditLog{
		ID:             logIDStr,
		RealmName:      realmName,
		KeycloakUserID: &userIDStr,
		Action:         models.AuditActions.UserLogin,
		ResourceType:   "user",
		ResourceID:     userID.String(),
		IPAddress:      "192.168.1.1",
		UserAgent:      "Mozilla/5.0",
		Severity:       models.AuditSeverityInfo,
		CreatedAt:      time.Now(),
	}

	mockService.On("GetAuditLog", mock.Anything, realmName, logIDStr).Return(expectedLog, nil)

	c, w := setupAuditGinContext("GET", "/audit/"+logID.String(), nil)
	c.Set("realm_name", realmName)
	c.Params = gin.Params{{Key: "id", Value: logID.String()}}

	handler.Get(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.AuditLog
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, expectedLog.ID, response.ID)
	assert.Equal(t, expectedLog.RealmName, response.RealmName)
	assert.Equal(t, expectedLog.KeycloakUserID, response.KeycloakUserID)

	mockService.AssertExpectations(t)
}

func TestAuditHandler_List_MissingRealmName(t *testing.T) {
	handler, _ := setupAuditHandler()

	c, w := setupAuditGinContext("GET", "/audit", nil)

	handler.List(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestAuditHandler_Get_NotFound(t *testing.T) {
	handler, mockService := setupAuditHandler()

	realmName := "test-realm"
	logID := uuid.New()

	logIDStr := logID.String()
	mockService.On("GetAuditLog", mock.Anything, realmName, logIDStr).Return(nil, nil)

	c, w := setupAuditGinContext("GET", "/audit/"+logID.String(), nil)
	c.Set("realm_name", realmName)
	c.Params = gin.Params{{Key: "id", Value: logID.String()}}

	handler.Get(c)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")

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
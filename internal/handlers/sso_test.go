package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	"gorm.io/datatypes"
)

type MockSSOService struct {
	mock.Mock
}

func (m *MockSSOService) ListProviders(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]*models.SSOProvider, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize)
	return args.Get(0).([]*models.SSOProvider), args.Get(1).(int64), args.Error(2)
}

func (m *MockSSOService) CreateProvider(ctx context.Context, provider *models.SSOProvider) (*models.SSOProvider, error) {
	args := m.Called(ctx, provider)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SSOProvider), args.Error(1)
}

func (m *MockSSOService) GetProvider(ctx context.Context, tenantID, providerID uuid.UUID) (*models.SSOProvider, error) {
	args := m.Called(ctx, tenantID, providerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SSOProvider), args.Error(1)
}

func (m *MockSSOService) UpdateProvider(ctx context.Context, tenantID, providerID uuid.UUID, req *models.UpdateSSOProviderRequest) (*models.SSOProvider, error) {
	args := m.Called(ctx, tenantID, providerID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SSOProvider), args.Error(1)
}

func (m *MockSSOService) DeleteProvider(ctx context.Context, tenantID, providerID uuid.UUID) error {
	args := m.Called(ctx, tenantID, providerID)
	return args.Error(0)
}

func (m *MockSSOService) TestConnection(ctx context.Context, tenantID, providerID uuid.UUID, req *models.TestSSOProviderRequest) (*models.SSOTestResult, error) {
	args := m.Called(ctx, tenantID, providerID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SSOTestResult), args.Error(1)
}

func setupSSOHandler() (*SSOHandler, *MockSSOService) {
	mockService := &MockSSOService{}
	logger := zap.NewNop()

	handler := &SSOHandler{
		ssoService: mockService,
		logger:     logger,
		validator:  validator.New(),
	}
	return handler, mockService
}

func setupSSOGinContext(method, path string, body interface{}) (*gin.Context, *httptest.ResponseRecorder) {
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

func TestSSOHandler_ListProviders(t *testing.T) {
	handler, mockService := setupSSOHandler()

	tenantID := uuid.New()
	expectedProviders := []*models.SSOProvider{
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			ProviderType: models.SSOProviderTypeSAML,
			ProviderName: "test-saml",
			DisplayName:  "Test SAML Provider",
			Status:       models.SSOStatusActive,
			IsDefault:    true,
			Priority:     1,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		},
		{
			ID:           uuid.New(),
			TenantID:     tenantID,
			ProviderType: models.SSOProviderTypeOIDC,
			ProviderName: "test-oidc",
			DisplayName:  "Test OIDC Provider",
			Status:       models.SSOStatusInactive,
			IsDefault:    false,
			Priority:     0,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		},
	}

	mockService.On("ListProviders", mock.Anything, tenantID, 1, 10).Return(expectedProviders, int64(2), nil)

	c, w := setupSSOGinContext("GET", "/sso/providers?page=1&page_size=10", nil)
	c.Set("tenant_id", tenantID)

	handler.ListProviders(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.SSOProviderListResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), response.Total)
	assert.Len(t, response.Providers, 2)
	assert.Equal(t, 1, response.Page)
	assert.Equal(t, 10, response.PageSize)
	assert.Equal(t, 1, response.TotalPages)

	mockService.AssertExpectations(t)
}

func TestSSOHandler_ListProviders_NoTenant(t *testing.T) {
	handler, _ := setupSSOHandler()

	c, w := setupSSOGinContext("GET", "/sso/providers", nil)

	handler.ListProviders(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestSSOHandler_CreateProvider(t *testing.T) {
	handler, mockService := setupSSOHandler()

	tenantID := uuid.New()
	samlConfig := models.SSOConfiguration{
		SAML: &models.SAMLConfig{
			EntityID:         "test-entity",
			SSOServiceURL:    "https://example.com/sso",
			X509Certificate:  "test-cert",
			AttributeMapping: models.AttributeMapping{Email: "email"},
		},
	}
	configJSON, _ := json.Marshal(samlConfig)

	requestBody := models.CreateSSOProviderRequest{
		ProviderType:  models.SSOProviderTypeSAML,
		ProviderName:  "test-saml-provider",
		DisplayName:   "Test SAML Provider",
		Configuration: datatypes.JSON(configJSON),
		IsDefault:     true,
		Priority:      1,
	}

	expectedProvider := &models.SSOProvider{
		ID:            uuid.New(),
		TenantID:      tenantID,
		ProviderType:  models.SSOProviderTypeSAML,
		ProviderName:  "test-saml-provider",
		DisplayName:   "Test SAML Provider",
		Configuration: datatypes.JSON(configJSON),
		Status:        models.SSOStatusInactive,
		IsDefault:     true,
		Priority:      1,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	mockService.On("CreateProvider", mock.Anything, mock.MatchedBy(func(provider *models.SSOProvider) bool {
		return provider.TenantID == tenantID &&
			provider.ProviderType == models.SSOProviderTypeSAML &&
			provider.ProviderName == "test-saml-provider"
	})).Return(expectedProvider, nil)

	c, w := setupSSOGinContext("POST", "/sso/providers", requestBody)
	c.Set("tenant_id", tenantID)

	handler.CreateProvider(c)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response models.SSOProviderResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, expectedProvider.ProviderName, response.ProviderName)
	assert.Equal(t, expectedProvider.ProviderType, response.ProviderType)

	mockService.AssertExpectations(t)
}

func TestSSOHandler_CreateProvider_InvalidJSON(t *testing.T) {
	handler, _ := setupSSOHandler()

	tenantID := uuid.New()

	c, w := setupSSOGinContext("POST", "/sso/providers", nil)
	c.Request.Body = http.NoBody
	c.Set("tenant_id", tenantID)

	handler.CreateProvider(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestSSOHandler_CreateProvider_ValidationError(t *testing.T) {
	handler, _ := setupSSOHandler()

	tenantID := uuid.New()
	requestBody := models.CreateSSOProviderRequest{
		ProviderType: "invalid-type",
		ProviderName: "",
	}

	c, w := setupSSOGinContext("POST", "/sso/providers", requestBody)
	c.Set("tenant_id", tenantID)

	handler.CreateProvider(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestSSOHandler_GetProvider(t *testing.T) {
	handler, mockService := setupSSOHandler()

	tenantID := uuid.New()
	providerID := uuid.New()
	expectedProvider := &models.SSOProvider{
		ID:           providerID,
		TenantID:     tenantID,
		ProviderType: models.SSOProviderTypeSAML,
		ProviderName: "test-provider",
		DisplayName:  "Test Provider",
		Status:       models.SSOStatusActive,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	mockService.On("GetProvider", mock.Anything, tenantID, providerID).Return(expectedProvider, nil)

	c, w := setupSSOGinContext("GET", "/sso/providers/"+providerID.String(), nil)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: providerID.String()}}

	handler.GetProvider(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.SSOProviderResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, expectedProvider.ID, response.ID)
	assert.Equal(t, expectedProvider.ProviderName, response.ProviderName)

	mockService.AssertExpectations(t)
}

func TestSSOHandler_GetProvider_NotFound(t *testing.T) {
	handler, mockService := setupSSOHandler()

	tenantID := uuid.New()
	providerID := uuid.New()

	mockService.On("GetProvider", mock.Anything, tenantID, providerID).Return(nil, nil)

	c, w := setupSSOGinContext("GET", "/sso/providers/"+providerID.String(), nil)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: providerID.String()}}

	handler.GetProvider(c)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")

	mockService.AssertExpectations(t)
}

func TestSSOHandler_GetProvider_InvalidID(t *testing.T) {
	handler, _ := setupSSOHandler()

	tenantID := uuid.New()

	c, w := setupSSOGinContext("GET", "/sso/providers/invalid-uuid", nil)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: "invalid-uuid"}}

	handler.GetProvider(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestSSOHandler_UpdateProvider(t *testing.T) {
	handler, mockService := setupSSOHandler()

	tenantID := uuid.New()
	providerID := uuid.New()
	newDisplayName := "Updated Provider"
	newStatus := models.SSOStatusActive

	requestBody := models.UpdateSSOProviderRequest{
		DisplayName: &newDisplayName,
		Status:      &newStatus,
	}

	expectedProvider := &models.SSOProvider{
		ID:           providerID,
		TenantID:     tenantID,
		ProviderType: models.SSOProviderTypeSAML,
		ProviderName: "test-provider",
		DisplayName:  newDisplayName,
		Status:       newStatus,
		UpdatedAt:    time.Now(),
	}

	mockService.On("UpdateProvider", mock.Anything, tenantID, providerID, mock.MatchedBy(func(req *models.UpdateSSOProviderRequest) bool {
		return req.DisplayName != nil && *req.DisplayName == newDisplayName &&
			req.Status != nil && *req.Status == newStatus
	})).Return(expectedProvider, nil)

	c, w := setupSSOGinContext("PUT", "/sso/providers/"+providerID.String(), requestBody)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: providerID.String()}}

	handler.UpdateProvider(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.SSOProviderResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, newDisplayName, response.DisplayName)
	assert.Equal(t, newStatus, response.Status)

	mockService.AssertExpectations(t)
}

func TestSSOHandler_UpdateProvider_NotFound(t *testing.T) {
	handler, mockService := setupSSOHandler()

	tenantID := uuid.New()
	providerID := uuid.New()
	newDisplayName := "Updated Provider"

	requestBody := models.UpdateSSOProviderRequest{
		DisplayName: &newDisplayName,
	}

	mockService.On("UpdateProvider", mock.Anything, tenantID, providerID, mock.Anything).Return(nil, nil)

	c, w := setupSSOGinContext("PUT", "/sso/providers/"+providerID.String(), requestBody)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: providerID.String()}}

	handler.UpdateProvider(c)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")

	mockService.AssertExpectations(t)
}

func TestSSOHandler_UpdateProvider_InvalidID(t *testing.T) {
	handler, _ := setupSSOHandler()

	tenantID := uuid.New()
	newDisplayName := "Updated Provider"

	requestBody := models.UpdateSSOProviderRequest{
		DisplayName: &newDisplayName,
	}

	c, w := setupSSOGinContext("PUT", "/sso/providers/invalid-uuid", requestBody)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: "invalid-uuid"}}

	handler.UpdateProvider(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestSSOHandler_UpdateProvider_InvalidJSON(t *testing.T) {
	handler, _ := setupSSOHandler()

	tenantID := uuid.New()
	providerID := uuid.New()

	c, w := setupSSOGinContext("PUT", "/sso/providers/"+providerID.String(), nil)
	c.Request.Body = http.NoBody
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: providerID.String()}}

	handler.UpdateProvider(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestSSOHandler_UpdateProvider_ServiceError(t *testing.T) {
	handler, mockService := setupSSOHandler()

	tenantID := uuid.New()
	providerID := uuid.New()
	newDisplayName := "Updated Provider"

	requestBody := models.UpdateSSOProviderRequest{
		DisplayName: &newDisplayName,
	}

	mockService.On("UpdateProvider", mock.Anything, tenantID, providerID, mock.Anything).Return(nil, errors.New("service error"))

	c, w := setupSSOGinContext("PUT", "/sso/providers/"+providerID.String(), requestBody)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: providerID.String()}}

	handler.UpdateProvider(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")

	mockService.AssertExpectations(t)
}

func TestSSOHandler_DeleteProvider(t *testing.T) {
	handler, mockService := setupSSOHandler()

	tenantID := uuid.New()
	providerID := uuid.New()

	mockService.On("DeleteProvider", mock.Anything, tenantID, providerID).Return(nil)

	c, w := setupSSOGinContext("DELETE", "/sso/providers/"+providerID.String(), nil)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: providerID.String()}}

	handler.DeleteProvider(c)

	assert.Equal(t, http.StatusNoContent, w.Code)

	mockService.AssertExpectations(t)
}

func TestSSOHandler_DeleteProvider_InvalidID(t *testing.T) {
	handler, _ := setupSSOHandler()

	tenantID := uuid.New()

	c, w := setupSSOGinContext("DELETE", "/sso/providers/invalid-uuid", nil)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: "invalid-uuid"}}

	handler.DeleteProvider(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestSSOHandler_DeleteProvider_ServiceError(t *testing.T) {
	handler, mockService := setupSSOHandler()

	tenantID := uuid.New()
	providerID := uuid.New()

	mockService.On("DeleteProvider", mock.Anything, tenantID, providerID).Return(errors.New("service error"))

	c, w := setupSSOGinContext("DELETE", "/sso/providers/"+providerID.String(), nil)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: providerID.String()}}

	handler.DeleteProvider(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")

	mockService.AssertExpectations(t)
}

func TestSSOHandler_TestConnection(t *testing.T) {
	handler, mockService := setupSSOHandler()

	tenantID := uuid.New()
	providerID := uuid.New()

	requestBody := models.TestSSOProviderRequest{
		TestUser:     "test@example.com",
		TestPassword: "password123",
	}

	expectedResult := &models.SSOTestResult{
		Success:           true,
		TestedAt:          time.Now(),
		ResponseTime:      100,
		ConnectionSuccess: true,
		AuthSuccess:       true,
		UserInfoSuccess:   true,
		AttributeMapping:  true,
	}

	mockService.On("TestConnection", mock.Anything, tenantID, providerID, mock.MatchedBy(func(req *models.TestSSOProviderRequest) bool {
		return req.TestUser == "test@example.com" && req.TestPassword == "password123"
	})).Return(expectedResult, nil)

	c, w := setupSSOGinContext("POST", "/sso/test-connection?provider_id="+providerID.String(), requestBody)
	c.Set("tenant_id", tenantID)

	handler.TestConnection(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.SSOTestResult
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
	assert.True(t, response.ConnectionSuccess)

	mockService.AssertExpectations(t)
}

func TestSSOHandler_TestConnection_MissingProviderID(t *testing.T) {
	handler, _ := setupSSOHandler()

	tenantID := uuid.New()

	requestBody := models.TestSSOProviderRequest{
		TestUser:     "test@example.com",
		TestPassword: "password123",
	}

	c, w := setupSSOGinContext("POST", "/sso/test-connection", requestBody)
	c.Set("tenant_id", tenantID)

	handler.TestConnection(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestSSOHandler_TestConnection_InvalidProviderID(t *testing.T) {
	handler, _ := setupSSOHandler()

	tenantID := uuid.New()

	requestBody := models.TestSSOProviderRequest{
		TestUser:     "test@example.com",
		TestPassword: "password123",
	}

	c, w := setupSSOGinContext("POST", "/sso/test-connection?provider_id=invalid-uuid", requestBody)
	c.Set("tenant_id", tenantID)

	handler.TestConnection(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestSSOHandler_NoTenantContext(t *testing.T) {
	handler, _ := setupSSOHandler()

	tests := []struct {
		name     string
		method   string
		path     string
		body     interface{}
		handler  func(*gin.Context)
		expected int
	}{
		{
			name:     "ListProviders without tenant",
			method:   "GET",
			path:     "/sso/providers",
			body:     nil,
			handler:  handler.ListProviders,
			expected: http.StatusBadRequest,
		},
		{
			name:   "CreateProvider without tenant",
			method: "POST",
			path:   "/sso/providers",
			body: models.CreateSSOProviderRequest{
				ProviderType: models.SSOProviderTypeSAML,
				ProviderName: "test",
			},
			handler:  handler.CreateProvider,
			expected: http.StatusBadRequest,
		},
		{
			name:     "GetProvider without tenant",
			method:   "GET",
			path:     "/sso/providers/123",
			body:     nil,
			handler:  handler.GetProvider,
			expected: http.StatusBadRequest,
		},
		{
			name:     "UpdateProvider without tenant",
			method:   "PUT",
			path:     "/sso/providers/123",
			body:     models.UpdateSSOProviderRequest{},
			handler:  handler.UpdateProvider,
			expected: http.StatusBadRequest,
		},
		{
			name:     "DeleteProvider without tenant",
			method:   "DELETE",
			path:     "/sso/providers/123",
			body:     nil,
			handler:  handler.DeleteProvider,
			expected: http.StatusBadRequest,
		},
		{
			name:     "TestConnection without tenant",
			method:   "POST",
			path:     "/sso/test-connection",
			body:     models.TestSSOProviderRequest{},
			handler:  handler.TestConnection,
			expected: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, w := setupSSOGinContext(tt.method, tt.path, tt.body)

			tt.handler(c)

			assert.Equal(t, tt.expected, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, response, "error")
		})
	}
}

func TestNewSSOHandler(t *testing.T) {
	logger := zap.NewNop()
	mockService := &MockSSOService{}

	handler := NewSSOHandler(mockService, logger)

	assert.NotNil(t, handler)
	assert.Equal(t, mockService, handler.ssoService)
	assert.Equal(t, logger, handler.logger)
	assert.NotNil(t, handler.validator)
}

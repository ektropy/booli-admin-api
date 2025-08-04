package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/booli/booli-admin-api/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap/zaptest"
)

type MockEnvironmentService struct {
	mock.Mock
}

func (m *MockEnvironmentService) CreateTenantEnvironment(ctx context.Context, req *models.CreateTenantEnvironmentRequest, userTenantID uuid.UUID) (*models.TenantEnvironment, error) {
	args := m.Called(ctx, req, userTenantID)
	return args.Get(0).(*models.TenantEnvironment), args.Error(1)
}

func (m *MockEnvironmentService) GetTenantEnvironment(ctx context.Context, environmentID, userTenantID uuid.UUID) (*models.TenantEnvironment, error) {
	args := m.Called(ctx, environmentID, userTenantID)
	return args.Get(0).(*models.TenantEnvironment), args.Error(1)
}

func (m *MockEnvironmentService) ListTenantEnvironments(ctx context.Context, tenantID, userTenantID uuid.UUID, page, pageSize int) (*models.TenantEnvironmentListResponse, error) {
	args := m.Called(ctx, tenantID, userTenantID, page, pageSize)
	return args.Get(0).(*models.TenantEnvironmentListResponse), args.Error(1)
}

func (m *MockEnvironmentService) UpdateTenantEnvironment(ctx context.Context, environmentID uuid.UUID, req *models.UpdateTenantEnvironmentRequest, userTenantID uuid.UUID) (*models.TenantEnvironment, error) {
	args := m.Called(ctx, environmentID, req, userTenantID)
	return args.Get(0).(*models.TenantEnvironment), args.Error(1)
}

func (m *MockEnvironmentService) DeleteTenantEnvironment(ctx context.Context, environmentID, userTenantID uuid.UUID) error {
	args := m.Called(ctx, environmentID, userTenantID)
	return args.Error(0)
}

func (m *MockEnvironmentService) GetSIEMEnrichmentData(ctx context.Context, tenantID, userTenantID uuid.UUID) (*models.SIEMEnrichmentData, error) {
	args := m.Called(ctx, tenantID, userTenantID)
	return args.Get(0).(*models.SIEMEnrichmentData), args.Error(1)
}

func (m *MockEnvironmentService) GrantTenantAccess(ctx context.Context, req *models.CreateTenantAccessGrantRequest, granterTenantID uuid.UUID) (*models.TenantAccessGrant, error) {
	args := m.Called(ctx, req, granterTenantID)
	return args.Get(0).(*models.TenantAccessGrant), args.Error(1)
}

func (m *MockEnvironmentService) RevokeAccess(ctx context.Context, grantID, revokerTenantID uuid.UUID) error {
	args := m.Called(ctx, grantID, revokerTenantID)
	return args.Error(0)
}

func setupEnvironmentHandler() (*EnvironmentHandler, *MockEnvironmentService) {
	mockService := &MockEnvironmentService{}
	logger := zaptest.NewLogger(nil)
	handler := NewEnvironmentHandler(mockService, logger)
	return handler, mockService
}

func setupGinContext(method, path string, body interface{}) (*gin.Context, *httptest.ResponseRecorder) {
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

func TestEnvironmentHandler_CreateEnvironment(t *testing.T) {
	handler, mockService := setupEnvironmentHandler()

	tenantID := uuid.New()
	userTenantID := tenantID

	requestBody := models.CreateTenantEnvironmentRequest{
		TenantID:    tenantID,
		Name:        "production",
		Description: "Production environment",
		Environment: "prod",
		NetworkRanges: []models.NetworkRange{
			{
				CIDR:        "10.0.0.0/16",
				Name:        "main-network",
				Description: "Main production network",
			},
		},
	}

	expectedEnvironment := &models.TenantEnvironment{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        "production",
		Description: "Production environment",
		Environment: "prod",
		IsActive:    true,
	}

	mockService.On("CreateTenantEnvironment", mock.Anything, mock.MatchedBy(func(req *models.CreateTenantEnvironmentRequest) bool {
		return req.Name == "production" && req.Description == "Production environment"
	}), userTenantID).Return(expectedEnvironment, nil)

	c, w := setupGinContext("POST", "/environments", requestBody)
	c.Set("tenant_id", tenantID.String())

	handler.CreateEnvironment(c)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response models.TenantEnvironment
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, expectedEnvironment.Name, response.Name)
	assert.Equal(t, expectedEnvironment.Description, response.Description)

	mockService.AssertExpectations(t)
}

func TestEnvironmentHandler_GetEnvironment(t *testing.T) {
	handler, mockService := setupEnvironmentHandler()

	tenantID := uuid.New()
	environmentID := uuid.New()

	expectedEnvironment := &models.TenantEnvironment{
		ID:          environmentID,
		TenantID:    tenantID,
		Name:        "staging",
		Description: "Staging environment",
		Environment: "staging",
		IsActive:    true,
	}

	mockService.On("GetTenantEnvironment", mock.Anything, environmentID, tenantID).Return(expectedEnvironment, nil)

	c, w := setupGinContext("GET", "/environments/"+environmentID.String(), nil)
	c.Set("tenant_id", tenantID.String())
	c.Params = gin.Params{{Key: "id", Value: environmentID.String()}}

	handler.GetEnvironment(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.TenantEnvironment
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, expectedEnvironment.Name, response.Name)

	mockService.AssertExpectations(t)
}

func TestEnvironmentHandler_ListEnvironments(t *testing.T) {
	handler, mockService := setupEnvironmentHandler()

	tenantID := uuid.New()

	expectedResponse := &models.TenantEnvironmentListResponse{
		Environments: []models.TenantEnvironment{
			{
				ID:          uuid.New(),
				TenantID:    tenantID,
				Name:        "production",
				Description: "Production environment",
				IsActive:    true,
			},
			{
				ID:          uuid.New(),
				TenantID:    tenantID,
				Name:        "staging",
				Description: "Staging environment",
				IsActive:    true,
			},
		},
		Total:      2,
		Page:       1,
		PageSize:   10,
		TotalPages: 1,
	}

	mockService.On("ListTenantEnvironments", mock.Anything, tenantID, tenantID, 1, 10).Return(expectedResponse, nil)

	c, w := setupGinContext("GET", "/environments?page=1&page_size=10", nil)
	c.Params = gin.Params{{Key: "tenant_id", Value: tenantID.String()}}
	c.Set("tenant_id", tenantID.String())

	handler.ListEnvironments(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.TenantEnvironmentListResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), response.Total)
	assert.Len(t, response.Environments, 2)

	mockService.AssertExpectations(t)
}

func TestEnvironmentHandler_UpdateEnvironment(t *testing.T) {
	handler, mockService := setupEnvironmentHandler()

	tenantID := uuid.New()
	environmentID := uuid.New()

	newName := "updated-environment"
	requestBody := models.UpdateTenantEnvironmentRequest{
		Name: &newName,
	}

	expectedEnvironment := &models.TenantEnvironment{
		ID:          environmentID,
		TenantID:    tenantID,
		Name:        newName,
		Description: "Updated environment",
		IsActive:    true,
	}

	mockService.On("UpdateTenantEnvironment", mock.Anything, environmentID, mock.Anything, tenantID).Return(expectedEnvironment, nil)

	c, w := setupGinContext("PUT", "/environments/"+environmentID.String(), requestBody)
	c.Set("tenant_id", tenantID.String())
	c.Params = gin.Params{{Key: "id", Value: environmentID.String()}}

	handler.UpdateEnvironment(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.TenantEnvironment
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, newName, response.Name)

	mockService.AssertExpectations(t)
}

func TestEnvironmentHandler_DeleteEnvironment(t *testing.T) {
	handler, mockService := setupEnvironmentHandler()

	tenantID := uuid.New()
	environmentID := uuid.New()

	mockService.On("DeleteTenantEnvironment", mock.Anything, environmentID, tenantID).Return(nil)

	c, w := setupGinContext("DELETE", "/environments/"+environmentID.String(), nil)
	c.Set("tenant_id", tenantID.String())
	c.Params = gin.Params{{Key: "id", Value: environmentID.String()}}

	handler.DeleteEnvironment(c)

	assert.Equal(t, http.StatusNoContent, w.Code)

	mockService.AssertExpectations(t)
}

func TestEnvironmentHandler_GetSIEMEnrichmentData(t *testing.T) {
	handler, mockService := setupEnvironmentHandler()

	tenantID := uuid.New()

	expectedData := &models.SIEMEnrichmentData{
		TenantID: tenantID,
		NetworkRanges: []models.NetworkRange{
			{
				CIDR:        "10.0.0.0/16",
				Name:        "production-network",
				Description: "Production network range",
			},
		},
		PublicIPs: []models.PublicIP{
			{
				IPAddress: "203.0.113.1",
				Purpose:   "web-server",
			},
		},
		Domains: []models.Domain{
			{
				DomainName: "example.com",
				Purpose:    "main-domain",
			},
		},
	}

	mockService.On("GetSIEMEnrichmentData", mock.Anything, tenantID, tenantID).Return(expectedData, nil)

	c, w := setupGinContext("GET", "/environments/enrichment", nil)
	c.Params = gin.Params{{Key: "tenant_id", Value: tenantID.String()}}
	c.Set("tenant_id", tenantID.String())

	handler.GetSIEMEnrichmentData(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.SIEMEnrichmentData
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, tenantID, response.TenantID)
	assert.Len(t, response.NetworkRanges, 1)
	assert.Len(t, response.PublicIPs, 1)
	assert.Len(t, response.Domains, 1)

	mockService.AssertExpectations(t)
}

func TestEnvironmentHandler_InvalidTenantID(t *testing.T) {
	handler, _ := setupEnvironmentHandler()

	c, w := setupGinContext("GET", "/environments", nil)
	c.Set("tenant_id", "invalid-uuid")

	handler.ListEnvironments(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, float64(401), response["status"])
	errorDetail, ok := response["error"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "UNAUTHORIZED", errorDetail["code"])
	assert.Equal(t, "Invalid tenant context", errorDetail["message"])
}

func TestEnvironmentHandler_MissingTenantID(t *testing.T) {
	handler, _ := setupEnvironmentHandler()

	c, w := setupGinContext("GET", "/environments", nil)

	handler.ListEnvironments(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, float64(401), response["status"])
	errorDetail, ok := response["error"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "UNAUTHORIZED", errorDetail["code"])
	assert.Equal(t, "Invalid tenant context", errorDetail["message"])
}

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/booli/booli-admin-api/internal/constants"
	"github.com/booli/booli-admin-api/internal/models"
	"github.com/booli/booli-admin-api/internal/services"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) ListUsers(ctx context.Context, tenantID uuid.UUID, req *models.UserSearchRequest) ([]models.User, int64, error) {
	args := m.Called(ctx, tenantID, req)
	return args.Get(0).([]models.User), args.Get(1).(int64), args.Error(2)
}

func (m *MockUserService) CreateUser(ctx context.Context, req *models.CreateUserRequest) (*models.User, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) GetUser(ctx context.Context, tenantID uuid.UUID, userID string) (*models.User, error) {
	args := m.Called(ctx, tenantID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) UpdateUser(ctx context.Context, tenantID uuid.UUID, userID string, req *models.UpdateUserRequest) (*models.User, error) {
	args := m.Called(ctx, tenantID, userID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) DeleteUser(ctx context.Context, tenantID uuid.UUID, userID string) error {
	args := m.Called(ctx, tenantID, userID)
	return args.Error(0)
}

func (m *MockUserService) BulkCreateUsers(ctx context.Context, tenantID uuid.UUID, req *models.BulkCreateUserRequest) ([]models.User, error) {
	args := m.Called(ctx, tenantID, req)
	return args.Get(0).([]models.User), args.Error(1)
}

func (m *MockUserService) ImportUsersFromCSV(ctx context.Context, tenantID uuid.UUID, records [][]string) (*services.CSVImportResult, error) {
	args := m.Called(ctx, tenantID, records)
	return args.Get(0).(*services.CSVImportResult), args.Error(1)
}

func setupUserHandler() (*UserHandler, *MockUserService) {
	mockService := &MockUserService{}
	logger := zap.NewNop()

	handler := &UserHandler{
		userService: mockService,
		logger:      logger,
		validator:   validator.New(),
	}
	return handler, mockService
}

func setupUserGinContext(method, path string, body interface{}) (*gin.Context, *httptest.ResponseRecorder) {
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

func TestUserHandler_List(t *testing.T) {
	handler, mockService := setupUserHandler()

	tenantID := uuid.New()
	expectedUsers := []models.User{
		{
			ID:        uuid.New().String(),
			TenantID:  tenantID,
			Email:     "test@example.com",
			FirstName: "Test",
			LastName:  "User",
			Enabled:   true,
		},
	}

	mockService.On("ListUsers", mock.Anything, tenantID, mock.MatchedBy(func(req *models.UserSearchRequest) bool {
		return req.Page == 1 && req.PageSize == 10
	})).Return(expectedUsers, int64(1), nil)

	c, w := setupUserGinContext("GET", "/users?page=1&page_size=10", nil)
	c.Set("tenant_id", tenantID)

	handler.List(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.UserListResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), response.Total)
	assert.Len(t, response.Users, 1)

	mockService.AssertExpectations(t)
}

func TestUserHandler_Create(t *testing.T) {
	handler, mockService := setupUserHandler()

	tenantID := uuid.New()
	requestBody := models.CreateUserRequest{
		TenantID:  tenantID,
		Email:     "new@example.com",
		FirstName: "New",
		LastName:  "User",
		Password:  "password123",
	}

	expectedUser := &models.User{
		ID:        uuid.New().String(),
		TenantID:  tenantID,
		Email:     "new@example.com",
		FirstName: "New",
		LastName:  "User",
		Enabled:   true,
	}

	mockService.On("CreateUser", mock.Anything, mock.MatchedBy(func(req *models.CreateUserRequest) bool {
		return req.Email == "new@example.com" && req.FirstName == "New" && req.LastName == "User"
	})).Return(expectedUser, nil)

	c, w := setupUserGinContext("POST", "/users", requestBody)
	c.Set("tenant_id", tenantID)

	handler.Create(c)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response models.UserResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, expectedUser.Email, response.Email)
	assert.Equal(t, expectedUser.FirstName, response.FirstName)
	assert.Equal(t, expectedUser.LastName, response.LastName)

	mockService.AssertExpectations(t)
}

func TestUserHandler_Create_MSPAdmin(t *testing.T) {
	handler, mockService := setupUserHandler()

	requestBody := models.CreateUserRequest{
		TenantName: "test-tenant",
		Email:      "admin@example.com",
		FirstName:  "Admin",
		LastName:   "User",
		Password:   "password123",
	}

	expectedUser := &models.User{
		ID:        uuid.New().String(),
		Email:     "admin@example.com",
		FirstName: "Admin",
		LastName:  "User",
	}

	mockService.On("CreateUser", mock.Anything, mock.MatchedBy(func(req *models.CreateUserRequest) bool {
		return req.TenantName == "test-tenant" && req.Email == "admin@example.com" && req.FirstName == "Admin"
	})).Return(expectedUser, nil)

	c, w := setupUserGinContext("POST", "/users", requestBody)
	c.Set("user_roles", []string{constants.RoleMSPAdmin})

	handler.Create(c)

	assert.Equal(t, http.StatusCreated, w.Code)
	mockService.AssertExpectations(t)
}

func TestUserHandler_Get(t *testing.T) {
	handler, mockService := setupUserHandler()

	tenantID := uuid.New()
	userID := uuid.New().String()

	expectedUser := &models.User{
		ID:        userID,
		TenantID:  tenantID,
		Email:     "test@example.com",
		FirstName: "Test",
		LastName:  "User",
		Enabled:   true,
	}

	mockService.On("GetUser", mock.Anything, tenantID, userID).Return(expectedUser, nil)

	c, w := setupUserGinContext("GET", "/users/"+userID, nil)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: userID}}

	handler.Get(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.UserResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, expectedUser.Email, response.Email)

	mockService.AssertExpectations(t)
}

func TestUserHandler_Update(t *testing.T) {
	handler, mockService := setupUserHandler()

	tenantID := uuid.New()
	userID := uuid.New().String()
	newFirstName := "Updated"

	requestBody := models.UpdateUserRequest{
		FirstName: &newFirstName,
	}

	expectedUser := &models.User{
		ID:        userID,
		TenantID:  tenantID,
		Email:     "test@example.com",
		FirstName: newFirstName,
		LastName:  "User",
		Enabled:   true,
	}

	mockService.On("UpdateUser", mock.Anything, tenantID, userID, mock.Anything).Return(expectedUser, nil)

	c, w := setupUserGinContext("PUT", "/users/"+userID, requestBody)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: userID}}

	handler.Update(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.UserResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, newFirstName, response.FirstName)

	mockService.AssertExpectations(t)
}

func TestUserHandler_Delete(t *testing.T) {
	handler, mockService := setupUserHandler()

	tenantID := uuid.New()
	userID := uuid.New().String()

	mockService.On("DeleteUser", mock.Anything, tenantID, userID).Return(nil)

	c, w := setupUserGinContext("DELETE", "/users/"+userID, nil)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: userID}}

	handler.Delete(c)

	assert.Equal(t, http.StatusNoContent, w.Code)
	mockService.AssertExpectations(t)
}

func TestUserHandler_BulkCreate(t *testing.T) {
	handler, mockService := setupUserHandler()

	tenantID := uuid.New()
	requestBody := models.BulkCreateUserRequest{
		Users: []models.CreateUserRequest{
			{
				Email:     "user1@example.com",
				FirstName: "User",
				LastName:  "One",
				Password:  "password123",
			},
			{
				Email:     "user2@example.com",
				FirstName: "User",
				LastName:  "Two",
				Password:  "password123",
			},
		},
	}

	expectedResults := []models.User{
		{
			ID:        uuid.New().String(),
			Email:     "user1@example.com",
			FirstName: "User",
			LastName:  "One",
			Enabled:   true,
		},
		{
			ID:        uuid.New().String(),
			Email:     "user2@example.com",
			FirstName: "User",
			LastName:  "Two",
			Enabled:   true,
		},
	}

	mockService.On("BulkCreateUsers", mock.Anything, tenantID, mock.Anything).Return(expectedResults, nil)

	c, w := setupUserGinContext("POST", "/users/bulk-create", requestBody)
	c.Set("tenant_id", tenantID)

	handler.BulkCreate(c)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "results")

	mockService.AssertExpectations(t)
}

func TestUserHandler_ImportCSV(t *testing.T) {
	handler, mockService := setupUserHandler()

	tenantID := uuid.New()
	csvContent := "email,first_name,last_name\ntest@example.com,Test,User\n"

	expectedResult := &services.CSVImportResult{
		TotalProcessed: 1,
		SuccessCount:   1,
		ErrorCount:     0,
		SuccessfulUsers: []models.User{
			{
				ID:        uuid.New().String(),
				Email:     "test@example.com",
				FirstName: "Test",
				LastName:  "User",
			},
		},
		FailedUsers: []services.CSVError{},
	}

	mockService.On("ImportUsersFromCSV", mock.Anything, tenantID, mock.MatchedBy(func(records [][]string) bool {
		return len(records) == 2 && records[0][0] == "email" && records[1][0] == "test@example.com"
	})).Return(expectedResult, nil)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "users.csv")
	part.Write([]byte(csvContent))
	writer.Close()

	req := httptest.NewRequest("POST", "/users/import-csv", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("tenant_id", tenantID)

	handler.ImportCSV(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response services.CSVImportResult
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 1, response.TotalProcessed)
	assert.Equal(t, 1, response.SuccessCount)

	mockService.AssertExpectations(t)
}

func TestUserHandler_InvalidTenantID(t *testing.T) {
	handler, _ := setupUserHandler()

	c, w := setupUserGinContext("GET", "/users", nil)

	handler.List(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestUserHandler_Get_NotFound(t *testing.T) {
	handler, mockService := setupUserHandler()

	tenantID := uuid.New()
	userID := uuid.New().String()

	mockService.On("GetUser", mock.Anything, tenantID, userID).Return(nil, nil)

	c, w := setupUserGinContext("GET", "/users/"+userID, nil)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: userID}}

	handler.Get(c)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")

	mockService.AssertExpectations(t)
}

func TestUserHandler_Create_ValidationError(t *testing.T) {
	handler, _ := setupUserHandler()

	requestBody := models.CreateUserRequest{
		Email: "invalid-email",
	}

	c, w := setupUserGinContext("POST", "/users", requestBody)
	c.Set("tenant_id", uuid.New())

	handler.Create(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestUserHandler_Create_InvalidJSON(t *testing.T) {
	handler, _ := setupUserHandler()

	c, w := setupUserGinContext("POST", "/users", nil)
	c.Request.Body = io.NopCloser(strings.NewReader("invalid json"))
	c.Set("tenant_id", uuid.New())

	handler.Create(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestUserHandler_Update_NotFound(t *testing.T) {
	handler, mockService := setupUserHandler()

	tenantID := uuid.New()
	userID := uuid.New().String()
	newFirstName := "Updated"

	requestBody := models.UpdateUserRequest{
		FirstName: &newFirstName,
	}

	mockService.On("UpdateUser", mock.Anything, tenantID, userID, mock.Anything).Return(nil, nil)

	c, w := setupUserGinContext("PUT", "/users/"+userID, requestBody)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: userID}}

	handler.Update(c)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")

	mockService.AssertExpectations(t)
}

func TestUserHandler_Update_InvalidJSON(t *testing.T) {
	handler, _ := setupUserHandler()

	tenantID := uuid.New()
	userID := uuid.New().String()

	c, w := setupUserGinContext("PUT", "/users/"+userID, nil)
	c.Request.Body = io.NopCloser(strings.NewReader("invalid json"))
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: userID}}

	handler.Update(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestUserHandler_Update_ValidationError(t *testing.T) {
	handler, _ := setupUserHandler()

	tenantID := uuid.New()
	userID := uuid.New().String()
	invalidEmail := "invalid-email"

	requestBody := models.UpdateUserRequest{
		Email: &invalidEmail,
	}

	c, w := setupUserGinContext("PUT", "/users/"+userID, requestBody)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: userID}}

	handler.Update(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestUserHandler_Update_MissingUserID(t *testing.T) {
	handler, _ := setupUserHandler()

	tenantID := uuid.New()
	newFirstName := "Updated"

	requestBody := models.UpdateUserRequest{
		FirstName: &newFirstName,
	}

	c, w := setupUserGinContext("PUT", "/users/", requestBody)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: ""}}

	handler.Update(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestUserHandler_Delete_MissingUserID(t *testing.T) {
	handler, _ := setupUserHandler()

	tenantID := uuid.New()

	c, w := setupUserGinContext("DELETE", "/users/", nil)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: ""}}

	handler.Delete(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestUserHandler_Delete_MSPAdmin(t *testing.T) {
	handler, mockService := setupUserHandler()

	userID := uuid.New().String()

	mockService.On("DeleteUser", mock.Anything, uuid.Nil, userID).Return(nil)

	c, w := setupUserGinContext("DELETE", "/users/"+userID, nil)
	c.Set("user_roles", []string{constants.RoleMSPAdmin})
	c.Params = gin.Params{{Key: "id", Value: userID}}

	handler.Delete(c)

	assert.Equal(t, http.StatusNoContent, w.Code)

	mockService.AssertExpectations(t)
}

func TestUserHandler_Delete_MSPPower(t *testing.T) {
	handler, mockService := setupUserHandler()

	userID := uuid.New().String()

	mockService.On("DeleteUser", mock.Anything, uuid.Nil, userID).Return(nil)

	c, w := setupUserGinContext("DELETE", "/users/"+userID, nil)
	c.Set("user_roles", []string{constants.RoleMSPPower})
	c.Params = gin.Params{{Key: "id", Value: userID}}

	handler.Delete(c)

	assert.Equal(t, http.StatusNoContent, w.Code)

	mockService.AssertExpectations(t)
}

func TestUserHandler_BulkCreate_InvalidJSON(t *testing.T) {
	handler, _ := setupUserHandler()

	tenantID := uuid.New()

	c, w := setupUserGinContext("POST", "/users/bulk-create", nil)
	c.Request.Body = io.NopCloser(strings.NewReader("invalid json"))
	c.Set("tenant_id", tenantID)

	handler.BulkCreate(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestUserHandler_BulkCreate_ValidationError(t *testing.T) {
	handler, _ := setupUserHandler()

	tenantID := uuid.New()
	requestBody := models.BulkCreateUserRequest{
		Users: []models.CreateUserRequest{},
	}

	c, w := setupUserGinContext("POST", "/users/bulk-create", requestBody)
	c.Set("tenant_id", tenantID)

	handler.BulkCreate(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestUserHandler_ImportCSV_MissingFile(t *testing.T) {
	handler, _ := setupUserHandler()

	tenantID := uuid.New()

	req := httptest.NewRequest("POST", "/users/import-csv", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("tenant_id", tenantID)

	handler.ImportCSV(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestUserHandler_ImportCSV_InvalidFileType(t *testing.T) {
	handler, _ := setupUserHandler()

	tenantID := uuid.New()
	fileContent := "not a csv file"

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "users.txt")
	part.Write([]byte(fileContent))
	writer.Close()

	req := httptest.NewRequest("POST", "/users/import-csv", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("tenant_id", tenantID)

	handler.ImportCSV(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestUserHandler_ImportCSV_InvalidCSVFormat(t *testing.T) {
	handler, _ := setupUserHandler()

	tenantID := uuid.New()
	csvContent := "invalid,csv,format\nwith,\"unclosed,quote"

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "users.csv")
	part.Write([]byte(csvContent))
	writer.Close()

	req := httptest.NewRequest("POST", "/users/import-csv", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("tenant_id", tenantID)

	handler.ImportCSV(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestUserHandler_ImportCSV_EmptyFile(t *testing.T) {
	handler, _ := setupUserHandler()

	tenantID := uuid.New()
	csvContent := "email,first_name,last_name"

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "users.csv")
	part.Write([]byte(csvContent))
	writer.Close()

	req := httptest.NewRequest("POST", "/users/import-csv", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("tenant_id", tenantID)

	handler.ImportCSV(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestUserHandler_Get_ServiceError(t *testing.T) {
	handler, mockService := setupUserHandler()

	tenantID := uuid.New()
	userID := uuid.New().String()

	mockService.On("GetUser", mock.Anything, tenantID, userID).Return(nil, errors.New("service error"))

	c, w := setupUserGinContext("GET", "/users/"+userID, nil)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: userID}}

	handler.Get(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	mockService.AssertExpectations(t)
}

func TestUserHandler_Get_MissingUserID(t *testing.T) {
	handler, _ := setupUserHandler()

	tenantID := uuid.New()

	c, w := setupUserGinContext("GET", "/users/", nil)
	c.Set("tenant_id", tenantID)
	c.Params = gin.Params{{Key: "id", Value: ""}}

	handler.Get(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestNewUserHandler(t *testing.T) {
	logger := zap.NewNop()
	mockService := &MockUserService{}

	handler := NewUserHandler(mockService, logger)

	assert.NotNil(t, handler)
	assert.Equal(t, mockService, handler.userService)
	assert.Equal(t, logger, handler.logger)
	assert.NotNil(t, handler.validator)
}

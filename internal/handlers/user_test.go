package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/booli/booli-admin-api/internal/models"
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

func (m *MockUserService) ListUsers(ctx context.Context, realmName string, req *models.UserSearchRequest) ([]models.User, int64, error) {
	args := m.Called(ctx, realmName, req)
	return args.Get(0).([]models.User), args.Get(1).(int64), args.Error(2)
}

func (m *MockUserService) CreateUser(ctx context.Context, realmName string, req *models.CreateUserRequest) (*models.User, error) {
	args := m.Called(ctx, realmName, req)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) GetUser(ctx context.Context, realmName, userID string) (*models.User, error) {
	args := m.Called(ctx, realmName, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) UpdateUser(ctx context.Context, realmName, userID string, req *models.UpdateUserRequest) (*models.User, error) {
	args := m.Called(ctx, realmName, userID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) DeleteUser(ctx context.Context, realmName, userID string) error {
	args := m.Called(ctx, realmName, userID)
	return args.Error(0)
}

func (m *MockUserService) BulkCreateUsers(ctx context.Context, realmName string, users []models.CreateUserRequest) (*models.BulkCreateResult, error) {
	args := m.Called(ctx, realmName, users)
	return args.Get(0).(*models.BulkCreateResult), args.Error(1)
}

func (m *MockUserService) ImportUsersFromCSV(ctx context.Context, realmName string, csvRecords [][]string) (*models.CSVImportResult, error) {
	args := m.Called(ctx, realmName, csvRecords)
	return args.Get(0).(*models.CSVImportResult), args.Error(1)
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
		req = httptest.NewRequest(method, path, strings.NewReader(string(jsonBody)))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}

	c.Request = req
	return c, w
}

func TestUserHandler_List(t *testing.T) {
	handler, mockService := setupUserHandler()

	realmName := "test-realm"
	expectedUsers := []models.User{
		{
			ID:        uuid.New().String(),
			Email:     "test@example.com",
			FirstName: "Test",
			LastName:  "User",
			Enabled:   true,
		},
	}

	mockService.On("ListUsers", mock.Anything, realmName, mock.MatchedBy(func(req *models.UserSearchRequest) bool {
		return req.Page == 1 && req.PageSize == 10
	})).Return(expectedUsers, int64(1), nil)

	c, w := setupUserGinContext("GET", "/users?page=1&page_size=10", nil)
	c.Set("realm_name", realmName)

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

	realmName := "test-realm"
	requestBody := models.CreateUserRequest{
		Username:  "newuser",
		Email:     "new@example.com",
		FirstName: "New",
		LastName:  "User",
		Password:  "password123",
	}

	expectedUser := &models.User{
		ID:        uuid.New().String(),
		Email:     "new@example.com",
		FirstName: "New",
		LastName:  "User",
		Enabled:   true,
	}

	mockService.On("CreateUser", mock.Anything, realmName, mock.MatchedBy(func(req *models.CreateUserRequest) bool {
		return req.Email == "new@example.com" && req.FirstName == "New" && req.LastName == "User"
	})).Return(expectedUser, nil)

	c, w := setupUserGinContext("POST", "/users", requestBody)
	c.Set("realm_name", realmName)

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

func TestUserHandler_Get(t *testing.T) {
	handler, mockService := setupUserHandler()

	realmName := "test-realm"
	userID := uuid.New().String()

	expectedUser := &models.User{
		ID:        userID,
		Email:     "test@example.com",
		FirstName: "Test",
		LastName:  "User",
		Enabled:   true,
	}

	mockService.On("GetUser", mock.Anything, realmName, userID).Return(expectedUser, nil)

	c, w := setupUserGinContext("GET", "/users/"+userID, nil)
	c.Set("realm_name", realmName)
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

	realmName := "test-realm"
	userID := uuid.New().String()
	newFirstName := "Updated"

	requestBody := models.UpdateUserRequest{
		FirstName: &newFirstName,
	}

	expectedUser := &models.User{
		ID:        userID,
		Email:     "test@example.com",
		FirstName: newFirstName,
		LastName:  "User",
		Enabled:   true,
	}

	mockService.On("UpdateUser", mock.Anything, realmName, userID, mock.Anything).Return(expectedUser, nil)

	c, w := setupUserGinContext("PUT", "/users/"+userID, requestBody)
	c.Set("realm_name", realmName)
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

	realmName := "test-realm"
	userID := uuid.New().String()

	mockService.On("DeleteUser", mock.Anything, realmName, userID).Return(nil)

	c, w := setupUserGinContext("DELETE", "/users/"+userID, nil)
	c.Set("realm_name", realmName)
	c.Params = gin.Params{{Key: "id", Value: userID}}

	handler.Delete(c)

	assert.Equal(t, http.StatusNoContent, w.Code)
	mockService.AssertExpectations(t)
}

func TestUserHandler_BulkCreate_Success(t *testing.T) {
	handler, mockService := setupUserHandler()

	realmName := "test-realm"
	users := []models.CreateUserRequest{
		{
			Username:  "user1",
			Email:     "user1@example.com",
			FirstName: "User",
			LastName:  "One",
			Password:  "password123",
			Enabled:   true,
		},
		{
			Username:  "user2",
			Email:     "user2@example.com",
			FirstName: "User",
			LastName:  "Two",
			Password:  "password456",
			Enabled:   true,
		},
	}

	requestBody := models.BulkCreateUserRequest{
		Users: users,
	}

	expectedResult := &models.BulkCreateResult{
		TotalProcessed: 2,
		SuccessCount:   2,
		FailureCount:   0,
		Successful: []*models.User{
			{ID: "user1", Email: "user1@example.com", FirstName: "User", LastName: "One", Enabled: true},
			{ID: "user2", Email: "user2@example.com", FirstName: "User", LastName: "Two", Enabled: true},
		},
		Failed: []models.BulkError{},
	}

	mockService.On("BulkCreateUsers", mock.Anything, realmName, users).Return(expectedResult, nil)

	c, w := setupUserGinContext("POST", "/users/bulk-create", requestBody)
	c.Set("realm_name", realmName)

	handler.BulkCreate(c)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response models.BulkCreateResult
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 2, response.TotalProcessed)
	assert.Equal(t, 2, response.SuccessCount)
	assert.Equal(t, 0, response.FailureCount)

	mockService.AssertExpectations(t)
}

func TestUserHandler_ImportCSV_Success(t *testing.T) {
	handler, mockService := setupUserHandler()

	realmName := "test-realm"
	csvData := `email,first_name,last_name,username,password,role,enabled
user1@example.com,User,One,user1,pass123,tenant-user,true
user2@example.com,User,Two,user2,pass456,tenant-admin,true`

	expectedResult := &models.CSVImportResult{
		TotalProcessed: 2,
		SuccessCount:   2,
		ErrorCount:     0,
		SuccessfulUsers: []models.User{
			{ID: "user1", Email: "user1@example.com", FirstName: "User", LastName: "One", Enabled: true},
			{ID: "user2", Email: "user2@example.com", FirstName: "User", LastName: "Two", Enabled: true},
		},
		FailedUsers: []models.CSVError{},
		ParseErrors: []models.CSVError{},
	}

	expectedRecords := [][]string{
		{"email", "first_name", "last_name", "username", "password", "role", "enabled"},
		{"user1@example.com", "User", "One", "user1", "pass123", "tenant-user", "true"},
		{"user2@example.com", "User", "Two", "user2", "pass456", "tenant-admin", "true"},
	}

	mockService.On("ImportUsersFromCSV", mock.Anything, realmName, expectedRecords).Return(expectedResult, nil)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "users.csv")
	assert.NoError(t, err)

	_, err = part.Write([]byte(csvData))
	assert.NoError(t, err)

	err = writer.Close()
	assert.NoError(t, err)

	req, err := http.NewRequest("POST", "/users/import-csv", body)
	assert.NoError(t, err)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("realm_name", realmName)

	handler.ImportCSV(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.CSVImportResult
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, 2, response.TotalProcessed)
	assert.Equal(t, 2, response.SuccessCount)
	assert.Equal(t, 0, response.ErrorCount)

	mockService.AssertExpectations(t)
}

func TestUserHandler_List_MissingRealmName(t *testing.T) {
	handler, _ := setupUserHandler()

	c, w := setupUserGinContext("GET", "/users", nil)

	handler.List(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestUserHandler_Get_NotFound(t *testing.T) {
	handler, mockService := setupUserHandler()

	realmName := "test-realm"
	userID := uuid.New().String()

	mockService.On("GetUser", mock.Anything, realmName, userID).Return(nil, nil)

	c, w := setupUserGinContext("GET", "/users/"+userID, nil)
	c.Set("realm_name", realmName)
	c.Params = gin.Params{{Key: "id", Value: userID}}

	handler.Get(c)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")

	mockService.AssertExpectations(t)
}

func TestUserHandler_Get_ServiceError(t *testing.T) {
	handler, mockService := setupUserHandler()

	realmName := "test-realm"
	userID := uuid.New().String()

	mockService.On("GetUser", mock.Anything, realmName, userID).Return(nil, errors.New("service error"))

	c, w := setupUserGinContext("GET", "/users/"+userID, nil)
	c.Set("realm_name", realmName)
	c.Params = gin.Params{{Key: "id", Value: userID}}

	handler.Get(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	mockService.AssertExpectations(t)
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

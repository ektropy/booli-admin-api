package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/booli/booli-admin-api/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

type MockKeycloakAdmin struct {
	mock.Mock
}

func (m *MockKeycloakAdmin) ExecuteActionsEmail(ctx context.Context, realmName, userID string, actions []string, lifespan int, clientID, redirectURI string) error {
	args := m.Called(ctx, realmName, userID, actions, lifespan, clientID, redirectURI)
	return args.Error(0)
}

func (m *MockKeycloakAdmin) SendVerifyEmail(ctx context.Context, realmName, userID string) error {
	args := m.Called(ctx, realmName, userID)
	return args.Error(0)
}

func setupUserInviteHandler() (*UserInviteHandler, *MockUserService, *MockKeycloakAdmin) {
	mockUserService := &MockUserService{}
	mockKeycloak := &MockKeycloakAdmin{}
	logger := zap.NewNop()

	handler := NewUserInviteHandler(mockUserService, mockKeycloak, logger)
	return handler, mockUserService, mockKeycloak
}

func setupInviteGinContext(method, path string, body interface{}) (*gin.Context, *httptest.ResponseRecorder) {
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

func TestUserInviteHandler_CreateWithInvite(t *testing.T) {
	handler, mockUserService, _ := setupUserInviteHandler()

	realmName := "test-realm"
	requestBody := models.CreateUserRequest{
		Username:  "inviteuser",
		Email:     "invite@example.com",
		FirstName: "Invite",
		LastName:  "User",
	}

	expectedUser := &models.User{
		ID:        uuid.New().String(),
		Email:     "invite@example.com",
		FirstName: "Invite",
		LastName:  "User",
		Enabled:   false,
	}

	mockUserService.On("CreateUser", mock.Anything, realmName, mock.MatchedBy(func(req *models.CreateUserRequest) bool {
		return req.Email == "invite@example.com" && req.SendInvite == true && req.Enabled == false
	})).Return(expectedUser, nil)

	c, w := setupInviteGinContext("POST", "/users/invite", requestBody)
	c.Set("realm_name", realmName)

	handler.CreateWithInvite(c)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, true, response["invite_sent"])
	assert.Equal(t, "invitation_pending", response["status"])
	assert.Contains(t, response, "expires_at")

	mockUserService.AssertExpectations(t)
}

func TestUserInviteHandler_SendInvite_Success(t *testing.T) {
	handler, _, mockKeycloak := setupUserInviteHandler()

	realmName := "test-realm"
	userID := uuid.New().String()
	requestBody := map[string]interface{}{
		"actions":  []string{"UPDATE_PASSWORD", "VERIFY_EMAIL"},
		"lifespan": 86400,
	}

	mockKeycloak.On("ExecuteActionsEmail", mock.Anything, realmName, userID,
		[]string{"UPDATE_PASSWORD", "VERIFY_EMAIL"}, 86400, "", "").Return(nil)

	c, w := setupInviteGinContext("POST", "/users/"+userID+"/send-invite", requestBody)
	c.Set("realm_name", realmName)
	c.Params = gin.Params{{Key: "userId", Value: userID}}

	handler.SendInvite(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invitation_sent", response["status"])
	assert.Equal(t, userID, response["user_id"])
	assert.Contains(t, response, "expires_at")

	mockKeycloak.AssertExpectations(t)
}

func TestUserInviteHandler_SendInvite_DefaultActions(t *testing.T) {
	handler, _, mockKeycloak := setupUserInviteHandler()

	realmName := "test-realm"
	userID := uuid.New().String()

	mockKeycloak.On("ExecuteActionsEmail", mock.Anything, realmName, userID,
		[]string{"UPDATE_PASSWORD", "VERIFY_EMAIL"}, 259200, "", "").Return(nil)

	c, w := setupInviteGinContext("POST", "/users/"+userID+"/send-invite", nil)
	c.Set("realm_name", realmName)
	c.Params = gin.Params{{Key: "userId", Value: userID}}

	handler.SendInvite(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invitation_sent", response["status"])
	assert.Equal(t, userID, response["user_id"])

	mockKeycloak.AssertExpectations(t)
}

func TestUserInviteHandler_SendVerifyEmail_Success(t *testing.T) {
	handler, _, mockKeycloak := setupUserInviteHandler()

	realmName := "test-realm"
	userID := uuid.New().String()

	mockKeycloak.On("SendVerifyEmail", mock.Anything, realmName, userID).Return(nil)

	c, w := setupInviteGinContext("POST", "/users/"+userID+"/verify-email", nil)
	c.Set("realm_name", realmName)
	c.Params = gin.Params{{Key: "userId", Value: userID}}

	handler.SendVerifyEmail(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "verification_email_sent", response["status"])
	assert.Equal(t, userID, response["user_id"])

	mockKeycloak.AssertExpectations(t)
}

func TestUserInviteHandler_CreateWithInvite_MissingRealm(t *testing.T) {
	handler, _, _ := setupUserInviteHandler()

	requestBody := models.CreateUserRequest{
		Username: "inviteuser",
		Email:    "invite@example.com",
	}

	c, w := setupInviteGinContext("POST", "/users/invite", requestBody)

	handler.CreateWithInvite(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestUserInviteHandler_SendInvite_MissingUserID(t *testing.T) {
	handler, _, _ := setupUserInviteHandler()

	realmName := "test-realm"

	c, w := setupInviteGinContext("POST", "/users/send-invite", nil)
	c.Set("realm_name", realmName)
	c.Params = gin.Params{{Key: "userId", Value: ""}}

	handler.SendInvite(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

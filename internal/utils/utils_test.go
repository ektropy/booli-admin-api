package utils

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
)

func TestRespondWithError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		statusCode int
		errorCode  string
		message    string
		details    interface{}
	}{
		{
			name:       "Bad Request with details",
			statusCode: http.StatusBadRequest,
			errorCode:  ErrCodeBadRequest,
			message:    "Invalid input",
			details:    "Username is required",
		},
		{
			name:       "Internal Error without details",
			statusCode: http.StatusInternalServerError,
			errorCode:  ErrCodeInternalError,
			message:    "Something went wrong",
			details:    nil,
		},
		{
			name:       "Unauthorized",
			statusCode: http.StatusUnauthorized,
			errorCode:  ErrCodeUnauthorized,
			message:    "Access denied",
			details:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/test", nil)

			RespondWithError(c, tt.statusCode, tt.errorCode, tt.message, tt.details)

			assert.Equal(t, tt.statusCode, w.Code)
			assert.Contains(t, w.Body.String(), tt.message)
			assert.Contains(t, w.Body.String(), tt.errorCode)

			if tt.details != nil {
				assert.Contains(t, w.Body.String(), "details")
			}
		})
	}
}

func TestRespondWithSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)

	data := map[string]interface{}{
		"id":   "123",
		"name": "Test User",
	}

	RespondWithSuccess(c, http.StatusOK, data)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "123")
	assert.Contains(t, w.Body.String(), "Test User")
}

func TestGetRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name     string
		setupCtx func(*gin.Context)
		expected string
	}{
		{
			name: "From context",
			setupCtx: func(c *gin.Context) {
				c.Set("request_id", "ctx-123")
			},
			expected: "ctx-123",
		},
		{
			name: "From X-Request-ID header",
			setupCtx: func(c *gin.Context) {
				c.Request.Header.Set("X-Request-ID", "header-456")
			},
			expected: "header-456",
		},
		{
			name: "From X-Correlation-ID header",
			setupCtx: func(c *gin.Context) {
				c.Request.Header.Set("X-Correlation-ID", "correlation-789")
			},
			expected: "correlation-789",
		},
		{
			name: "No request ID",
			setupCtx: func(c *gin.Context) {
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/", nil)

			tt.setupCtx(c)

			result := GetRequestID(c)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResponseStructures(t *testing.T) {
	errorResp := ErrorResponse{
		Error: ErrorDetail{
			Code:    "TEST_ERROR",
			Message: "Test error message",
			Details: "Additional details",
		},
		Status:    400,
		Path:      "/test/path",
		Timestamp: "2023-01-01T00:00:00Z",
		RequestID: "req-123",
	}

	assert.Equal(t, "TEST_ERROR", errorResp.Error.Code)
	assert.Equal(t, "Test error message", errorResp.Error.Message)
	assert.Equal(t, "Additional details", errorResp.Error.Details)
	assert.Equal(t, 400, errorResp.Status)
	assert.Equal(t, "/test/path", errorResp.Path)

	successResp := SuccessResponse{
		Data:      map[string]string{"key": "value"},
		Status:    200,
		Timestamp: "2023-01-01T00:00:00Z",
		RequestID: "req-456",
	}

	assert.Equal(t, 200, successResp.Status)
	assert.Equal(t, "req-456", successResp.RequestID)
	assert.NotNil(t, successResp.Data)
}

func TestFormatValidationErrors(t *testing.T) {
	type TestStruct struct {
		Email    string `validate:"required,email"`
		Username string `validate:"required,min=3,max=50"`
		Age      int    `validate:"min=18"`
	}

	validate := validator.New()

	tests := []struct {
		name     string
		data     TestStruct
		hasError bool
	}{
		{
			name: "Valid data",
			data: TestStruct{
				Email:    "test@example.com",
				Username: "testuser",
				Age:      25,
			},
			hasError: false,
		},
		{
			name: "Invalid email and short username",
			data: TestStruct{
				Email:    "invalid-email",
				Username: "ab",
				Age:      17,
			},
			hasError: true,
		},
		{
			name: "Missing required fields",
			data: TestStruct{
				Age: 25,
			},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate.Struct(tt.data)

			if tt.hasError {
				assert.Error(t, err)
				formatted := FormatValidationErrors(err)
				assert.NotEmpty(t, formatted)

				for _, message := range formatted {
					assert.NotEmpty(t, message)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFormatValidationErrors_NonValidationError(t *testing.T) {
	regularError := assert.AnError

	formatted := FormatValidationErrors(regularError)
	assert.NotEmpty(t, formatted)
	assert.Equal(t, "assert.AnError general error for testing", formatted[0])
}

func TestErrorCodes(t *testing.T) {
	errorCodes := []string{
		ErrCodeBadRequest,
		ErrCodeUnauthorized,
		ErrCodeForbidden,
		ErrCodeNotFound,
		ErrCodeConflict,
		ErrCodeValidationFailed,
		ErrCodeInternalError,
		ErrCodeServiceUnavailable,
		ErrCodeRateLimited,
		ErrCodeInvalidToken,
		ErrCodeExpiredToken,
		ErrCodeInsufficientPermissions,
		ErrCodeTenantRequired,
		ErrCodeResourceNotFound,
	}

	for _, code := range errorCodes {
		assert.NotEmpty(t, code, "Error code should not be empty")
	}
}

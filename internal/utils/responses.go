package utils

import (
	"time"

	"github.com/gin-gonic/gin"
)

// ErrorResponse represents an API error response
// swagger:model
type ErrorResponse struct {
	Error     ErrorDetail `json:"error"`
	Status    int         `json:"status" example:"400"`
	Path      string      `json:"path" example:"/api/v1/environments"`
	Timestamp string      `json:"timestamp" example:"2024-01-01T12:00:00Z"`
	RequestID string      `json:"request_id,omitempty" example:"req-123456789"`
}

// ErrorDetail represents detailed error information
// swagger:model
type ErrorDetail struct {
	Code    string      `json:"code" example:"BAD_REQUEST"`
	Message string      `json:"message" example:"Invalid request body"`
	Details interface{} `json:"details,omitempty"`
}

type SuccessResponse struct {
	Data      interface{} `json:"data"`
	Status    int         `json:"status"`
	Timestamp string      `json:"timestamp"`
	RequestID string      `json:"request_id,omitempty"`
}

func RespondWithError(c *gin.Context, statusCode int, errorCode, message string, details interface{}) {
	response := ErrorResponse{
		Error: ErrorDetail{
			Code:    errorCode,
			Message: message,
			Details: details,
		},
		Status:    statusCode,
		Path:      c.Request.URL.Path,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: GetRequestID(c),
	}

	c.JSON(statusCode, response)
}

func RespondWithSuccess(c *gin.Context, statusCode int, data interface{}) {
	response := SuccessResponse{
		Data:      data,
		Status:    statusCode,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: GetRequestID(c),
	}

	c.JSON(statusCode, response)
}

func GetRequestID(c *gin.Context) string {
	if requestID, exists := c.Get("request_id"); exists {
		return requestID.(string)
	}

	if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
		return requestID
	}

	if requestID := c.GetHeader("X-Correlation-ID"); requestID != "" {
		return requestID
	}

	return ""
}

const (
	ErrCodeValidationFailed        = "VALIDATION_FAILED"
	ErrCodeUnauthorized            = "UNAUTHORIZED"
	ErrCodeForbidden               = "FORBIDDEN"
	ErrCodeNotFound                = "NOT_FOUND"
	ErrCodeConflict                = "CONFLICT"
	ErrCodeInternalError           = "INTERNAL_ERROR"
	ErrCodeBadRequest              = "BAD_REQUEST"
	ErrCodeServiceUnavailable      = "SERVICE_UNAVAILABLE"
	ErrCodeRateLimited             = "RATE_LIMITED"
	ErrCodeInvalidToken            = "INVALID_TOKEN"
	ErrCodeExpiredToken            = "EXPIRED_TOKEN"
	ErrCodeInsufficientPermissions = "INSUFFICIENT_PERMISSIONS"
	ErrCodeTenantRequired          = "TENANT_REQUIRED"
	ErrCodeResourceNotFound        = "RESOURCE_NOT_FOUND"
)

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type ErrorCode string

const (
	ErrorCodeBadRequest         ErrorCode = "BAD_REQUEST"
	ErrorCodeUnauthorized       ErrorCode = "UNAUTHORIZED"
	ErrorCodeForbidden          ErrorCode = "FORBIDDEN"
	ErrorCodeNotFound           ErrorCode = "NOT_FOUND"
	ErrorCodeConflict           ErrorCode = "CONFLICT"
	ErrorCodeValidationFailed   ErrorCode = "VALIDATION_FAILED"
	ErrorCodeInternalError      ErrorCode = "INTERNAL_ERROR"
	ErrorCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	ErrorCodeTooManyRequests    ErrorCode = "TOO_MANY_REQUESTS"
	ErrorCodeInvalidTenant      ErrorCode = "INVALID_TENANT_CONTEXT"
	ErrorCodeListFailed         ErrorCode = "LIST_FAILED"
	ErrorCodeCreateFailed       ErrorCode = "CREATE_FAILED"
	ErrorCodeUpdateFailed       ErrorCode = "UPDATE_FAILED"
	ErrorCodeDeleteFailed       ErrorCode = "DELETE_FAILED"
	ErrorCodeGetFailed          ErrorCode = "GET_FAILED"
)

type ErrorResponse struct {
	Error string    `json:"error"`
	Code  ErrorCode `json:"code"`
}

type SuccessResponse struct {
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Page       int         `json:"page"`
	PageSize   int         `json:"page_size"`
	Total      int64       `json:"total"`
	TotalPages int         `json:"total_pages"`
}

func RespondWithError(c *gin.Context, statusCode int, message string, code ErrorCode, logger *zap.Logger, logFields ...zap.Field) {
	response := ErrorResponse{
		Error: message,
		Code:  code,
	}

	if logger != nil {
		fields := append([]zap.Field{
			zap.Int("status_code", statusCode),
			zap.String("error_code", string(code)),
			zap.String("error_message", message),
		}, logFields...)

		if statusCode >= 500 {
			logger.Error("Internal server error", fields...)
		} else {
			logger.Warn("Client error", fields...)
		}
	}

	c.JSON(statusCode, response)
}

func RespondWithSuccess(c *gin.Context, statusCode int, data interface{}) {
	if data == nil {
		c.Status(statusCode)
		return
	}

	c.JSON(statusCode, data)
}

func RespondWithMessage(c *gin.Context, statusCode int, message string, data interface{}) {
	response := SuccessResponse{
		Message: message,
		Data:    data,
	}
	c.JSON(statusCode, response)
}

func RespondWithPagination(c *gin.Context, data interface{}, page, pageSize int, total int64) {
	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))

	response := PaginatedResponse{
		Data:       data,
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
	}

	c.JSON(http.StatusOK, response)
}

func RespondBadRequest(c *gin.Context, message string, logger *zap.Logger, logFields ...zap.Field) {
	RespondWithError(c, http.StatusBadRequest, message, ErrorCodeBadRequest, logger, logFields...)
}

func RespondUnauthorized(c *gin.Context, message string, logger *zap.Logger, logFields ...zap.Field) {
	RespondWithError(c, http.StatusUnauthorized, message, ErrorCodeUnauthorized, logger, logFields...)
}

func RespondForbidden(c *gin.Context, message string, logger *zap.Logger, logFields ...zap.Field) {
	RespondWithError(c, http.StatusForbidden, message, ErrorCodeForbidden, logger, logFields...)
}

func RespondNotFound(c *gin.Context, message string, logger *zap.Logger, logFields ...zap.Field) {
	RespondWithError(c, http.StatusNotFound, message, ErrorCodeNotFound, logger, logFields...)
}

func RespondConflict(c *gin.Context, message string, logger *zap.Logger, logFields ...zap.Field) {
	RespondWithError(c, http.StatusConflict, message, ErrorCodeConflict, logger, logFields...)
}

func RespondValidationError(c *gin.Context, message string, logger *zap.Logger, logFields ...zap.Field) {
	RespondWithError(c, http.StatusBadRequest, message, ErrorCodeValidationFailed, logger, logFields...)
}

func RespondInternalError(c *gin.Context, message string, logger *zap.Logger, logFields ...zap.Field) {
	RespondWithError(c, http.StatusInternalServerError, message, ErrorCodeInternalError, logger, logFields...)
}

func RespondServiceUnavailable(c *gin.Context, message string, logger *zap.Logger, logFields ...zap.Field) {
	RespondWithError(c, http.StatusServiceUnavailable, message, ErrorCodeServiceUnavailable, logger, logFields...)
}

func RespondTooManyRequests(c *gin.Context, message string, logger *zap.Logger, logFields ...zap.Field) {
	RespondWithError(c, http.StatusTooManyRequests, message, ErrorCodeTooManyRequests, logger, logFields...)
}

func RespondInvalidTenant(c *gin.Context, logger *zap.Logger, logFields ...zap.Field) {
	RespondWithError(c, http.StatusBadRequest, "Invalid tenant context", ErrorCodeInvalidTenant, logger, logFields...)
}

func RespondListFailed(c *gin.Context, resource string, err error, logger *zap.Logger) {
	message := "Failed to list " + resource
	RespondWithError(c, http.StatusInternalServerError, message, ErrorCodeListFailed, logger, zap.Error(err))
}

func RespondCreateFailed(c *gin.Context, resource string, err error, logger *zap.Logger) {
	message := "Failed to create " + resource
	RespondWithError(c, http.StatusInternalServerError, message, ErrorCodeCreateFailed, logger, zap.Error(err))
}

func RespondUpdateFailed(c *gin.Context, resource string, err error, logger *zap.Logger) {
	message := "Failed to update " + resource
	RespondWithError(c, http.StatusInternalServerError, message, ErrorCodeUpdateFailed, logger, zap.Error(err))
}

func RespondDeleteFailed(c *gin.Context, resource string, err error, logger *zap.Logger) {
	message := "Failed to delete " + resource
	RespondWithError(c, http.StatusInternalServerError, message, ErrorCodeDeleteFailed, logger, zap.Error(err))
}

func RespondGetFailed(c *gin.Context, resource string, err error, logger *zap.Logger) {
	message := "Failed to get " + resource
	RespondWithError(c, http.StatusInternalServerError, message, ErrorCodeGetFailed, logger, zap.Error(err))
}

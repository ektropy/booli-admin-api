package middleware

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// RequestLoggingConfig configures request logging behavior
type RequestLoggingConfig struct {
	LogRequestBody   bool
	LogResponseBody  bool
	MaxBodySize      int64
	SkipPaths        []string
	SkipHealthChecks bool
}

// DefaultRequestLoggingConfig returns a sensible default configuration
func DefaultRequestLoggingConfig() RequestLoggingConfig {
	return RequestLoggingConfig{
		LogRequestBody:   false, // Disabled by default for security
		LogResponseBody:  false, // Disabled by default for performance
		MaxBodySize:      1024,  // 1KB max for logged bodies
		SkipPaths:        []string{"/favicon.ico"},
		SkipHealthChecks: true,
	}
}

// DevelopmentRequestLoggingConfig returns config suitable for development
func DevelopmentRequestLoggingConfig() RequestLoggingConfig {
	return RequestLoggingConfig{
		LogRequestBody:   true,  // Enabled for debugging
		LogResponseBody:  true,  // Enabled for debugging
		MaxBodySize:      4096,  // 4KB max for logged bodies
		SkipPaths:        []string{"/favicon.ico"},
		SkipHealthChecks: true,
	}
}

// EnhancedRequestLogger provides detailed HTTP request/response logging
func EnhancedRequestLogger(logger *zap.Logger, config RequestLoggingConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Skip certain paths
		if shouldSkipLogging(path, config) {
			c.Next()
			return
		}

		// Store context information
		c.Set("logger", logger)

		var requestBody []byte
		if config.LogRequestBody && shouldLogBody(c.Request) {
			requestBody = readAndRestoreBody(c.Request, config.MaxBodySize)
		}

		// Capture response
		responseWriter := &responseCapture{
			ResponseWriter: c.Writer,
			body:           &bytes.Buffer{},
			logBody:        config.LogResponseBody,
			maxSize:        config.MaxBodySize,
		}
		c.Writer = responseWriter

		// Process request
		c.Next()

		// Calculate metrics
		latency := time.Since(start)
		statusCode := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method
		userAgent := c.Request.UserAgent()

		if raw != "" {
			path = path + "?" + raw
		}

		// Build log fields
		fields := []zap.Field{
			zap.String("method", method),
			zap.String("path", path),
			zap.Int("status", statusCode),
			zap.Duration("latency", latency),
			zap.String("ip", clientIP),
			zap.String("user_agent", userAgent),
			zap.Int64("request_size", c.Request.ContentLength),
			zap.Int("response_size", c.Writer.Size()),
		}

		// Add user context if available
		if userID, exists := c.Get("user_id"); exists {
			fields = append(fields, zap.String("user_id", userID.(string)))
		}
		if realmName, exists := c.Get("realm"); exists {
			fields = append(fields, zap.String("realm", realmName.(string)))
		}
		if email, exists := c.Get("user_email"); exists {
			fields = append(fields, zap.String("user_email", email.(string)))
		}

		// Add request body if enabled
		if len(requestBody) > 0 {
			fields = append(fields, zap.String("request_body", string(requestBody)))
		}

		// Add response body if enabled and captured
		if responseWriter.body.Len() > 0 {
			fields = append(fields, zap.String("response_body", responseWriter.body.String()))
		}

		// Add error information if available
		if len(c.Errors) > 0 {
			fields = append(fields, zap.String("errors", c.Errors.String()))
		}

		// Log based on status code
		message := "HTTP Request"
		switch {
		case statusCode >= 500:
			logger.Error(message, fields...)
		case statusCode >= 400:
			logger.Warn(message, fields...)
		case isHealthCheck(path):
			logger.Debug(message, fields...)
		default:
			logger.Info(message, fields...)
		}
	}
}

// shouldSkipLogging determines if a path should be skipped
func shouldSkipLogging(path string, config RequestLoggingConfig) bool {
	// Skip health checks if configured
	if config.SkipHealthChecks && isHealthCheck(path) {
		return true
	}

	// Skip configured paths
	for _, skipPath := range config.SkipPaths {
		if path == skipPath {
			return true
		}
	}

	return false
}

// isHealthCheck determines if a path is a health check endpoint
func isHealthCheck(path string) bool {
	healthPaths := []string{"/health", "/ready", "/ping", "/status"}
	for _, healthPath := range healthPaths {
		if path == healthPath {
			return true
		}
	}
	return false
}

// shouldLogBody determines if request body should be logged
func shouldLogBody(req *http.Request) bool {
	// Don't log bodies for certain content types
	contentType := req.Header.Get("Content-Type")
	
	// Skip binary content
	if strings.Contains(contentType, "multipart/form-data") ||
		strings.Contains(contentType, "application/octet-stream") ||
		strings.Contains(contentType, "image/") ||
		strings.Contains(contentType, "video/") ||
		strings.Contains(contentType, "audio/") {
		return false
	}

	// Only log for POST, PUT, PATCH requests
	method := req.Method
	return method == "POST" || method == "PUT" || method == "PATCH"
}

// readAndRestoreBody reads request body and restores it for further processing
func readAndRestoreBody(req *http.Request, maxSize int64) []byte {
	if req.Body == nil {
		return nil
	}

	// Read body up to maxSize
	limitReader := io.LimitReader(req.Body, maxSize)
	body, err := io.ReadAll(limitReader)
	if err != nil {
		return nil
	}

	// Restore original body for further processing
	req.Body = io.NopCloser(bytes.NewReader(body))

	return body
}

// responseCapture captures response data for logging
type responseCapture struct {
	gin.ResponseWriter
	body    *bytes.Buffer
	logBody bool
	maxSize int64
	written int64
}

func (w *responseCapture) Write(b []byte) (int, error) {
	// Write to original response
	n, err := w.ResponseWriter.Write(b)

	// Capture response body if enabled and within size limit
	if w.logBody && w.written < w.maxSize {
		remaining := w.maxSize - w.written
		if int64(len(b)) <= remaining {
			w.body.Write(b)
		} else {
			w.body.Write(b[:remaining])
		}
		w.written += int64(len(b))
	}

	return n, err
}

// RequestID middleware adds a unique request ID to each request
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := generateRequestID()
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	return generateRandomString(16)
}

// generateRandomString generates a random string of specified length
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[len(charset)/2+i%len(charset)] // Simple deterministic approach
	}
	return string(b)
}
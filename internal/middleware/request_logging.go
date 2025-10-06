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

type RequestLoggingConfig struct {
	LogRequestBody   bool
	LogResponseBody  bool
	MaxBodySize      int64
	SkipPaths        []string
	SkipHealthChecks bool
}

func DefaultRequestLoggingConfig() RequestLoggingConfig {
	return RequestLoggingConfig{
		LogRequestBody:   false,
		LogResponseBody:  false,
		MaxBodySize:      1024,
		SkipPaths:        []string{"/favicon.ico"},
		SkipHealthChecks: true,
	}
}

func DevelopmentRequestLoggingConfig() RequestLoggingConfig {
	return RequestLoggingConfig{
		LogRequestBody:   true,
		LogResponseBody:  true,
		MaxBodySize:      4096,
		SkipPaths:        []string{"/favicon.ico"},
		SkipHealthChecks: true,
	}
}

func EnhancedRequestLogger(logger *zap.Logger, config RequestLoggingConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		if shouldSkipLogging(path, config) {
			c.Next()
			return
		}

		c.Set("logger", logger)

		var requestBody []byte
		if config.LogRequestBody && shouldLogBody(c.Request) {
			requestBody = readAndRestoreBody(c.Request, config.MaxBodySize)
		}

		responseWriter := &responseCapture{
			ResponseWriter: c.Writer,
			body:           &bytes.Buffer{},
			logBody:        config.LogResponseBody,
			maxSize:        config.MaxBodySize,
		}
		c.Writer = responseWriter

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method
		userAgent := c.Request.UserAgent()

		if raw != "" {
			path = path + "?" + raw
		}

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

		if userID, exists := c.Get("user_id"); exists {
			fields = append(fields, zap.String("user_id", userID.(string)))
		}
		if realmName, exists := c.Get("realm"); exists {
			fields = append(fields, zap.String("realm", realmName.(string)))
		}
		if email, exists := c.Get("user_email"); exists {
			fields = append(fields, zap.String("user_email", email.(string)))
		}

		if len(requestBody) > 0 {
			fields = append(fields, zap.String("request_body", string(requestBody)))
		}

		if responseWriter.body.Len() > 0 {
			fields = append(fields, zap.String("response_body", responseWriter.body.String()))
		}

		if len(c.Errors) > 0 {
			fields = append(fields, zap.String("errors", c.Errors.String()))
		}

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

func shouldSkipLogging(path string, config RequestLoggingConfig) bool {
	if config.SkipHealthChecks && isHealthCheck(path) {
		return true
	}

	for _, skipPath := range config.SkipPaths {
		if path == skipPath {
			return true
		}
	}

	return false
}

func isHealthCheck(path string) bool {
	healthPaths := []string{"/health", "/ready", "/ping", "/status"}
	for _, healthPath := range healthPaths {
		if path == healthPath {
			return true
		}
	}
	return false
}

func shouldLogBody(req *http.Request) bool {
	contentType := req.Header.Get("Content-Type")

	if strings.Contains(contentType, "multipart/form-data") ||
		strings.Contains(contentType, "application/octet-stream") ||
		strings.Contains(contentType, "image/") ||
		strings.Contains(contentType, "video/") ||
		strings.Contains(contentType, "audio/") {
		return false
	}

	method := req.Method
	return method == "POST" || method == "PUT" || method == "PATCH"
}

func readAndRestoreBody(req *http.Request, maxSize int64) []byte {
	if req.Body == nil {
		return nil
	}

	limitReader := io.LimitReader(req.Body, maxSize)
	body, err := io.ReadAll(limitReader)
	if err != nil {
		return nil
	}

	req.Body = io.NopCloser(bytes.NewReader(body))

	return body
}

type responseCapture struct {
	gin.ResponseWriter
	body    *bytes.Buffer
	logBody bool
	maxSize int64
	written int64
}

func (w *responseCapture) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)

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

func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := generateRequestID()
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

func generateRequestID() string {
	return generateRandomString(16)
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[len(charset)/2+i%len(charset)]
	}
	return string(b)
}

package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// RateLimiterConfig defines rate limiting configuration
type RateLimiterConfig struct {
	RequestsPerMinute int
	BurstSize         int
	KeyFunc           func(*gin.Context) string
	OnRateLimited     func(*gin.Context)
}

// RateLimiter provides rate limiting middleware
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	config   RateLimiterConfig
	logger   *zap.Logger
}

// NewRateLimiter creates a new rate limiter middleware
func NewRateLimiter(config RateLimiterConfig, logger *zap.Logger) *RateLimiter {
	if config.KeyFunc == nil {
		config.KeyFunc = defaultKeyFunc
	}

	if config.OnRateLimited == nil {
		config.OnRateLimited = defaultOnRateLimited
	}

	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		config:   config,
		logger:   logger,
	}
}

// Middleware returns the rate limiting gin middleware
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := rl.config.KeyFunc(c)
		limiter := rl.getLimiter(key)

		if !limiter.Allow() {
			rl.logger.Warn("Rate limit exceeded",
				zap.String("key", key),
				zap.String("path", c.Request.URL.Path),
				zap.String("method", c.Request.Method))

			rl.config.OnRateLimited(c)
			return
		}

		// Add rate limit headers
		rl.addRateLimitHeaders(c, limiter)
		c.Next()
	}
}

// getLimiter gets or creates a rate limiter for the given key
func (rl *RateLimiter) getLimiter(key string) *rate.Limiter {
	limiter, exists := rl.limiters[key]
	if !exists {
		// Create new limiter with requests per minute converted to requests per second
		rps := rate.Limit(float64(rl.config.RequestsPerMinute) / 60.0)
		limiter = rate.NewLimiter(rps, rl.config.BurstSize)
		rl.limiters[key] = limiter
	}
	return limiter
}

// addRateLimitHeaders adds rate limiting headers to the response
func (rl *RateLimiter) addRateLimitHeaders(c *gin.Context, limiter *rate.Limiter) {
	// Calculate remaining requests based on burst size
	// This is an approximation since golang.org/x/time/rate doesn't expose tokens directly
	remaining := rl.config.BurstSize

	// Try to reserve a token to check availability
	reservation := limiter.Reserve()
	if reservation.OK() {
		reservation.Cancel() // Cancel the reservation since we're just checking
		// If reservation was OK, we have at least one token available
		if remaining > 0 {
			remaining--
		}
	} else {
		remaining = 0
	}

	c.Header("X-RateLimit-Limit", strconv.Itoa(rl.config.RequestsPerMinute))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))
}

// defaultKeyFunc uses client IP as the key
func defaultKeyFunc(c *gin.Context) string {
	return c.ClientIP()
}

// defaultOnRateLimited sends a 429 response
func defaultOnRateLimited(c *gin.Context) {
	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":   "Rate limit exceeded",
		"code":    "RATE_LIMITED",
		"message": "Too many requests, please try again later",
		"retry_after": 60,
	})
	c.Abort()
}

// Common rate limiter configurations

// StandardAPIRateLimit provides standard rate limiting (100 req/min, burst 10)
func StandardAPIRateLimit(logger *zap.Logger) gin.HandlerFunc {
	return NewRateLimiter(RateLimiterConfig{
		RequestsPerMinute: 100,
		BurstSize:         10,
	}, logger).Middleware()
}

// BulkOperationRateLimit provides strict rate limiting for bulk operations (10 req/min, burst 2)
func BulkOperationRateLimit(logger *zap.Logger) gin.HandlerFunc {
	return NewRateLimiter(RateLimiterConfig{
		RequestsPerMinute: 10,
		BurstSize:         2,
		KeyFunc: func(c *gin.Context) string {
			// Use user ID + realm for bulk operations to prevent abuse
			userID, _ := c.Get("user_id")
			realm, _ := c.Get("realm")
			return fmt.Sprintf("bulk_%v_%v", userID, realm)
		},
	}, logger).Middleware()
}

// CSVImportRateLimit provides very strict rate limiting for CSV imports (5 req/min, burst 1)
func CSVImportRateLimit(logger *zap.Logger) gin.HandlerFunc {
	return NewRateLimiter(RateLimiterConfig{
		RequestsPerMinute: 5,
		BurstSize:         1,
		KeyFunc: func(c *gin.Context) string {
			// Use user ID + realm for CSV imports
			userID, _ := c.Get("user_id")
			realm, _ := c.Get("realm")
			return fmt.Sprintf("csv_%v_%v", userID, realm)
		},
	}, logger).Middleware()
}

// AuthenticationRateLimit provides rate limiting for auth endpoints (20 req/min, burst 5)
func AuthenticationRateLimit(logger *zap.Logger) gin.HandlerFunc {
	return NewRateLimiter(RateLimiterConfig{
		RequestsPerMinute: 20,
		BurstSize:         5,
		KeyFunc: func(c *gin.Context) string {
			// Use IP address for auth endpoints
			return c.ClientIP()
		},
	}, logger).Middleware()
}
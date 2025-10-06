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

type RateLimiterConfig struct {
	RequestsPerMinute int
	BurstSize         int
	KeyFunc           func(*gin.Context) string
	OnRateLimited     func(*gin.Context)
}

type RateLimiter struct {
	limiters map[string]*rate.Limiter
	config   RateLimiterConfig
	logger   *zap.Logger
}

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

		rl.addRateLimitHeaders(c, limiter)
		c.Next()
	}
}

func (rl *RateLimiter) getLimiter(key string) *rate.Limiter {
	limiter, exists := rl.limiters[key]
	if !exists {
		rps := rate.Limit(float64(rl.config.RequestsPerMinute) / 60.0)
		limiter = rate.NewLimiter(rps, rl.config.BurstSize)
		rl.limiters[key] = limiter
	}
	return limiter
}

func (rl *RateLimiter) addRateLimitHeaders(c *gin.Context, limiter *rate.Limiter) {
	remaining := rl.config.BurstSize

	reservation := limiter.Reserve()
	if reservation.OK() {
		reservation.Cancel()
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

func defaultKeyFunc(c *gin.Context) string {
	return c.ClientIP()
}

func defaultOnRateLimited(c *gin.Context) {
	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":       "Rate limit exceeded",
		"code":        "RATE_LIMITED",
		"message":     "Too many requests, please try again later",
		"retry_after": 60,
	})
	c.Abort()
}

func StandardAPIRateLimit(logger *zap.Logger) gin.HandlerFunc {
	return NewRateLimiter(RateLimiterConfig{
		RequestsPerMinute: 100,
		BurstSize:         10,
	}, logger).Middleware()
}

func BulkOperationRateLimit(logger *zap.Logger) gin.HandlerFunc {
	return NewRateLimiter(RateLimiterConfig{
		RequestsPerMinute: 10,
		BurstSize:         2,
		KeyFunc: func(c *gin.Context) string {
			userID, _ := c.Get("user_id")
			realm, _ := c.Get("realm")
			return fmt.Sprintf("bulk_%v_%v", userID, realm)
		},
	}, logger).Middleware()
}

func CSVImportRateLimit(logger *zap.Logger) gin.HandlerFunc {
	return NewRateLimiter(RateLimiterConfig{
		RequestsPerMinute: 5,
		BurstSize:         1,
		KeyFunc: func(c *gin.Context) string {
			userID, _ := c.Get("user_id")
			realm, _ := c.Get("realm")
			return fmt.Sprintf("csv_%v_%v", userID, realm)
		},
	}, logger).Middleware()
}

func AuthenticationRateLimit(logger *zap.Logger) gin.HandlerFunc {
	return NewRateLimiter(RateLimiterConfig{
		RequestsPerMinute: 20,
		BurstSize:         5,
		KeyFunc: func(c *gin.Context) string {
			return c.ClientIP()
		},
	}, logger).Middleware()
}

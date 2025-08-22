package middleware

import (
	"github.com/gin-gonic/gin"
)

func EnhancedSecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		
		c.Header("X-Content-Type-Options", "nosniff")
		
		c.Header("X-XSS-Protection", "1; mode=block")
		
		c.Header("X-Frame-Options", "DENY")
		
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; media-src 'none'; object-src 'none'; child-src 'none'; frame-src 'none'; worker-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'self';")
		
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()")
		
		c.Header("Server", "")
		c.Header("X-Powered-By", "")
		
		c.Next()
	}
}

func CORSHeaders(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		var allowedOrigin string
		for _, allowed := range allowedOrigins {
			if origin == allowed || allowed == "*" {
				allowedOrigin = origin
				break
			}
		}
		
		if allowedOrigin != "" {
			c.Header("Access-Control-Allow-Origin", allowedOrigin)
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With")
		c.Header("Access-Control-Max-Age", "86400") // 24 hours
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		
		c.Next()
	}
}

// BulkOperationHeaders adds specific security headers for bulk operations
func BulkOperationHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Request-Type", "bulk-operation")
		
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		
		c.Header("X-Process-Time-Limit", "300")
		
		c.Next()
	}
}
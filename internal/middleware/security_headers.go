package middleware

import (
	"github.com/gin-gonic/gin"
)

// EnhancedSecurityHeaders adds comprehensive security headers to all responses
func EnhancedSecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// HSTS (HTTP Strict Transport Security)
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		
		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")
		
		// XSS Protection
		c.Header("X-XSS-Protection", "1; mode=block")
		
		// Prevent page from being displayed in iframe (clickjacking protection)
		c.Header("X-Frame-Options", "DENY")
		
		// Content Security Policy
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; media-src 'none'; object-src 'none'; child-src 'none'; frame-src 'none'; worker-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'self';")
		
		// Referrer Policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		
		// Permissions Policy (formerly Feature Policy)
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()")
		
		// Remove server information
		c.Header("Server", "")
		c.Header("X-Powered-By", "")
		
		c.Next()
	}
}

// CORSHeaders configures CORS headers for API access
func CORSHeaders(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		// Check if origin is allowed
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
		
		// Handle preflight requests
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
		// Additional security for bulk operations
		c.Header("X-Request-Type", "bulk-operation")
		
		// Prevent caching of bulk operation responses
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		
		// Add timing information for monitoring
		c.Header("X-Process-Time-Limit", "300") // 5 minutes max
		
		c.Next()
	}
}
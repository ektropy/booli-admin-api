package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSuperAdminRequired(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		userRoles      []string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "MSP admin role present",
			userRoles:      []string{"msp-admin", "admin"},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"success"}`,
		},
		{
			name:           "MSP admin role with other roles",
			userRoles:      []string{"default-roles-msp-platform", "offline_access", "msp-admin", "admin", "uma_authorization"},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"success"}`,
		},
		{
			name:           "Only admin role without msp-admin",
			userRoles:      []string{"admin", "user"},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "",
		},
		{
			name:           "No msp-admin role",
			userRoles:      []string{"user", "basic"},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "",
		},
		{
			name:           "Empty roles",
			userRoles:      []string{},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "",
		},
		{
			name:           "No roles context",
			userRoles:      nil,
			expectedStatus: http.StatusForbidden,
			expectedBody:   `{"code":"ACCESS_DENIED","error":"Access denied"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()

			router.GET("/test", func(c *gin.Context) {
				if tt.userRoles != nil {
					c.Set("user_roles", tt.userRoles)
				}
				c.Next()
			}, SuperAdminRequired(), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedBody != "" {
				assert.JSONEq(t, tt.expectedBody, w.Body.String())
			} else if tt.expectedStatus == http.StatusForbidden {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)

				assert.Equal(t, float64(403), response["status"])
				assert.Equal(t, "/test", response["path"])
				assert.Contains(t, response, "timestamp")

				errorDetail, ok := response["error"].(map[string]interface{})
				assert.True(t, ok)
				assert.Equal(t, "INSUFFICIENT_PERMISSIONS", errorDetail["code"])
				assert.Equal(t, "MSP admin access required", errorDetail["message"])
				assert.Equal(t, "User does not have MSP admin role", errorDetail["details"])
			}
		})
	}
}

func TestAdminRequired(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		userRoles      []string
		expectedStatus int
	}{
		{
			name:           "Admin role present",
			userRoles:      []string{"tenant-admin", "user"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "No admin role",
			userRoles:      []string{"user", "basic"},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()

			router.GET("/test", func(c *gin.Context) {
				c.Set("user_roles", tt.userRoles)
				c.Next()
			}, TenantAdminRequired(), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestMSPRequired(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		userRoles      []string
		expectedStatus int
	}{
		{
			name:           "MSP admin role",
			userRoles:      []string{"msp-admin"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "MSP power role",
			userRoles:      []string{"msp-power"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "MSP basic role",
			userRoles:      []string{"msp-basic"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "No MSP roles",
			userRoles:      []string{"admin", "user"},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()

			router.GET("/test", func(c *gin.Context) {
				c.Set("user_roles", tt.userRoles)
				c.Next()
			}, MSPRequired(), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestRoleRequired(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		requiredRoles  []string
		userRoles      []string
		expectedStatus int
	}{
		{
			name:           "Single required role present",
			requiredRoles:  []string{"admin"},
			userRoles:      []string{"admin", "user"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Multiple required roles - one present",
			requiredRoles:  []string{"admin", "superuser"},
			userRoles:      []string{"admin", "user"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Multiple required roles - different one present",
			requiredRoles:  []string{"admin", "superuser"},
			userRoles:      []string{"superuser", "user"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Required role not present",
			requiredRoles:  []string{"admin"},
			userRoles:      []string{"user", "basic"},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "No required roles match",
			requiredRoles:  []string{"admin", "superuser"},
			userRoles:      []string{"user", "basic"},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()

			router.GET("/test", func(c *gin.Context) {
				c.Set("user_roles", tt.userRoles)
				c.Next()
			}, RoleRequired(tt.requiredRoles...), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestContainsRole(t *testing.T) {
	tests := []struct {
		name       string
		userRoles  []string
		targetRole string
		expected   bool
	}{
		{
			name:       "Role present",
			userRoles:  []string{"admin", "user", "msp-admin"},
			targetRole: "msp-admin",
			expected:   true,
		},
		{
			name:       "Role not present",
			userRoles:  []string{"admin", "user"},
			targetRole: "msp-admin",
			expected:   false,
		},
		{
			name:       "Empty roles",
			userRoles:  []string{},
			targetRole: "admin",
			expected:   false,
		},
		{
			name:       "Exact match",
			userRoles:  []string{"exact-match"},
			targetRole: "exact-match",
			expected:   true,
		},
		{
			name:       "Case sensitive",
			userRoles:  []string{"Admin"},
			targetRole: "admin",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsRole(tt.userRoles, tt.targetRole)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name          string
		authHeader    string
		expectedToken string
		expectedError bool
	}{
		{
			name:          "Valid Bearer token",
			authHeader:    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedError: false,
		},
		{
			name:          "Valid bearer token (lowercase)",
			authHeader:    "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedError: false,
		},
		{
			name:          "Missing Authorization header",
			authHeader:    "",
			expectedToken: "",
			expectedError: true,
		},
		{
			name:          "Invalid format - no space",
			authHeader:    "BearereyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken: "",
			expectedError: true,
		},
		{
			name:          "Invalid format - wrong scheme",
			authHeader:    "Basic eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken: "",
			expectedError: true,
		},
		{
			name:          "Invalid format - too many parts",
			authHeader:    "Bearer token extra",
			expectedToken: "",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			c.Request = req

			token, err := extractToken(c)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedToken, token)
			}
		})
	}
}

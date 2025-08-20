package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BulkImportIntegrationTest tests the complete bulk import workflow
type BulkImportIntegrationTest struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewBulkImportIntegrationTest creates a new integration test instance
func NewBulkImportIntegrationTest(baseURL, token string) *BulkImportIntegrationTest {
	return &BulkImportIntegrationTest{
		baseURL: baseURL,
		token:   token,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// TestBulkImportWorkflow tests the complete bulk import workflow
func TestBulkImportWorkflow(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("RUN_INTEGRATION_TESTS") != "true" {
		t.Skip("Skipping integration test. Set RUN_INTEGRATION_TESTS=true to run.")
	}

	baseURL := os.Getenv("API_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8081"
	}

	token := os.Getenv("TEST_TOKEN")
	if token == "" {
		t.Skip("Integration test requires authentication setup")
	}

	test := NewBulkImportIntegrationTest(baseURL, token)

	t.Run("TestJSONBulkCreate", test.TestJSONBulkCreate)
	t.Run("TestCSVImport", test.TestCSVImport)
	t.Run("TestCSVImportWithErrors", test.TestCSVImportWithErrors)
	t.Run("TestRateLimiting", test.TestRateLimiting)
}

// TestJSONBulkCreate tests bulk user creation via JSON
func (test *BulkImportIntegrationTest) TestJSONBulkCreate(t *testing.T) {
	// Prepare test data
	users := []map[string]interface{}{
		{
			"email":        "bulk1@test.com",
			"first_name":   "Bulk",
			"last_name":    "User1",
			"username":     "bulk.user1",
			"password":     "SecurePass123!",
			"enabled":      true,
			"default_role": "tenant-user",
		},
		{
			"email":        "bulk2@test.com",
			"first_name":   "Bulk",
			"last_name":    "User2",
			"username":     "bulk.user2",
			"password":     "SecurePass456!",
			"enabled":      true,
			"default_role": "tenant-admin",
		},
	}

	requestBody := map[string]interface{}{
		"users": users,
	}

	resp, err := test.makeJSONRequest("POST", "/api/v1/users/bulk-create", requestBody)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, float64(2), result["total_processed"])
	assert.Equal(t, float64(2), result["success_count"])
	assert.Equal(t, float64(0), result["failure_count"])

	successful, ok := result["successful"].([]interface{})
	require.True(t, ok)
	assert.Len(t, successful, 2)

	// Cleanup - delete created users
	for _, user := range successful {
		userMap := user.(map[string]interface{})
		userID := userMap["id"].(string)
		test.cleanupUser(userID)
	}
}

// TestCSVImport tests bulk user creation via CSV file upload
func (test *BulkImportIntegrationTest) TestCSVImport(t *testing.T) {
	csvContent := `email,first_name,last_name,username,password,role,enabled
csv1@test.com,CSV,User1,csv.user1,SecurePass123!,tenant-user,true
csv2@test.com,CSV,User2,csv.user2,SecurePass456!,tenant-admin,true`

	resp, err := test.makeCSVRequest("/api/v1/users/import-csv", "test-users.csv", csvContent)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, float64(2), result["total_processed"])
	assert.Equal(t, float64(2), result["success_count"])
	assert.Equal(t, float64(0), result["error_count"])

	successful, ok := result["successful_users"].([]interface{})
	require.True(t, ok)
	assert.Len(t, successful, 2)

	// Cleanup - delete created users
	for _, user := range successful {
		userMap := user.(map[string]interface{})
		userID := userMap["id"].(string)
		test.cleanupUser(userID)
	}
}

// TestCSVImportWithErrors tests CSV import error handling
func (test *BulkImportIntegrationTest) TestCSVImportWithErrors(t *testing.T) {
	// Create CSV content with errors
	csvContent := `email,first_name,last_name,username,password,role,enabled
valid@test.com,Valid,User,valid.user,SecurePass123!,tenant-user,true
invalid-email,Invalid,Email,invalid.email,SecurePass456!,tenant-user,true
,Missing,Email,missing.email,SecurePass789!,tenant-user,true`

	resp, err := test.makeCSVRequest("/api/v1/users/import-csv", "error-users.csv", csvContent)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, float64(3), result["total_processed"])
	assert.Greater(t, result["error_count"], float64(0))

	parseErrors, hasParseErrors := result["parse_errors"].([]interface{})
	failedUsers, hasFailedUsers := result["failed_users"].([]interface{})
	
	// Should have either parse errors or failed users
	assert.True(t, (hasParseErrors && len(parseErrors) > 0) || (hasFailedUsers && len(failedUsers) > 0))

	// Cleanup any successfully created users
	if successful, ok := result["successful_users"].([]interface{}); ok {
		for _, user := range successful {
			userMap := user.(map[string]interface{})
			userID := userMap["id"].(string)
			test.cleanupUser(userID)
		}
	}
}

// TestRateLimiting tests rate limiting for bulk operations
func (test *BulkImportIntegrationTest) TestRateLimiting(t *testing.T) {
	// This test is more complex and may require multiple API calls
	// to trigger rate limiting. For now, we'll test that the headers are present.
	
	users := []map[string]interface{}{
		{
			"email":        "ratelimit@test.com",
			"first_name":   "Rate",
			"last_name":    "Limit",
			"username":     "rate.limit",
			"password":     "SecurePass123!",
			"enabled":      true,
			"default_role": "tenant-user",
		},
	}

	requestBody := map[string]interface{}{
		"users": users,
	}

	resp, err := test.makeJSONRequest("POST", "/api/v1/users/bulk-create", requestBody)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.NotEmpty(t, resp.Header.Get("X-RateLimit-Limit"))
	assert.NotEmpty(t, resp.Header.Get("X-RateLimit-Remaining"))
	assert.NotEmpty(t, resp.Header.Get("X-RateLimit-Reset"))

	assert.Equal(t, "bulk-operation", resp.Header.Get("X-Request-Type"))
	assert.Equal(t, "no-cache, no-store, must-revalidate", resp.Header.Get("Cache-Control"))

	if resp.StatusCode == http.StatusCreated {
		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		if successful, ok := result["successful"].([]interface{}); ok {
			for _, user := range successful {
				userMap := user.(map[string]interface{})
				userID := userMap["id"].(string)
				test.cleanupUser(userID)
			}
		}
	}
}

// makeJSONRequest makes an HTTP request with JSON body
func (test *BulkImportIntegrationTest) makeJSONRequest(method, path string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequestWithContext(context.Background(), method, test.baseURL+path, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+test.token)
	req.Header.Set("Content-Type", "application/json")

	return test.client.Do(req)
}

// makeCSVRequest makes an HTTP request with CSV file upload
func (test *BulkImportIntegrationTest) makeCSVRequest(path, filename, csvContent string) (*http.Response, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return nil, err
	}

	_, err = part.Write([]byte(csvContent))
	if err != nil {
		return nil, err
	}

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", test.baseURL+path, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+test.token)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	return test.client.Do(req)
}

// cleanupUser deletes a user (cleanup helper)
func (test *BulkImportIntegrationTest) cleanupUser(userID string) {
	req, err := http.NewRequestWithContext(
		context.Background(),
		"DELETE",
		fmt.Sprintf("%s/api/v1/users/%s", test.baseURL, userID),
		nil,
	)
	if err != nil {
		return
	}

	req.Header.Set("Authorization", "Bearer "+test.token)
	
	resp, err := test.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// TestMain sets up and tears down for integration tests
func TestMain(m *testing.M) {
	// You could add setup/teardown logic here if needed
	// For example, starting a test database, setting up test data, etc.
	
	code := m.Run()
	
	// Cleanup logic could go here
	
	os.Exit(code)
}
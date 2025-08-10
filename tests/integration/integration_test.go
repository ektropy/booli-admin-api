package integration

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type IntegrationTestSuite struct {
	BaseIntegrationTestSuite
}

func (suite *IntegrationTestSuite) TestHealthEndpoint() {
	healthURL := fmt.Sprintf("http://%s:%s/health", suite.backendHost, suite.backendPort)
	resp, err := http.Get(healthURL)
	require.NoError(suite.T(), err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(suite.T(), err)

	bodyStr := string(body)
	assert.Contains(suite.T(), bodyStr, `"status":"healthy"`)
	assert.Contains(suite.T(), bodyStr, `"service":"booli-admin-api"`)
}

func (suite *IntegrationTestSuite) TestDatabaseConnectivity() {
	err := suite.db.Ping()
	require.NoError(suite.T(), err)

	var count int
	err = suite.db.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'").Scan(&count)
	require.NoError(suite.T(), err)
	assert.Greater(suite.T(), count, 0)
}

func (suite *IntegrationTestSuite) TestKeycloakConnectivity() {
	url := fmt.Sprintf("http://%s:%s/health/ready", suite.keycloakHost, suite.keycloakMgmtPort)
	resp, err := http.Get(url)
	require.NoError(suite.T(), err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	token := suite.AuthenticateUser("master", "admin-cli", "", suite.Config.KeycloakAdminUser, suite.Config.KeycloakAdminPassword)
	assert.NotEmpty(suite.T(), token)
}

func (suite *IntegrationTestSuite) TestValkeyConnectivity() {

	resp, err := http.Get(suite.GetHealthURL())
	require.NoError(suite.T(), err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
}

func (suite *IntegrationTestSuite) TestAuthenticationFlow() {
	resp, err := suite.MakeRequest("GET", "/admin/tenants", nil, nil)
	require.NoError(suite.T(), err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(suite.T(), http.StatusUnauthorized, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(suite.T(), err)

	bodyStr := string(body)
	assert.Contains(suite.T(), bodyStr, `"error":"Authentication required"`)
}

func (suite *IntegrationTestSuite) TestContainerOrchestration() {

	containers := map[string]testcontainers.Container{
		"PostgreSQL": suite.postgresContainer,
		"Valkey":     suite.valkeyContainer,
		"Keycloak":   suite.keycloakContainer,
	}

	for name, container := range containers {
		require.NotNil(suite.T(), container, "Container %s should not be nil", name)

		state, err := container.State(suite.ctx)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), state.Running, "Container %s should be running", name)

	}

	require.NotNil(suite.T(), suite.backendProcess, "Backend process should not be nil")
}

func (suite *IntegrationTestSuite) TestEndToEndWorkflow() {

	resp, err := http.Get(suite.GetHealthURL())
	require.NoError(suite.T(), err)
	_ = resp.Body.Close()
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	resp, err = suite.MakeRequest("GET", "/admin/tenants", nil, nil)
	require.NoError(suite.T(), err)
	_ = resp.Body.Close()
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.StatusCode)

	token := suite.AuthenticateUser("master", "admin-cli", "", suite.Config.KeycloakAdminUser, suite.Config.KeycloakAdminPassword)
	assert.NotEmpty(suite.T(), token)

	err = suite.db.Ping()
	require.NoError(suite.T(), err)

}

func TestIntegrationSuite(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "true" {
		t.Skip("Integration tests skipped. Set RUN_INTEGRATION_TESTS=true to run.")
	}

	suite.Run(t, new(IntegrationTestSuite))
}

func TestIntegrationEnvironmentSmokeTest(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "true" {
		t.Skip("Integration tests skipped. Set RUN_INTEGRATION_TESTS=true to run.")
	}

	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:15-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "test",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(30 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	defer container.Terminate(ctx)

	host, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)

	dsn := fmt.Sprintf("postgres://test:test@%s:%s/test?sslmode=disable", host, port.Port())
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer db.Close()

	err = db.Ping()
	require.NoError(t, err)
}

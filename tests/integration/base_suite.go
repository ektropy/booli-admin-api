package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/booli/booli-admin-api/internal/config"
	"github.com/booli/booli-admin-api/internal/initialization"
	"github.com/booli/booli-admin-api/internal/keycloak"
	testconfig "github.com/booli/booli-admin-api/tests/config"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap/zaptest"
)

type BaseIntegrationTestSuite struct {
	suite.Suite

	Config *testconfig.TestConfig

	postgresContainer testcontainers.Container
	valkeyContainer   testcontainers.Container
	keycloakContainer testcontainers.Container
	backendProcess    *os.Process

	postgresHost     string
	postgresPort     string
	valkeyHost       string
	valkeyPort       string
	keycloakHost     string
	keycloakPort     string
	keycloakMgmtPort string
	backendHost      string
	backendPort      string

	db  *sql.DB
	ctx context.Context
}

func (suite *BaseIntegrationTestSuite) SetupSuite() {
	suite.ctx = context.Background()
	suite.Config = testconfig.GetTestConfig()

	log.Println("Setting up Integration Test Suite...")

	suite.startPostgreSQLContainer()
	suite.startValkeyContainer()
	suite.startKeycloakContainer()
	suite.initializeKeycloak()
	suite.startBackendContainer()
	suite.initializeDatabaseConnection()

	log.Println("Integration Test Suite setup completed")
}

func (suite *BaseIntegrationTestSuite) TearDownSuite() {
	log.Println("Tearing down Integration Test Suite...")

	if suite.db != nil {
		_ = suite.db.Close()
	}

	if suite.backendProcess != nil {
		if err := suite.backendProcess.Kill(); err != nil {
			log.Printf("Warning: Failed to kill backend process: %v", err)
		}
	}

	containers := []testcontainers.Container{
		suite.keycloakContainer,
		suite.valkeyContainer,
		suite.postgresContainer,
	}

	for _, container := range containers {
		if container != nil {
			if err := container.Terminate(suite.ctx); err != nil {
				log.Printf("Warning: Failed to terminate container: %v", err)
			}
		}
	}

	log.Println("Integration Test Suite teardown completed")
}

func (suite *BaseIntegrationTestSuite) getContainerIP(container testcontainers.Container) string {
	if container == nil {
		return "localhost"
	}

	networks, err := container.Networks(suite.ctx)
	if err != nil || len(networks) == 0 {
		return "localhost"
	}

	for _, network := range networks {
		inspect, err := container.Inspect(suite.ctx)
		if err != nil {
			continue
		}

		if networkSettings, ok := inspect.NetworkSettings.Networks[network]; ok {
			if networkSettings.IPAddress != "" {
				return networkSettings.IPAddress
			}
		}
	}

	return "localhost"
}

func (suite *BaseIntegrationTestSuite) startPostgreSQLContainer() {
	log.Println("Starting PostgreSQL container...")

	req := testcontainers.ContainerRequest{
		Image:        fmt.Sprintf("postgres:%s", suite.Config.PostgresVersion),
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     suite.Config.PostgresUser,
			"POSTGRES_PASSWORD": suite.Config.PostgresPassword,
			"POSTGRES_DB":       suite.Config.PostgresDB,
		},
		WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(suite.Config.StartupTimeout),
	}

	container, err := testcontainers.GenericContainer(suite.ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	suite.Require().NoError(err)

	suite.postgresContainer = container

	host, err := container.Host(suite.ctx)
	suite.Require().NoError(err)
	suite.postgresHost = host

	port, err := container.MappedPort(suite.ctx, "5432")
	suite.Require().NoError(err)
	suite.postgresPort = port.Port()

	log.Printf("PostgreSQL container started at %s:%s", suite.postgresHost, suite.postgresPort)
}

func (suite *BaseIntegrationTestSuite) startValkeyContainer() {
	log.Println("Starting Valkey container...")

	req := testcontainers.ContainerRequest{
		Image:        fmt.Sprintf("valkey/valkey:%s", suite.Config.ValkeyVersion),
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForListeningPort("6379/tcp").WithStartupTimeout(suite.Config.StartupTimeout),
	}

	container, err := testcontainers.GenericContainer(suite.ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	suite.Require().NoError(err)

	suite.valkeyContainer = container

	host, err := container.Host(suite.ctx)
	suite.Require().NoError(err)
	suite.valkeyHost = host

	port, err := container.MappedPort(suite.ctx, "6379")
	suite.Require().NoError(err)
	suite.valkeyPort = port.Port()

	log.Printf("Valkey container started at %s:%s", suite.valkeyHost, suite.valkeyPort)
}

func (suite *BaseIntegrationTestSuite) startKeycloakContainer() {
	log.Println("Starting Keycloak container...")

	req := testcontainers.ContainerRequest{
		Image:        fmt.Sprintf("quay.io/keycloak/keycloak:%s", suite.Config.KeycloakVersion),
		ExposedPorts: []string{"8080/tcp", "9000/tcp"},
		Env: map[string]string{
			"KEYCLOAK_ADMIN":          suite.Config.KeycloakAdminUser,
			"KEYCLOAK_ADMIN_PASSWORD": suite.Config.KeycloakAdminPassword,
			"KC_DB":                   "dev-mem",
			"KC_HTTP_ENABLED":         "true",
			"KC_HOSTNAME_STRICT":      "false",
			"KC_HEALTH_ENABLED":       "true",
			"KC_HTTP_MANAGEMENT_PORT": "9000",
		},
		Cmd: []string{"start-dev"},
		WaitingFor: wait.ForHTTP("/health/ready").
			WithPort("9000/tcp").
			WithStartupTimeout(suite.Config.StartupTimeout).
			WithPollInterval(suite.Config.PollInterval),
	}

	container, err := testcontainers.GenericContainer(suite.ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	suite.Require().NoError(err)

	suite.keycloakContainer = container

	host, err := container.Host(suite.ctx)
	suite.Require().NoError(err)
	suite.keycloakHost = host

	port, err := container.MappedPort(suite.ctx, "8080")
	suite.Require().NoError(err)
	suite.keycloakPort = port.Port()

	mgmtPort, err := container.MappedPort(suite.ctx, "9000")
	suite.Require().NoError(err)
	suite.keycloakMgmtPort = mgmtPort.Port()

	log.Printf("Keycloak container started at %s:%s (mgmt: %s)", suite.keycloakHost, suite.keycloakPort, suite.keycloakMgmtPort)
}

func (suite *BaseIntegrationTestSuite) initializeKeycloak() {
	log.Println("Initializing Keycloak with MSP realm and test data...")

	logger := zaptest.NewLogger(suite.T())

	adminClient := keycloak.NewAdminClient(
		fmt.Sprintf("http://%s:%s", suite.keycloakHost, suite.keycloakPort),
		suite.Config.KeycloakMasterRealm,
		"admin-cli",
		"",
		suite.Config.KeycloakAdminUser,
		suite.Config.KeycloakAdminPassword,
		logger,
	)

	cfg := &config.Config{
		Keycloak: config.KeycloakConfig{
			URL:          fmt.Sprintf("http://%s:%s", suite.keycloakHost, suite.keycloakPort),
			AdminUser:    suite.Config.KeycloakAdminUser,
			AdminPass:    suite.Config.KeycloakAdminPassword,
			MasterRealm:  suite.Config.KeycloakMasterRealm,
			MSPRealm:     suite.Config.KeycloakMSPRealm,
			ClientID:     suite.Config.KeycloakClientID,
			ClientSecret: suite.Config.KeycloakClientSecret,
			APIAudience:  suite.Config.APIAudience,
		},
	}

	keycloakInit := initialization.NewKeycloakInitializer(adminClient, nil, cfg, logger)

	setupConfig := initialization.InitializationConfig{
		Realms: []initialization.RealmConfig{{
			Name:        suite.Config.KeycloakMSPRealm,
			DisplayName: "MSP",
			Enabled:     true,
		}},
		Clients: []initialization.ClientConfig{{
			RealmName:                 suite.Config.KeycloakMSPRealm,
			ClientID:                  suite.Config.KeycloakClientID,
			Secret:                    suite.Config.KeycloakClientSecret,
			StandardFlowEnabled:       true,
			ServiceAccountsEnabled:    true,
			DirectAccessGrantsEnabled: true,
			APIAudience:               suite.Config.APIAudience,
		}},
		Roles: []initialization.RoleConfig{},
		Users: []initialization.UserConfig{},
	}

	for _, role := range suite.Config.DefaultRoles {
		setupConfig.Roles = append(setupConfig.Roles, initialization.RoleConfig{
			RealmName:   suite.Config.KeycloakMSPRealm,
			Name:        role,
			Description: fmt.Sprintf("Role: %s", role),
		})
	}

	for _, testUser := range suite.Config.DefaultTestUsers {
		setupConfig.Users = append(setupConfig.Users, initialization.UserConfig{
			RealmName: suite.Config.KeycloakMSPRealm,
			Username:  testUser.Username,
			Password:  testUser.Password,
			Email:     testUser.Email,
			FirstName: testUser.FirstName,
			LastName:  testUser.LastName,
			Roles:     testUser.Roles,
			Enabled:   true,
		})
	}

	err := keycloakInit.Initialize(suite.ctx, &setupConfig)
	suite.Require().NoError(err)

	log.Println("Keycloak initialization completed successfully")
}

func (suite *BaseIntegrationTestSuite) startBackendContainer() {
	log.Println("Starting Booli Admin API backend...")

	suite.backendHost = suite.Config.BackendHost
	suite.backendPort = suite.Config.BackendPort

	suite.buildAndStartBackendBinary()

	log.Printf("Backend binary started at %s:%s", suite.backendHost, suite.backendPort)
}

func (suite *BaseIntegrationTestSuite) buildAndStartBackendBinary() {
	log.Println("Building backend binary for testing...")

	buildCmd := exec.Command("go", "build", "-o", "booli-admin-api-test", "./cmd/server")
	buildCmd.Dir = "../.."
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr

	err := buildCmd.Run()
	if err != nil {
		log.Printf("Failed to build backend binary: %v", err)
		suite.T().Fatalf("Failed to build backend binary: %v", err)
	}

	log.Println("Backend binary built successfully")

	env := []string{
		"BOOLI_ENVIRONMENT=test",
		"BOOLI_LOG_LEVEL=debug", // Enable debug logging
		fmt.Sprintf("BOOLI_SERVER_PORT=%s", suite.Config.BackendPort),
		fmt.Sprintf("BOOLI_DATABASE_HOST=%s", suite.postgresHost),
		fmt.Sprintf("BOOLI_DATABASE_PORT=%s", suite.postgresPort),
		fmt.Sprintf("BOOLI_DATABASE_USER=%s", suite.Config.PostgresUser),
		fmt.Sprintf("BOOLI_DATABASE_PASSWORD=%s", suite.Config.PostgresPassword),
		fmt.Sprintf("BOOLI_DATABASE_DBNAME=%s", suite.Config.PostgresDB),
		"BOOLI_DATABASE_SSLMODE=disable",
		fmt.Sprintf("BOOLI_REDIS_HOST=%s", suite.valkeyHost),
		fmt.Sprintf("BOOLI_REDIS_PORT=%s", suite.valkeyPort),
		fmt.Sprintf("BOOLI_KEYCLOAK_URL=http://%s:%s", suite.keycloakHost, suite.keycloakPort),
		fmt.Sprintf("BOOLI_KEYCLOAK_ADMIN_USER=%s", suite.Config.KeycloakAdminUser),
		fmt.Sprintf("BOOLI_KEYCLOAK_ADMIN_PASSWORD=%s", suite.Config.KeycloakAdminPassword),
		fmt.Sprintf("BOOLI_KEYCLOAK_MSP_REALM=%s", suite.Config.KeycloakMSPRealm),
		fmt.Sprintf("BOOLI_KEYCLOAK_CLIENT_ID=%s", suite.Config.KeycloakClientID),
		fmt.Sprintf("BOOLI_KEYCLOAK_CLIENT_SECRET=%s", suite.Config.KeycloakClientSecret),
		fmt.Sprintf("BOOLI_KEYCLOAK_API_AUDIENCE=%s", suite.Config.APIAudience),

		"KEYCLOAK_MSP_REALM=msp",
		"KEYCLOAK_MSP_REALM_ENABLED=true",
		"KEYCLOAK_MSP_REALM_DISPLAY_NAME=MSP Realm",
		fmt.Sprintf("KEYCLOAK_MSP_CLIENT_ID=%s", suite.Config.KeycloakClientID),
		fmt.Sprintf("KEYCLOAK_MSP_CLIENT_SECRET=%s", suite.Config.KeycloakClientSecret),
		fmt.Sprintf("KEYCLOAK_MSP_API_AUDIENCE=%s", suite.Config.APIAudience),
		"KEYCLOAK_MSP_DEFAULT_USER_USERNAME=admin",
		"KEYCLOAK_MSP_DEFAULT_USER_PASSWORD=admin123",
		"KEYCLOAK_MSP_DEFAULT_USER_ROLES=msp-admin",
	}

	startCmd := exec.CommandContext(suite.ctx, "stdbuf", "-o0", "-e0", "./booli-admin-api-test")
	startCmd.Dir = "../.."
	startCmd.Env = append(os.Environ(), env...)

	timestamp := time.Now().Format("20060102-150405")
	logDir := "logs"
	logBaseName := "backend-test-" + timestamp + ".log"
	logFileName := filepath.Join(logDir, logBaseName)
	logFile, err := os.Create(filepath.Clean(logFileName))
	if err != nil {
		log.Printf("Failed to create log file: %v", err)
		startCmd.Stdout = os.Stdout
		startCmd.Stderr = os.Stderr
	} else {
		log.Printf("Backend output will be logged to %s and console", logFileName)

		stdoutWriter := io.MultiWriter(os.Stdout, logFile)
		stderrWriter := io.MultiWriter(os.Stderr, logFile)

		startCmd.Stdout = stdoutWriter
		startCmd.Stderr = stderrWriter
	}

	err = startCmd.Start()
	if err != nil {
		log.Printf("Failed to start backend binary: %v", err)
		suite.T().Fatalf("Failed to start backend binary: %v", err)
	}

	suite.backendProcess = startCmd.Process

	log.Println("Backend binary started, waiting for health check...")

	time.Sleep(2 * time.Second)

	suite.waitForBackendHealth()
}

func (suite *BaseIntegrationTestSuite) waitForBackendHealth() {
	healthURL := fmt.Sprintf("http://%s:%s/health", suite.backendHost, suite.backendPort)

	log.Printf("Health check URL: %s", healthURL)

	for i := 0; i < 30; i++ {
		log.Printf("Health check attempt %d/30", i+1)

		if suite.backendProcess != nil {
			if process, err := os.FindProcess(suite.backendProcess.Pid); err != nil {
				log.Printf("Backend process not found: %v", err)
				break
			} else {
				log.Printf("Backend process PID %d exists", process.Pid)
			}
		}
		parsedURL, parseErr := url.Parse(healthURL)
		if parseErr != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
			log.Printf("Invalid health URL: %s", healthURL)
			break
		}
		resp, err := http.Get(parsedURL.String())
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			log.Println("Backend health check passed")
			return
		}
		if resp != nil {
			log.Printf("Health check failed: HTTP %d", resp.StatusCode)
			_ = resp.Body.Close()
		} else {
			log.Printf("Health check failed: %v", err)
		}

		time.Sleep(time.Second)
	}

	if suite.backendProcess != nil {
		if err := suite.backendProcess.Kill(); err != nil {
			log.Printf("Warning: Failed to kill backend process after health check failure: %v", err)
		}
	}

	suite.T().Fatal("Backend failed health check after 30 seconds")
}

func (suite *BaseIntegrationTestSuite) initializeDatabaseConnection() {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		suite.postgresHost, suite.postgresPort, suite.Config.PostgresUser,
		suite.Config.PostgresPassword, suite.Config.PostgresDB)

	db, err := sql.Open("postgres", dsn)
	suite.Require().NoError(err)

	suite.db = db

	err = db.Ping()
	suite.Require().NoError(err)

	log.Println("Database connection initialized")
}

func (suite *BaseIntegrationTestSuite) AuthenticateUser(realm, clientID, clientSecret, username, password string) string {
	url := fmt.Sprintf("http://%s:%s/realms/%s/protocol/openid-connect/token",
		suite.keycloakHost, suite.keycloakPort, realm)
	return suite.authenticateUserInternal(url, clientID, clientSecret, username, password)
}

func (suite *BaseIntegrationTestSuite) GetAPIURL(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasPrefix(path, suite.Config.APIBasePath) {
		path = suite.Config.APIBasePath + path
	}
	return fmt.Sprintf("http://%s:%s%s", suite.backendHost, suite.backendPort, path)
}

func (suite *BaseIntegrationTestSuite) GetHealthURL() string {
	return fmt.Sprintf("http://%s:%s/health", suite.backendHost, suite.backendPort)
}

func (suite *BaseIntegrationTestSuite) MakeRequest(method, path string, headers map[string]string, body interface{}) (*http.Response, error) {
	return suite.makeHTTPRequest(suite.GetAPIURL(path), method, headers, body)
}

func (suite *BaseIntegrationTestSuite) authenticateUserInternal(urlStr, clientID, clientSecret, username, password string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		log.Printf("Invalid URL provided: %s", urlStr)
		return ""
	}

	data := fmt.Sprintf("grant_type=password&client_id=%s&username=%s&password=%s", clientID, username, password)
	if clientSecret != "" {
		data += fmt.Sprintf("&client_secret=%s", clientSecret)
	}

	resp, err := http.Post(parsedURL.String(), "application/x-www-form-urlencoded", strings.NewReader(data))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	var tokenResp map[string]interface{}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return ""
	}

	if token, ok := tokenResp["access_token"].(string); ok {
		return token
	}
	return ""
}

func (suite *BaseIntegrationTestSuite) makeHTTPRequest(url, method string, headers map[string]string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader

	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	return client.Do(req)
}

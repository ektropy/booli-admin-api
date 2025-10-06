package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"os"
	"testing"
	"time"

	"github.com/booli/booli-admin-api/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type UserInviteIntegrationTestSuite struct {
	BaseIntegrationTestSuite
	mailpitContainer testcontainers.Container
	mailpitHost      string
	mailpitPort      string
	mailpitWebPort   string
}

func (suite *UserInviteIntegrationTestSuite) SetupSuite() {
	suite.BaseIntegrationTestSuite.SetupSuite()
	suite.startMailPitContainer()
}

func (suite *UserInviteIntegrationTestSuite) TearDownSuite() {
	if suite.mailpitContainer != nil {
		_ = suite.mailpitContainer.Terminate(suite.ctx)
	}
	suite.BaseIntegrationTestSuite.TearDownSuite()
}

func (suite *UserInviteIntegrationTestSuite) startMailPitContainer() {
	req := testcontainers.ContainerRequest{
		Image:        "axllent/mailpit:latest",
		ExposedPorts: []string{"1025/tcp", "8025/tcp"},
		Env: map[string]string{
			"MP_MAX_MESSAGES":       "5000",
			"MP_SMTP_AUTH_DISABLED": "1",
		},
		WaitingFor: wait.ForListeningPort("1025/tcp").WithStartupTimeout(30 * time.Second),
	}

	container, err := testcontainers.GenericContainer(suite.ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	suite.Require().NoError(err)

	suite.mailpitContainer = container

	host, err := container.Host(suite.ctx)
	suite.Require().NoError(err)
	suite.mailpitHost = host

	smtpPort, err := container.MappedPort(suite.ctx, "1025")
	suite.Require().NoError(err)
	suite.mailpitPort = smtpPort.Port()

	webPort, err := container.MappedPort(suite.ctx, "8025")
	suite.Require().NoError(err)
	suite.mailpitWebPort = webPort.Port()
}

func (suite *UserInviteIntegrationTestSuite) configureKeycloakSMTP(realmName string) {
	token := suite.AuthenticateUser(realmName, suite.Config.KeycloakClientID, suite.Config.KeycloakClientSecret, "admin", "ChangeMe123!")
	require.NotEmpty(suite.T(), token)

	getURL := fmt.Sprintf("http://%s:%s/admin/realms/%s",
		suite.keycloakHost, suite.keycloakPort, realmName)

	getReq, err := http.NewRequest("GET", getURL, nil)
	require.NoError(suite.T(), err)
	getReq.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	getResp, err := client.Do(getReq)
	require.NoError(suite.T(), err)
	defer getResp.Body.Close()

	if getResp.StatusCode != 200 {
		suite.T().Logf("Failed to get realm %s: status %d", realmName, getResp.StatusCode)
		return
	}

	var realm map[string]interface{}
	err = json.NewDecoder(getResp.Body).Decode(&realm)
	require.NoError(suite.T(), err)

	if realmJSON, err := json.MarshalIndent(realm, "", "  "); err == nil {
		suite.T().Logf("Current realm structure for %s:\n%s", realmName, string(realmJSON))
	}

	smtpConfig := map[string]string{
		"host":               suite.mailpitHost,
		"port":               suite.mailpitPort,
		"from":               "noreply@booli.test",
		"fromDisplayName":    "Booli Test",
		"replyTo":            "",
		"replyToDisplayName": "",
		"envelopeFrom":       "",
		"ssl":                "false",
		"starttls":           "false",
		"auth":               "false",
		"user":               "",
		"password":           "",
	}

	realm["smtpServer"] = smtpConfig

	jsonData, err := json.Marshal(realm)
	require.NoError(suite.T(), err)

	suite.T().Logf("Sending PUT request to update realm with SMTP config for realm %s", realmName)

	putReq, err := http.NewRequest("PUT", getURL, bytes.NewBuffer(jsonData))
	require.NoError(suite.T(), err)
	putReq.Header.Set("Authorization", "Bearer "+token)
	putReq.Header.Set("Content-Type", "application/json")

	putResp, err := client.Do(putReq)
	require.NoError(suite.T(), err)
	defer putResp.Body.Close()

	suite.T().Logf("SMTP config PUT response: %d for realm %s", putResp.StatusCode, realmName)

	if putResp.StatusCode == 200 || putResp.StatusCode == 204 {
		suite.T().Logf("SMTP configuration PUT request accepted (status %d)", putResp.StatusCode)
	} else {
		body, _ := io.ReadAll(putResp.Body)
		suite.T().Logf("SMTP config PUT failed with status %d: %s", putResp.StatusCode, string(body))
		return
	}

	suite.verifySMTPConfiguration(realmName, token, smtpConfig)

	suite.testSMTPConfiguration(realmName, token, smtpConfig)
}

func (suite *UserInviteIntegrationTestSuite) verifySMTPConfiguration(realmName, token string, expectedConfig map[string]string) {
	getURL := fmt.Sprintf("http://%s:%s/admin/realms/%s",
		suite.keycloakHost, suite.keycloakPort, realmName)

	getReq, err := http.NewRequest("GET", getURL, nil)
	require.NoError(suite.T(), err)
	getReq.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	getResp, err := client.Do(getReq)
	require.NoError(suite.T(), err)
	defer getResp.Body.Close()

	if getResp.StatusCode != 200 {
		suite.T().Logf("Failed to verify realm %s: status %d", realmName, getResp.StatusCode)
		return
	}

	var realm map[string]interface{}
	err = json.NewDecoder(getResp.Body).Decode(&realm)
	require.NoError(suite.T(), err)

	if smtpServer, exists := realm["smtpServer"]; exists {
		suite.T().Logf("SMTP configuration found in realm %s", realmName)
		if smtpMap, ok := smtpServer.(map[string]interface{}); ok {
			suite.T().Logf("Current SMTP config: host=%v, port=%v, from=%v, auth=%v",
				smtpMap["host"], smtpMap["port"], smtpMap["from"], smtpMap["auth"])

			expectedHost := expectedConfig["host"]
			expectedPort := expectedConfig["port"]
			expectedFrom := expectedConfig["from"]

			if smtpMap["host"] == expectedHost && smtpMap["port"] == expectedPort && smtpMap["from"] == expectedFrom {
				suite.T().Logf("SMTP configuration matches expected values")
			} else {
				suite.T().Logf("SMTP configuration does NOT match expected values")
				suite.T().Logf("Expected: host=%s, port=%s, from=%s", expectedHost, expectedPort, expectedFrom)
				suite.T().Logf("Actual: host=%v, port=%v, from=%v", smtpMap["host"], smtpMap["port"], smtpMap["from"])
			}
		} else {
			suite.T().Logf("SMTP configuration exists but is not a map: %T", smtpServer)
		}
	} else {
		suite.T().Logf("No SMTP configuration found in realm %s - SMTP settings were NOT applied!", realmName)
	}
}

func (suite *UserInviteIntegrationTestSuite) testSMTPConfiguration(realmName, token string, smtpConfig map[string]string) {
	testURL := fmt.Sprintf("http://%s:%s/admin/realms/%s/testSMTPConnection",
		suite.keycloakHost, suite.keycloakPort, realmName)

	configJSON, err := json.Marshal(smtpConfig)
	if err != nil {
		suite.T().Logf("Failed to marshal SMTP config: %v", err)
		return
	}

	testReq, err := http.NewRequest("POST", testURL, bytes.NewBuffer(configJSON))
	if err != nil {
		suite.T().Logf("Failed to create test SMTP request: %v", err)
		return
	}
	testReq.Header.Set("Authorization", "Bearer "+token)
	testReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	testResp, err := client.Do(testReq)
	if err != nil {
		suite.T().Logf("Failed to test SMTP: %v", err)
		return
	}
	defer testResp.Body.Close()

	suite.T().Logf("SMTP test response: %d", testResp.StatusCode)

	body, err := io.ReadAll(testResp.Body)
	if err != nil {
		suite.T().Logf("Failed to read SMTP test response body: %v", err)
		return
	}

	suite.T().Logf("SMTP test response body length: %d bytes", len(body))
	if len(body) > 0 {
		suite.T().Logf("SMTP test response body: %s", string(body))
	}

	if testResp.StatusCode == 204 {
		suite.T().Logf("SMTP test successful for realm %s", realmName)
	} else {
		suite.T().Logf("SMTP test failed with status %d: %s", testResp.StatusCode, string(body))
	}
}

func (suite *UserInviteIntegrationTestSuite) TestCreateTenant() {
	mspAdmin := suite.Config.DefaultTestUsers[0]
	token := suite.AuthenticateUser("master", suite.Config.KeycloakClientID, suite.Config.KeycloakClientSecret, mspAdmin.Username, mspAdmin.Password)
	require.NotEmpty(suite.T(), token)

	tenantRequest := map[string]interface{}{
		"name":   "test-invite-tenant",
		"domain": "test-invite.local",
		"type":   "msp",
	}

	headers := map[string]string{
		"Authorization": "Bearer " + token,
	}

	resp, err := suite.MakeRequest("POST", "/admin/tenants", headers, tenantRequest)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		assert.Equal(suite.T(), http.StatusCreated, resp.StatusCode)
	}
}

func (suite *UserInviteIntegrationTestSuite) TestCreateUserWithInvite() {
	suite.TestCreateTenant()

	suite.configureKeycloakSMTP("tenant-test-invite-tenant")

	mspAdmin := suite.Config.DefaultTestUsers[0]
	token := suite.AuthenticateUser("master", suite.Config.KeycloakClientID, suite.Config.KeycloakClientSecret, mspAdmin.Username, mspAdmin.Password)
	require.NotEmpty(suite.T(), token)

	userRequest := models.CreateUserRequest{
		TenantRealm: "tenant-test-invite-tenant",
		Username:    "invite-test-user",
		Email:       "invite-test@example.com",
		FirstName:   "Invite",
		LastName:    "Test",
		SendInvite:  true,
		DefaultRole: "tenant-user",
	}

	headers := map[string]string{
		"Authorization": "Bearer " + token,
	}

	resp, err := suite.MakeRequest("POST", "/admin/users", headers, userRequest)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(suite.T(), err)

	if resp.StatusCode != http.StatusCreated {
		suite.T().Logf("Response body: %s", string(body))
	}
	assert.Equal(suite.T(), http.StatusCreated, resp.StatusCode)

	var user models.User
	err = json.Unmarshal(body, &user)
	require.NoError(suite.T(), err)

	assert.Equal(suite.T(), "invite-test-user", user.Username)
	assert.Equal(suite.T(), "invite-test@example.com", user.Email)
	assert.Equal(suite.T(), false, user.Enabled)

	suite.verifyEmailSent("invite-test@example.com")
}

func (suite *UserInviteIntegrationTestSuite) TestResendInvitation() {
	suite.TestCreateUserWithInvite()

	mspAdmin := suite.Config.DefaultTestUsers[0]
	token := suite.AuthenticateUser("master", suite.Config.KeycloakClientID, suite.Config.KeycloakClientSecret, mspAdmin.Username, mspAdmin.Password)
	require.NotEmpty(suite.T(), token)

	usersResp, err := suite.MakeRequest("GET", "/admin/users?tenant_realm=tenant-test-invite-tenant",
		map[string]string{"Authorization": "Bearer " + token}, nil)
	require.NoError(suite.T(), err)
	defer usersResp.Body.Close()

	var usersList models.UserListResponse
	body, err := io.ReadAll(usersResp.Body)
	require.NoError(suite.T(), err)
	err = json.Unmarshal(body, &usersList)
	require.NoError(suite.T(), err)

	require.Greater(suite.T(), len(usersList.Users), 0)

	userID := usersList.Users[0].ID

	resendRequest := map[string]interface{}{
		"actions":  []string{"UPDATE_PASSWORD", "VERIFY_EMAIL"},
		"lifespan": 86400,
	}

	resp, err := suite.MakeRequest("POST",
		fmt.Sprintf("/users/%s/send-invite", userID),
		map[string]string{"Authorization": "Bearer " + token},
		resendRequest)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	body, err = io.ReadAll(resp.Body)
	require.NoError(suite.T(), err)
	err = json.Unmarshal(body, &response)
	require.NoError(suite.T(), err)

	assert.Equal(suite.T(), "invitation_sent", response["status"])
	assert.Equal(suite.T(), userID, response["user_id"])
}

func (suite *UserInviteIntegrationTestSuite) TestSMTPConnectivity() {
	conn, err := smtp.Dial(fmt.Sprintf("%s:%s", suite.mailpitHost, suite.mailpitPort))
	require.NoError(suite.T(), err)
	defer conn.Close()

	err = conn.Hello("test")
	require.NoError(suite.T(), err)
}

func (suite *UserInviteIntegrationTestSuite) TestMailPitWebInterface() {
	url := fmt.Sprintf("http://%s:%s/api/v1/messages", suite.mailpitHost, suite.mailpitWebPort)
	resp, err := http.Get(url)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
}

func (suite *UserInviteIntegrationTestSuite) verifyEmailSent(expectedTo string) {
	time.Sleep(5 * time.Second)

	url := fmt.Sprintf("http://%s:%s/api/v1/messages", suite.mailpitHost, suite.mailpitWebPort)
	resp, err := http.Get(url)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(suite.T(), err)

	suite.T().Logf("MailPit messages response: %s", string(body))

	var messages struct {
		Total    int `json:"total"`
		Messages []struct {
			ID string `json:"ID"`
			To []struct {
				Address string `json:"Address"`
			} `json:"To"`
			Subject string `json:"Subject"`
			From    struct {
				Address string `json:"Address"`
			} `json:"From"`
		} `json:"messages"`
	}

	err = json.Unmarshal(body, &messages)
	require.NoError(suite.T(), err)

	suite.T().Logf("Total messages in MailPit: %d", messages.Total)

	for i, msg := range messages.Messages {
		suite.T().Logf("Message %d: From=%s, Subject=%s", i+1, msg.From.Address, msg.Subject)
		for j, to := range msg.To {
			suite.T().Logf("  To[%d]: %s", j, to.Address)
		}
	}

	found := false
	for _, msg := range messages.Messages {
		for _, to := range msg.To {
			if to.Address == expectedTo {
				found = true
				suite.T().Logf("Found email to %s with subject: %s", expectedTo, msg.Subject)
				break
			}
		}
		if found {
			break
		}
	}

	assert.True(suite.T(), found, "Email to %s not found in MailPit", expectedTo)
}

func TestUserInviteIntegrationSuite(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "true" {
		t.Skip("Integration tests skipped. Set RUN_INTEGRATION_TESTS=true to run.")
	}

	suite.Run(t, new(UserInviteIntegrationTestSuite))
}

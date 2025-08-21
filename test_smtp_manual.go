package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <keycloak_port> <mailpit_port>\n", os.Args[0])
		os.Exit(1)
	}
	
	keycloakPort := os.Args[1]
	mailpitPort := os.Args[2]
	
	// Get admin token
	fmt.Printf("Getting admin token from Keycloak on port %s...\n", keycloakPort)
	token, err := getAdminToken(keycloakPort)
	if err != nil {
		fmt.Printf("Failed to get token: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Printf("Token obtained: %s...\n", token[:50])
	
	// Test SMTP configuration
	fmt.Printf("Testing SMTP configuration...\n")
	err = testSMTPConfig(keycloakPort, mailpitPort, token)
	if err != nil {
		fmt.Printf("SMTP test failed: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Println("SMTP test completed successfully!")
}

func getAdminToken(keycloakPort string) (string, error) {
	url := fmt.Sprintf("http://localhost:%s/realms/master/protocol/openid-connect/token", keycloakPort)
	
	data := "grant_type=password&client_id=msp-client&client_secret=msp-secret&username=msp-admin&password=admin123"
	
	resp, err := http.Post(url, "application/x-www-form-urlencoded", bytes.NewBufferString(data))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	var tokenResp map[string]interface{}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", err
	}
	
	token, ok := tokenResp["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("no access token in response")
	}
	
	return token, nil
}

func testSMTPConfig(keycloakPort, mailpitPort, token string) error {
	// Update SMTP configuration
	realmURL := fmt.Sprintf("http://localhost:%s/admin/realms/tenant-test-invite-tenant", keycloakPort)
	
	smtpConfig := map[string]interface{}{
		"smtpServer": map[string]string{
			"host":            "localhost",
			"port":            mailpitPort,
			"from":            "noreply@booli.test",
			"fromDisplayName": "Booli Test",
			"replyTo":         "",
			"replyToDisplayName": "",
			"envelopeFrom":    "",
			"ssl":             "false",
			"starttls":        "false",
			"auth":            "false",
			"user":            "",
			"password":        "",
		},
	}
	
	jsonData, err := json.Marshal(smtpConfig)
	if err != nil {
		return err
	}
	
	// PUT SMTP configuration
	putReq, err := http.NewRequest("PUT", realmURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	putReq.Header.Set("Authorization", "Bearer "+token)
	putReq.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{}
	putResp, err := client.Do(putReq)
	if err != nil {
		return err
	}
	defer putResp.Body.Close()
	
	fmt.Printf("SMTP config PUT response: %d\n", putResp.StatusCode)
	
	// Read and analyze the response body
	body, err := io.ReadAll(putResp.Body)
	if err != nil {
		return err
	}
	
	fmt.Printf("Response body length: %d bytes\n", len(body))
	if len(body) > 0 {
		fmt.Printf("First 100 bytes (hex): %x\n", body[:min(100, len(body))])
		fmt.Printf("First 100 bytes (string): %q\n", string(body[:min(100, len(body))]))
	}
	
	// Test SMTP connection
	testURL := fmt.Sprintf("http://localhost:%s/admin/realms/tenant-test-invite-tenant/testSMTPConnection", keycloakPort)
	
	smtpTestConfig := map[string]string{
		"host":            "localhost",
		"port":            mailpitPort,
		"from":            "noreply@booli.test",
		"fromDisplayName": "Booli Test",
		"replyTo":         "",
		"replyToDisplayName": "",
		"envelopeFrom":    "",
		"ssl":             "false",
		"starttls":        "false",
		"auth":            "false",
		"user":            "",
		"password":        "",
	}
	
	testJSON, err := json.Marshal(smtpTestConfig)
	if err != nil {
		return err
	}
	
	testReq, err := http.NewRequest("POST", testURL, bytes.NewBuffer(testJSON))
	if err != nil {
		return err
	}
	testReq.Header.Set("Authorization", "Bearer "+token)
	testReq.Header.Set("Content-Type", "application/json")
	
	testResp, err := client.Do(testReq)
	if err != nil {
		return err
	}
	defer testResp.Body.Close()
	
	testBody, err := io.ReadAll(testResp.Body)
	if err != nil {
		return err
	}
	
	fmt.Printf("SMTP test response: %d\n", testResp.StatusCode)
	fmt.Printf("SMTP test body: %s\n", string(testBody))
	
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
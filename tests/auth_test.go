// tests_go/auth_test.go
package tests_go

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func TestLoginSuperuser(t *testing.T) {
	logTest(t, "Attempting valid login for superuser: %s", cfg.SuperuserUser)
	token := login(t, cfg.SuperuserUser, cfg.SuperuserPass) // login helper handles assertions and logging

	if token == "" {
		// login helper would have failed if status != 200, this is extra check
		logError(t, "Expected a non-empty token for superuser login, but got empty")
		t.Error("Expected a non-empty token for superuser login, but got empty")
	}
	if len(token) < 10 {
		logError(t, "Token seems too short: length %d", len(token))
		t.Errorf("Token seems too short: length %d", len(token))
	}
	logSuccess(t, "Superuser login successful, token received")
}

func TestLoginAPIUser(t *testing.T) {
	logTest(t, "Attempting valid login for apiuser: %s", cfg.APIUserUser)
	token := login(t, cfg.APIUserUser, cfg.APIUserPass) // login helper handles assertions and logging

	if token == "" {
		logError(t, "Expected a non-empty token for apiuser login, but got empty")
		t.Error("Expected a non-empty token for apiuser login, but got empty")
	}
	if len(token) < 10 {
		logError(t, "Token seems too short: length %d", len(token))
		t.Errorf("Token seems too short: length %d", len(token))
	}
	logSuccess(t, "Apiuser login successful, token received")
}

func TestInvalidLogin(t *testing.T) {
	logTest(t, "Attempting invalid login (wrong user/pass - expecting 401 Unauthorized)")
	loginURL := cfg.APIURL + "/login"
	payload := map[string]string{
		"username": "nonexistent_user_!@#$",
		"password": "wrong_password_$%^",
	}
	// Use doRequest directly for non-200 expectations
	bodyBytes, statusCode, err := doRequest(t, "POST", loginURL, getAuthHeaders(""), // No token needed
		bytes.NewBuffer(mustMarshal(t, payload)), cfg.RequestTimeout)

	if err != nil {
		logError(t, "Request execution failed: %v", err)
		t.Fatalf("Request execution failed: %v", err)
	}

	logInfo(t, "Received status %d for invalid login", statusCode)
	if statusCode != http.StatusUnauthorized {
		// Use t.Errorf for non-fatal assertion failure, include body
		logError(t, "Expected status %d, but got %d", http.StatusUnauthorized, statusCode)
		t.Errorf("Expected status %d, but got %d. Body: %s", http.StatusUnauthorized, statusCode, string(bodyBytes))
	}

	// Check for error field in response body
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
		logWarning(t, "Could not unmarshal error response: %v", err)
	} else if errResp.Error == "" {
		logError(t, "Expected 'error' field in JSON response for invalid login")
		t.Error("Expected 'error' field in JSON response for invalid login")
	}

	if statusCode == http.StatusUnauthorized && errResp.Error != "" {
		logSuccess(t, "Invalid login correctly rejected with 401 Unauthorized")
	}
}

func TestUnauthorizedUserLogin(t *testing.T) {
	logTest(t, "Attempting login for unauthorized user: %s (expecting 401 Unauthorized)", cfg.UnauthUser)
	loginURL := cfg.APIURL + "/login"
	payload := map[string]string{
		"username": cfg.UnauthUser,
		"password": cfg.UnauthPass,
	}
	// Use doRequest directly
	bodyBytes, statusCode, err := doRequest(t, "POST", loginURL, getAuthHeaders(""), // No token needed
		bytes.NewBuffer(mustMarshal(t, payload)), cfg.RequestTimeout)

	if err != nil {
		logError(t, "Request execution failed: %v", err)
		t.Fatalf("Request execution failed: %v", err)
	}

	logInfo(t, "Received status %d for unauthorized user login", statusCode)
	if statusCode != http.StatusUnauthorized {
		logError(t, "Expected status %d for user not in allowed groups, got %d", http.StatusUnauthorized, statusCode)
		t.Errorf("Expected status %d for user not in allowed groups, got %d. Body: %s",
			http.StatusUnauthorized, statusCode, string(bodyBytes))
	}

	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
		logWarning(t, "Could not unmarshal error response: %v", err)
	} else if errResp.Error == "" {
		logError(t, "Expected 'error' field in JSON response for unauthorized login")
		t.Error("Expected 'error' field in JSON response for unauthorized login")
	}

	if statusCode == http.StatusUnauthorized && errResp.Error != "" {
		logSuccess(t, "Unauthorized user login correctly rejected with 401 Unauthorized")
	}
}

// mustMarshal is a helper to simplify JSON marshaling in tests.
func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		logError(t, "Failed to marshal JSON: %v", err)
		t.Fatalf("Failed to marshal JSON: %v", err)
	}
	return data
}

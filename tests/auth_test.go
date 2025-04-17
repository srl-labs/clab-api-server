// tests_go/auth_test.go
package tests_go

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func TestLoginSuperuser(t *testing.T) {
	t.Logf("[TEST] Attempting valid login for superuser: %s", cfg.SuperuserUser)
	token := login(t, cfg.SuperuserUser, cfg.SuperuserPass) // login helper handles assertions and logging

	if token == "" {
		// login helper would have failed if status != 200, this is extra check
		t.Error("Expected a non-empty token for superuser login, but got empty")
	}
	if len(token) < 10 {
		t.Errorf("Token seems too short: length %d", len(token))
	}
	t.Log("  `-> Superuser login successful, token received.")
}

func TestLoginAPIUser(t *testing.T) {
	t.Logf("[TEST] Attempting valid login for apiuser: %s", cfg.APIUserUser)
	token := login(t, cfg.APIUserUser, cfg.APIUserPass) // login helper handles assertions and logging

	if token == "" {
		t.Error("Expected a non-empty token for apiuser login, but got empty")
	}
	if len(token) < 10 {
		t.Errorf("Token seems too short: length %d", len(token))
	}
	t.Log("  `-> Apiuser login successful, token received.")
}

func TestInvalidLogin(t *testing.T) {
	t.Log("[TEST] Attempting invalid login (wrong user/pass).")
	loginURL := cfg.APIURL + "/login"
	payload := map[string]string{
		"username": "nonexistent_user_!@#$",
		"password": "wrong_password_$%^",
	}
	// Use doRequest directly for non-200 expectations
	bodyBytes, statusCode, err := doRequest(t, "POST", loginURL, getAuthHeaders(""), // No token needed
		bytes.NewBuffer(mustMarshal(t, payload)), cfg.RequestTimeout)

	if err != nil {
		t.Fatalf("Request execution failed: %v", err)
	}

	t.Logf("  `-> Received status %d. Asserting it's 401.", statusCode)
	if statusCode != http.StatusUnauthorized {
		// Use t.Errorf for non-fatal assertion failure, include body
		t.Errorf("Expected status %d, but got %d. Body: %s", http.StatusUnauthorized, statusCode, string(bodyBytes))
	}

	// Check for error field in response body
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
		t.Logf("Warning: Could not unmarshal error response: %v. Body: %s", err, string(bodyBytes))
	} else if errResp.Error == "" {
		t.Error("Expected 'error' field in JSON response for invalid login")
	}
	t.Log("  `-> Invalid login test completed.") // More neutral completion message
}

func TestUnauthorizedUserLogin(t *testing.T) {
	t.Logf("[TEST] Attempting login for unauthorized user: %s (expecting 401).", cfg.UnauthUser)
	loginURL := cfg.APIURL + "/login"
	payload := map[string]string{
		"username": cfg.UnauthUser,
		"password": cfg.UnauthPass,
	}
	// Use doRequest directly
	bodyBytes, statusCode, err := doRequest(t, "POST", loginURL, getAuthHeaders(""), // No token needed
		bytes.NewBuffer(mustMarshal(t, payload)), cfg.RequestTimeout)

	if err != nil {
		t.Fatalf("Request execution failed: %v", err)
	}

	t.Logf("  `-> Received status %d. Asserting it's 401.", statusCode)
	if statusCode != http.StatusUnauthorized {
		t.Errorf("Expected status %d for user not in allowed groups, got %d. Body: %s", http.StatusUnauthorized, statusCode, string(bodyBytes))
	}

	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
		t.Logf("Warning: Could not unmarshal error response: %v. Body: %s", err, string(bodyBytes))
	} else if errResp.Error == "" {
		t.Error("Expected 'error' field in JSON response for unauthorized login")
	}
	t.Log("  `-> Unauthorized user login test completed.")
}

// mustMarshal is a helper to simplify JSON marshaling in tests.
func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %v", err)
	}
	return data
}

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
	token := login(t, cfg.SuperuserUser, cfg.SuperuserPass) // login helper handles assertions

	if token == "" {
		t.Error("Expected a non-empty token for superuser login, but got empty")
	}
	if len(token) < 10 {
		t.Errorf("Token seems too short: length %d", len(token))
	}
	t.Log("  `-> Superuser login successful, token received.")
}

func TestLoginAPIUser(t *testing.T) {
	t.Logf("[TEST] Attempting valid login for apiuser: %s", cfg.APIUserUser)
	token := login(t, cfg.APIUserUser, cfg.APIUserPass) // login helper handles assertions

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
	// Directly call http client here as login helper would fail the test
	loginURL := cfg.APIURL + "/login"
	payload := map[string]string{
		"username": "nonexistent_user_!@#$",
		"password": "wrong_password_$%^",
	}
	bodyBytes, statusCode, err := doRequest(t, "POST", loginURL, getAuthHeaders(""), // No token needed
		bytes.NewBuffer(mustMarshal(t, payload)), cfg.RequestTimeout)

	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	t.Logf("  `-> Received status %d. Asserting it's 401.", statusCode)
	if statusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized, got %d. Body: %s", statusCode, string(bodyBytes))
	}

	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
		t.Logf("Warning: Could not unmarshal error response: %v. Body: %s", err, string(bodyBytes))
	} else if errResp.Error == "" {
		t.Error("Expected 'error' field in JSON response for invalid login")
	}
	t.Log("  `-> Invalid login correctly resulted in 401.")
}

func TestUnauthorizedUserLogin(t *testing.T) {
	t.Logf("[TEST] Attempting login for unauthorized user: %s (expecting 401).", cfg.UnauthUser)
	// Directly call http client
	loginURL := cfg.APIURL + "/login"
	payload := map[string]string{
		"username": cfg.UnauthUser,
		"password": cfg.UnauthPass,
	}
	bodyBytes, statusCode, err := doRequest(t, "POST", loginURL, getAuthHeaders(""), // No token needed
		bytes.NewBuffer(mustMarshal(t, payload)), cfg.RequestTimeout)

	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	t.Logf("  `-> Received status %d. Asserting it's 401.", statusCode)
	if statusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized for user not in allowed groups, got %d. Body: %s", statusCode, string(bodyBytes))
	}

	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
		t.Logf("Warning: Could not unmarshal error response: %v. Body: %s", err, string(bodyBytes))
	} else if errResp.Error == "" {
		t.Error("Expected 'error' field in JSON response for unauthorized login")
	}
	t.Log("  `-> Unauthorized user login correctly resulted in 401.")
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

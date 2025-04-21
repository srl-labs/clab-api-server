// tests_go/lab_config_test.go
package tests_go

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// TestInspectLabInterfaces tests the endpoint for listing interfaces of a lab node
func TestInspectLabInterfaces(t *testing.T) {
	labName, userHeaders := setupEphemeralLab(t) // Setup handles creation and cleanup

	logTest(t, "Inspecting interfaces for lab '%s'", labName)

	interfacesURL := fmt.Sprintf("%s/api/v1/labs/%s/interfaces", cfg.APIURL, labName)
	bodyBytes, statusCode, err := doRequest(t, "GET", interfacesURL, userHeaders, nil, cfg.RequestTimeout)
	if err != nil {
		logError(t, "Failed to execute inspect interfaces request: %v", err)
		t.Fatalf("Failed to execute inspect interfaces request: %v", err)
	}

	if statusCode != http.StatusOK {
		logError(t, "Expected status %d inspecting interfaces for lab '%s', got %d", http.StatusOK, labName, statusCode)
		t.Fatalf("Expected status %d inspecting interfaces for lab '%s', got %d. Body: %s", http.StatusOK, labName, statusCode, string(bodyBytes))
	}

	// Verify we can parse the response as JSON
	var interfacesList []interface{}
	if err := json.Unmarshal(bodyBytes, &interfacesList); err != nil {
		logError(t, "Failed to unmarshal inspect interfaces response: %v", err)
		t.Fatalf("Failed to unmarshal inspect interfaces response: %v. Body: %s", err, string(bodyBytes))
	}

	if len(interfacesList) == 0 {
		logWarning(t, "Inspect interfaces for lab '%s' returned empty array, expected at least one node", labName)
		t.Errorf("Inspect interfaces for lab '%s' returned empty array, expected at least one node", labName)
	} else {
		logSuccess(t, "Successfully retrieved interfaces for lab '%s'", labName)
	}
}

// TestSaveLabConfig tests the endpoint for saving lab configuration
func TestSaveLabConfig(t *testing.T) {
	labName, userHeaders := setupEphemeralLab(t) // Setup handles creation and cleanup

	logTest(t, "Saving configuration for lab '%s'", labName)

	saveURL := fmt.Sprintf("%s/api/v1/labs/%s/save", cfg.APIURL, labName)
	bodyBytes, statusCode, err := doRequest(t, "POST", saveURL, userHeaders, nil, cfg.RequestTimeout)
	if err != nil {
		logError(t, "Failed to execute save config request: %v", err)
		t.Fatalf("Failed to execute save config request: %v", err)
	}

	if statusCode != http.StatusOK {
		logError(t, "Expected status %d saving config for lab '%s', got %d", http.StatusOK, labName, statusCode)
		t.Fatalf("Expected status %d saving config for lab '%s', got %d. Body: %s", http.StatusOK, labName, statusCode, string(bodyBytes))
	}

	// Verify we can parse the response
	var saveResponse struct {
		Message string `json:"message"`
		Output  string `json:"output"`
	}

	if err := json.Unmarshal(bodyBytes, &saveResponse); err != nil {
		logError(t, "Failed to unmarshal save config response: %v", err)
		t.Fatalf("Failed to unmarshal save config response: %v. Body: %s", err, string(bodyBytes))
	}

	if saveResponse.Message == "" {
		logError(t, "Save config response missing message field")
		t.Errorf("Save config response missing message field")
	} else {
		logSuccess(t, "Successfully saved configuration for lab '%s'", labName)
	}
}

// TestAccessLabInterfacesSuperuser tests that a superuser can access lab interfaces
func TestAccessLabInterfacesSuperuser(t *testing.T) {
	// Create a lab as the regular user
	apiLabName, _ := setupEphemeralLab(t) // Cleanup handled by setup

	// Access it as the superuser
	superuserToken := login(t, cfg.SuperuserUser, cfg.SuperuserPass)
	superuserHeaders := getAuthHeaders(superuserToken)

	logTest(t, "Accessing interfaces for lab '%s' as superuser '%s'",
		apiLabName, cfg.SuperuserUser)

	interfacesURL := fmt.Sprintf("%s/api/v1/labs/%s/interfaces", cfg.APIURL, apiLabName)
	bodyBytes, statusCode, err := doRequest(t, "GET", interfacesURL, superuserHeaders, nil, cfg.RequestTimeout)
	if err != nil {
		logError(t, "Failed to execute superuser lab interfaces request: %v", err)
		t.Fatalf("Failed to execute superuser lab interfaces request: %v", err)
	}

	if statusCode != http.StatusOK {
		logError(t, "Expected status %d for superuser accessing lab interfaces, got %d",
			http.StatusOK, statusCode)
		t.Fatalf("Expected status %d for superuser accessing lab interfaces, got %d. Body: %s",
			http.StatusOK, statusCode, string(bodyBytes))
	}

	// Verify we can parse the response as JSON
	var interfacesList []interface{}
	if err := json.Unmarshal(bodyBytes, &interfacesList); err != nil {
		logError(t, "Failed to unmarshal superuser lab interfaces response: %v", err)
		t.Fatalf("Failed to unmarshal superuser lab interfaces response: %v. Body: %s", err, string(bodyBytes))
	}

	logSuccess(t, "Superuser successfully accessed interfaces for lab '%s' owned by '%s'",
		apiLabName, cfg.APIUserUser)
}

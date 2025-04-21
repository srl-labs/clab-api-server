// tests_go/lab_network_test.go
package tests_go

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// TestInspectLabNetworkInterfaces tests the endpoint for listing network interfaces of lab nodes
func TestInspectLabNetworkInterfaces(t *testing.T) {
	labName, userHeaders := setupEphemeralLab(t) // Setup handles creation and cleanup

	logTest(t, "Inspecting network interfaces for lab '%s'", labName)

	interfacesURL := fmt.Sprintf("%s/api/v1/labs/%s/interfaces", cfg.APIURL, labName)
	bodyBytes, statusCode, err := doRequest(t, "GET", interfacesURL, userHeaders, nil, cfg.RequestTimeout)
	if err != nil {
		logError(t, "Failed to execute inspect network interfaces request: %v", err)
		t.Fatalf("Failed to execute inspect network interfaces request: %v", err)
	}

	if statusCode != http.StatusOK {
		logError(t, "Expected status %d inspecting network interfaces for lab '%s', got %d", http.StatusOK, labName, statusCode)
		t.Fatalf("Expected status %d inspecting network interfaces for lab '%s', got %d. Body: %s", http.StatusOK, labName, statusCode, string(bodyBytes))
	}

	// Verify we can parse the response as JSON
	var interfacesList []interface{}
	if err := json.Unmarshal(bodyBytes, &interfacesList); err != nil {
		logError(t, "Failed to unmarshal inspect network interfaces response: %v", err)
		t.Fatalf("Failed to unmarshal inspect network interfaces response: %v. Body: %s", err, string(bodyBytes))
	}

	if len(interfacesList) == 0 {
		logWarning(t, "Inspect network interfaces for lab '%s' returned empty array, expected at least one interface", labName)
		t.Errorf("Inspect network interfaces for lab '%s' returned empty array, expected at least one interface", labName)
	} else {
		logSuccess(t, "Successfully retrieved network interfaces for lab '%s'", labName)
	}
}

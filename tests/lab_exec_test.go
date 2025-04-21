// tests_go/lab_exec_test.go
package tests_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestExecCommandInLab tests the endpoint for executing commands in lab nodes
func TestExecCommandInLab(t *testing.T) {
	labName, userHeaders := setupEphemeralLab(t) // Setup handles creation and cleanup

	// Simple Linux command that should work on most containers in the lab
	command := "hostname"
	jsonPayload := fmt.Sprintf(`{"command": "%s"}`, command)

	logTest(t, "Executing command '%s' in lab '%s'", command, labName)

	execURL := fmt.Sprintf("%s/api/v1/labs/%s/exec", cfg.APIURL, labName)
	bodyBytes, statusCode, err := doRequest(t, "POST", execURL, userHeaders, bytes.NewBufferString(jsonPayload), cfg.RequestTimeout)
	if err != nil {
		logError(t, "Failed to execute command request: %v", err)
		t.Fatalf("Failed to execute command request: %v", err)
	}

	if statusCode != http.StatusOK {
		logError(t, "Expected status %d executing command in lab '%s', got %d", http.StatusOK, labName, statusCode)
		t.Fatalf("Expected status %d executing command in lab '%s', got %d. Body: %s", http.StatusOK, labName, statusCode, string(bodyBytes))
	}

	// Verify we can parse the response as JSON (map of nodes to exec results)
	var execResults map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &execResults); err != nil {
		logError(t, "Failed to unmarshal exec command response: %v", err)
		t.Fatalf("Failed to unmarshal exec command response: %v. Body: %s", err, string(bodyBytes))
	}

	if len(execResults) == 0 {
		logError(t, "Exec command in lab '%s' returned empty results, expected at least one node", labName)
		t.Errorf("Exec command in lab '%s' returned empty results, expected at least one node", labName)
	} else {
		logSuccess(t, "Successfully executed command in lab '%s'", labName)
	}
}

// TestPlainFormatExecCommandInLab tests the command execution with plain text output format
func TestPlainFormatExecCommandInLab(t *testing.T) {
	labName, userHeaders := setupEphemeralLab(t) // Setup handles creation and cleanup

	// Simple Linux command that should work on most containers in the lab
	command := "echo 'plain format test'"
	jsonPayload := fmt.Sprintf(`{"command": "%s"}`, command)

	logTest(t, "Executing command '%s' in lab '%s' with plain format", command, labName)

	execURL := fmt.Sprintf("%s/api/v1/labs/%s/exec?format=plain", cfg.APIURL, labName)
	bodyBytes, statusCode, err := doRequest(t, "POST", execURL, userHeaders, bytes.NewBufferString(jsonPayload), cfg.RequestTimeout)
	if err != nil {
		logError(t, "Failed to execute plain format command request: %v", err)
		t.Fatalf("Failed to execute plain format command request: %v", err)
	}

	if statusCode != http.StatusOK {
		logError(t, "Expected status %d executing plain format command in lab '%s', got %d", http.StatusOK, labName, statusCode)
		t.Fatalf("Expected status %d executing plain format command in lab '%s', got %d. Body: %s", http.StatusOK, labName, statusCode, string(bodyBytes))
	}

	// Response should be plain text
	responseText := string(bodyBytes)
	if len(responseText) == 0 {
		logError(t, "Plain format exec command in lab '%s' returned empty output", labName)
		t.Errorf("Plain format exec command in lab '%s' returned empty output", labName)
	} else if !strings.Contains(responseText, "plain format test") {
		logError(t, "Plain format exec command output does not contain expected string. Output: %s", responseText)
		t.Errorf("Plain format exec command output does not contain expected string. Output: %s", responseText)
	} else {
		logSuccess(t, "Successfully executed plain format command in lab '%s'", labName)
	}
}

// TestNodeFilteredExec tests executing a command with a node filter
func TestNodeFilteredExec(t *testing.T) {
	labName, userHeaders := setupEphemeralLab(t) // Setup handles creation and cleanup

	// Get the full node name from the lab
	logTest(t, "Finding node name for lab '%s' to use in filtered exec test", labName)

	inspectURL := fmt.Sprintf("%s/api/v1/labs/%s", cfg.APIURL, labName)
	inspectBytes, inspectCode, inspectErr := doRequest(t, "GET", inspectURL, userHeaders, nil, cfg.RequestTimeout)
	if inspectErr != nil || inspectCode != http.StatusOK {
		logError(t, "Failed to inspect lab to find node name: %v, Status: %d", inspectErr, inspectCode)
		t.Fatalf("Failed to inspect lab to find node name: %v, Status: %d, Body: %s",
			inspectErr, inspectCode, string(inspectBytes))
	}

	var labContainers []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(inspectBytes, &labContainers); err != nil {
		logError(t, "Failed to unmarshal lab inspect response: %v", err)
		t.Fatalf("Failed to unmarshal lab inspect response: %v. Body: %s", err, string(inspectBytes))
	}

	if len(labContainers) == 0 {
		logError(t, "Lab '%s' doesn't have any containers", labName)
		t.Fatalf("Lab '%s' doesn't have any containers", labName)
	}

	nodeFilter := labContainers[0].Name
	logTest(t, "Executing command with node filter '%s' in lab '%s'", nodeFilter, labName)

	// Simple Linux command
	command := "echo 'node filtered test'"
	jsonPayload := fmt.Sprintf(`{"command": "%s"}`, command)

	execURL := fmt.Sprintf("%s/api/v1/labs/%s/exec?nodeFilter=%s", cfg.APIURL, labName, nodeFilter)
	bodyBytes, statusCode, err := doRequest(t, "POST", execURL, userHeaders, bytes.NewBufferString(jsonPayload), cfg.RequestTimeout)
	if err != nil {
		logError(t, "Failed to execute filtered command request: %v", err)
		t.Fatalf("Failed to execute filtered command request: %v", err)
	}

	if statusCode != http.StatusOK {
		logError(t, "Expected status %d executing filtered command, got %d", http.StatusOK, statusCode)
		t.Fatalf("Expected status %d executing filtered command, got %d. Body: %s",
			http.StatusOK, statusCode, string(bodyBytes))
	}

	// Verify response contains only the filtered node
	var execResults map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &execResults); err != nil {
		logError(t, "Failed to unmarshal filtered exec response: %v", err)
		t.Fatalf("Failed to unmarshal filtered exec response: %v. Body: %s", err, string(bodyBytes))
	}

	if len(execResults) != 1 {
		logError(t, "Filtered exec should return exactly 1 node, got %d", len(execResults))
		t.Errorf("Filtered exec should return exactly 1 node, got %d", len(execResults))
	}

	if _, found := execResults[nodeFilter]; !found {
		logError(t, "Filtered exec results don't contain the specified node '%s'", nodeFilter)
		t.Errorf("Filtered exec results don't contain the specified node '%s'", nodeFilter)
	} else {
		logSuccess(t, "Successfully executed filtered command on node '%s'", nodeFilter)
	}
}

// tests_go/labs_test.go
package tests_go

import (
	// Import bytes
	"encoding/json"
	"fmt"
	"net/http"

	"strings"
	"testing"
	"time"
)

// Define expected structures from API responses (adjust based on actual models)
type ClabContainerInfo struct {
	Name        string `json:"name"`
	ContainerID string `json:"container_id"`
	Image       string `json:"image"`
	Kind        string `json:"kind"`
	State       string `json:"state"`
	IPv4Address string `json:"ipv4_address"`
	IPv6Address string `json:"ipv6_address"`
	LabName     string `json:"lab_name"`
	Owner       string `json:"owner"`
}

// ClabInspectOutput matches the top-level structure of `clab inspect --all --format json`
type ClabInspectOutput map[string][]ClabContainerInfo

func TestListLabsIncludesCreated(t *testing.T) {
	labName, userHeaders := setupEphemeralLab(t) // Setup handles creation and cleanup

	logTest(t, "Verifying lab '%s' is in the list for the owner (%s)", labName, cfg.APIUserUser)

	listURL := fmt.Sprintf("%s/api/v1/labs", cfg.APIURL)
	bodyBytes, statusCode, err := doRequest(t, "GET", listURL, userHeaders, nil, cfg.RequestTimeout)
	if err != nil {
		logError(t, "Failed to execute list labs request: %v", err)
		t.Fatalf("Failed to execute list labs request: %v", err)
	}

	if statusCode != http.StatusOK {
		logError(t, "Expected status %d listing labs, got %d", http.StatusOK, statusCode)
		t.Fatalf("Expected status %d listing labs, got %d. Body: %s", http.StatusOK, statusCode, string(bodyBytes))
	}

	var labsData ClabInspectOutput
	if err := json.Unmarshal(bodyBytes, &labsData); err != nil {
		logError(t, "Failed to unmarshal labs list response: %v", err)
		t.Fatalf("Failed to unmarshal labs list response: %v. Body: %s", err, string(bodyBytes))
	}

	if _, exists := labsData[labName]; !exists {
		logError(t, "Lab '%s' created by setup was not found in /api/v1/labs output for the user", labName)
		t.Errorf("Lab '%s' created by setup was not found in /api/v1/labs output for the user", labName)
	} else if len(labsData[labName]) == 0 {
		logError(t, "Lab '%s' should have container entries in the list", labName)
		t.Errorf("Lab '%s' should have container entries in the list", labName)
	} else {
		logSuccess(t, "Lab '%s' found in list", labName)
	}
}

func TestInspectCreatedLab(t *testing.T) {
	labName, userHeaders := setupEphemeralLab(t)

	logTest(t, "Inspecting details for lab '%s'", labName)
	inspectURL := fmt.Sprintf("%s/api/v1/labs/%s", cfg.APIURL, labName)
	bodyBytes, statusCode, err := doRequest(t, "GET", inspectURL, userHeaders, nil, cfg.RequestTimeout)
	if err != nil {
		logError(t, "Failed to execute inspect lab request: %v", err)
		t.Fatalf("Failed to execute inspect lab request: %v", err)
	}

	if statusCode != http.StatusOK {
		logError(t, "Expected status %d inspecting lab '%s', got %d", http.StatusOK, labName, statusCode)
		t.Fatalf("Expected status %d inspecting lab '%s', got %d. Body: %s", http.StatusOK, labName, statusCode, string(bodyBytes))
	}

	var labDetails []ClabContainerInfo
	if err := json.Unmarshal(bodyBytes, &labDetails); err != nil {
		logError(t, "Failed to unmarshal inspect response: %v", err)
		t.Fatalf("Failed to unmarshal inspect response: %v. Body: %s", err, string(bodyBytes))
	}

	if len(labDetails) == 0 {
		logError(t, "Inspect output for lab '%s' should contain container details, but was empty", labName)
		t.Errorf("Inspect output for lab '%s' should contain container details, but was empty", labName)
	} else if labDetails[0].LabName != labName {
		logError(t, "Expected lab name '%s' in inspect details, got '%s'", labName, labDetails[0].LabName)
		t.Errorf("Expected lab name '%s' in inspect details, got '%s'", labName, labDetails[0].LabName)
	} else {
		logSuccess(t, "Inspection successful for '%s'", labName)
	}
}

func TestCreateDuplicateLabFails(t *testing.T) {
	labName, userHeaders := setupEphemeralLab(t) // Lab exists now

	logTest(t, "Attempting to create duplicate lab '%s' (expecting 409 Conflict)", labName)

	topology := strings.ReplaceAll(cfg.SimpleTopologyContent, "{lab_name}", labName)
	// Call createLab helper, but check status code directly
	bodyBytes, statusCode, err := createLab(t, userHeaders, labName, topology, false, cfg.DeployTimeout) // reconfigure=false

	if err != nil {
		// This checks for transport errors, not status codes
		logError(t, "Failed to execute create duplicate lab request: %v", err)
		t.Fatalf("Failed to execute create duplicate lab request: %v", err)
	}

	// Assert the status code
	if statusCode != http.StatusConflict {
		logError(t, "Expected status %d (Conflict) when creating duplicate lab, but got %d", http.StatusConflict, statusCode)
		t.Errorf("Expected status %d (Conflict) when creating duplicate lab, but got %d. Body: %s", http.StatusConflict, statusCode, string(bodyBytes))
	} else {
		logSuccess(t, "Correctly received status %d (Conflict) when creating duplicate lab", statusCode)
		// Optionally check error message in body
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(bodyBytes, &errResp) == nil && !strings.Contains(errResp.Error, "already exists") {
			logWarning(t, "Conflict response body did not contain expected 'already exists' message: %s", errResp.Error)
		}
	}
}

func TestReconfigureLabOwnerSucceeds(t *testing.T) {
	labName, userHeaders := setupEphemeralLab(t) // Lab exists

	logTest(t, "Attempting to reconfigure owned lab '%s' (expecting 200 OK)", labName)

	topology := strings.ReplaceAll(cfg.SimpleTopologyContent, "{lab_name}", labName)
	// Call createLab helper with reconfigure=true
	bodyBytes, statusCode, err := createLab(t, userHeaders, labName, topology, true, cfg.DeployTimeout)

	if err != nil {
		logError(t, "Failed to execute reconfigure owned lab request: %v", err)
		t.Fatalf("Failed to execute reconfigure owned lab request: %v", err)
	}

	// Assert the status code
	if statusCode != http.StatusOK {
		logError(t, "Expected status %d (OK) when reconfiguring owned lab, but got %d", http.StatusOK, statusCode)
		t.Errorf("Expected status %d (OK) when reconfiguring owned lab, but got %d. Body: %s", http.StatusOK, statusCode, string(bodyBytes))
	} else {
		logSuccess(t, "Reconfigure successful")
	}

	logDebug(t, "Pausing for stabilization...")
	time.Sleep(cfg.StabilizePause)
}

func TestReconfigureLabNonOwnerFails(t *testing.T) {
	// 1. Create a lab as superuser
	suLabName, _ := setupSuperuserLab(t) // Cleanup handled by setup

	// 2. Get headers for the regular apiuser
	apiUserToken := login(t, cfg.APIUserUser, cfg.APIUserPass)
	apiUserHeaders := getAuthHeaders(apiUserToken)

	// 3. Attempt to reconfigure the superuser's lab as apiuser
	logTest(t, "Attempting non-owner reconfigure on lab '%s' by user '%s' (expecting 403 Forbidden)",
		suLabName, cfg.APIUserUser)

	topology := strings.ReplaceAll(cfg.SimpleTopologyContent, "{lab_name}", suLabName)
	// Use the apiuser headers to attempt the reconfigure
	bodyBytes, statusCode, err := createLab(t, apiUserHeaders, suLabName, topology, true, cfg.DeployTimeout) // reconfigure=true

	if err != nil {
		logError(t, "Failed to execute non-owner reconfigure request: %v", err)
		t.Fatalf("Failed to execute non-owner reconfigure request: %v", err)
	}

	// Assert the status code
	if statusCode != http.StatusForbidden {
		logError(t, "Expected status %d (Forbidden) when non-owner reconfiguring lab, but got %d",
			http.StatusForbidden, statusCode)
		t.Errorf("Expected status %d (Forbidden) when non-owner reconfiguring lab, but got %d. Body: %s",
			http.StatusForbidden, statusCode, string(bodyBytes))
	} else {
		logSuccess(t, "Correctly received status %d (Forbidden) when non-owner reconfiguring lab", statusCode)
		// Optionally check error message in body
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(bodyBytes, &errResp) == nil && !strings.Contains(errResp.Error, "permission denied") {
			logWarning(t, "Forbidden response body did not contain expected 'permission denied' message: %s", errResp.Error)
		}
	}
}

func TestReconfigureLabSuperuserSucceeds(t *testing.T) {
	// 1. Create a lab as apiuser
	apiLabName, _ := setupEphemeralLab(t) // Cleanup handled by setup

	// 2. Get headers for the superuser
	superuserToken := login(t, cfg.SuperuserUser, cfg.SuperuserPass)
	superuserHeaders := getAuthHeaders(superuserToken)

	// 3. Attempt to reconfigure the apiuser's lab as superuser
	logTest(t, "Attempting superuser reconfigure on lab '%s' owned by '%s' (expecting 200 OK)",
		apiLabName, cfg.APIUserUser)

	topology := strings.ReplaceAll(cfg.SimpleTopologyContent, "{lab_name}", apiLabName)
	// Use the superuser headers to attempt the reconfigure
	bodyBytes, statusCode, err := createLab(t, superuserHeaders, apiLabName, topology, true, cfg.DeployTimeout) // reconfigure=true

	if err != nil {
		logError(t, "Failed to execute superuser reconfigure request: %v", err)
		t.Fatalf("Failed to execute superuser reconfigure request: %v", err)
	}

	// Assert the status code
	if statusCode != http.StatusOK {
		logError(t, "Expected status %d (OK) when superuser reconfiguring lab, but got %d", http.StatusOK, statusCode)
		t.Errorf("Expected status %d (OK) when superuser reconfiguring lab, but got %d. Body: %s",
			http.StatusOK, statusCode, string(bodyBytes))
	} else {
		logSuccess(t, "Superuser reconfigure successful")
	}

	logDebug(t, "Pausing for stabilization...")
	time.Sleep(cfg.StabilizePause)
}

func TestListLabsSuperuser(t *testing.T) {
	// Setup both types of labs concurrently
	apiLabName, _ := setupEphemeralLab(t)
	suLabName, superuserHeaders := setupSuperuserLab(t) // Need headers for the request

	logTest(t, "Verifying superuser sees labs '%s' (owned by %s) and '%s' (owned by %s)",
		apiLabName, cfg.APIUserUser, suLabName, cfg.SuperuserUser)

	listURL := fmt.Sprintf("%s/api/v1/labs", cfg.APIURL)
	// Use superuser headers for the request
	bodyBytes, statusCode, err := doRequest(t, "GET", listURL, superuserHeaders, nil, cfg.RequestTimeout)
	if err != nil {
		logError(t, "Failed to execute list labs request as superuser: %v", err)
		t.Fatalf("Failed to execute list labs request as superuser: %v", err)
	}

	if statusCode != http.StatusOK {
		logError(t, "Expected status %d listing labs as superuser, got %d", http.StatusOK, statusCode)
		t.Fatalf("Expected status %d listing labs as superuser, got %d. Body: %s",
			http.StatusOK, statusCode, string(bodyBytes))
	}

	var labsData ClabInspectOutput
	if err := json.Unmarshal(bodyBytes, &labsData); err != nil {
		logError(t, "Failed to unmarshal labs list response (superuser): %v", err)
		t.Fatalf("Failed to unmarshal labs list response (superuser): %v. Body: %s",
			err, string(bodyBytes))
	}

	foundAPILab := false
	if _, exists := labsData[apiLabName]; exists {
		foundAPILab = true
	}

	foundSULab := false
	if _, exists := labsData[suLabName]; exists {
		foundSULab = true
	}

	if !foundAPILab {
		logError(t, "Superuser should see lab '%s' created by apiuser, but it was not found", apiLabName)
		t.Errorf("Superuser should see lab '%s' created by apiuser, but it was not found", apiLabName)
	}
	if !foundSULab {
		logError(t, "Superuser should see lab '%s' created by superuser, but it was not found", suLabName)
		t.Errorf("Superuser should see lab '%s' created by superuser, but it was not found", suLabName)
	}

	if foundAPILab && foundSULab {
		logSuccess(t, "Superuser list check successful: Both labs found")
	}
}

func TestListLabsAPIUserFilters(t *testing.T) {
	// Setup both types of labs concurrently
	apiLabName, apiUserHeaders := setupEphemeralLab(t) // Need headers for the request
	suLabName, _ := setupSuperuserLab(t)

	logTest(t, "Verifying apiuser '%s' sees '%s' but NOT '%s'",
		cfg.APIUserUser, apiLabName, suLabName)

	listURL := fmt.Sprintf("%s/api/v1/labs", cfg.APIURL)
	// Use apiuser headers for the request
	bodyBytes, statusCode, err := doRequest(t, "GET", listURL, apiUserHeaders, nil, cfg.RequestTimeout)
	if err != nil {
		logError(t, "Failed to execute list labs request as apiuser: %v", err)
		t.Fatalf("Failed to execute list labs request as apiuser: %v", err)
	}

	if statusCode != http.StatusOK {
		logError(t, "Expected status %d listing labs as apiuser, got %d", http.StatusOK, statusCode)
		t.Fatalf("Expected status %d listing labs as apiuser, got %d. Body: %s",
			http.StatusOK, statusCode, string(bodyBytes))
	}

	var labsData ClabInspectOutput
	if err := json.Unmarshal(bodyBytes, &labsData); err != nil {
		logError(t, "Failed to unmarshal labs list response (apiuser): %v", err)
		t.Fatalf("Failed to unmarshal labs list response (apiuser): %v. Body: %s",
			err, string(bodyBytes))
	}

	foundAPILab := false
	if _, exists := labsData[apiLabName]; exists {
		foundAPILab = true
	}

	foundSULab := false
	if _, exists := labsData[suLabName]; exists {
		foundSULab = true
	}

	if !foundAPILab {
		logError(t, "Apiuser should see their own lab '%s', but it was not found", apiLabName)
		t.Errorf("Apiuser should see their own lab '%s', but it was not found", apiLabName)
	}
	if foundSULab {
		logError(t, "Apiuser should NOT see lab '%s' owned by superuser, but it was found", suLabName)
		t.Errorf("Apiuser should NOT see lab '%s' owned by superuser, but it was found", suLabName)
	}

	if foundAPILab && !foundSULab {
		logSuccess(t, "Apiuser list filtering check successful")
	}
}

// tests_go/version_test.go
package tests_go

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// TestVersionInfoEndpoint tests the version information API endpoint
func TestVersionInfoEndpoint(t *testing.T) {
	// This endpoint should be accessible without authentication
	logTest(t, "Testing version information endpoint")

	versionURL := fmt.Sprintf("%s/api/v1/version", cfg.APIURL)
	bodyBytes, statusCode, err := doRequest(t, "GET", versionURL, nil, nil, cfg.RequestTimeout)
	if err != nil {
		logError(t, "Failed to execute version request: %v", err)
		t.Fatalf("Failed to execute version request: %v", err)
	}

	if statusCode != http.StatusOK {
		logError(t, "Expected status %d for version endpoint, got %d", http.StatusOK, statusCode)
		t.Fatalf("Expected status %d for version endpoint, got %d. Body: %s",
			http.StatusOK, statusCode, string(bodyBytes))
	}

	// Verify we can parse the response as JSON
	var versionInfo struct {
		Version   string `json:"version"`
		BuildTime string `json:"buildTime"`
		GitCommit string `json:"gitCommit"`
	}

	if err := json.Unmarshal(bodyBytes, &versionInfo); err != nil {
		logError(t, "Failed to unmarshal version response: %v", err)
		t.Fatalf("Failed to unmarshal version response: %v. Body: %s", err, string(bodyBytes))
	}

	// Verify version info has expected fields
	if versionInfo.Version == "" {
		logError(t, "Version field is empty in response")
		t.Errorf("Version field is empty in response")
	}

	logSuccess(t, "Successfully retrieved version information: %s", versionInfo.Version)
}

// TestHealthCheckEndpoint tests the health check API endpoint
func TestHealthCheckEndpoint(t *testing.T) {
	// Health check endpoint should also be accessible without authentication
	logTest(t, "Testing health check endpoint")

	healthURL := fmt.Sprintf("%s/api/v1/health", cfg.APIURL)
	bodyBytes, statusCode, err := doRequest(t, "GET", healthURL, nil, nil, cfg.RequestTimeout)
	if err != nil {
		logError(t, "Failed to execute health check request: %v", err)
		t.Fatalf("Failed to execute health check request: %v", err)
	}

	if statusCode != http.StatusOK {
		logError(t, "Expected status %d for health check endpoint, got %d", http.StatusOK, statusCode)
		t.Fatalf("Expected status %d for health check endpoint, got %d. Body: %s",
			http.StatusOK, statusCode, string(bodyBytes))
	}

	// Verify we can parse the response as JSON
	var healthInfo struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(bodyBytes, &healthInfo); err != nil {
		logError(t, "Failed to unmarshal health check response: %v", err)
		t.Fatalf("Failed to unmarshal health check response: %v. Body: %s", err, string(bodyBytes))
	}

	// Check status field
	if healthInfo.Status != "ok" && healthInfo.Status != "healthy" {
		logError(t, "Health check status not reporting healthy: %s", healthInfo.Status)
		t.Errorf("Health check status not reporting healthy: %s", healthInfo.Status)
	} else {
		logSuccess(t, "Successfully confirmed API health status: %s", healthInfo.Status)
	}
}

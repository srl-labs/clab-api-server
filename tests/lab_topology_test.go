// tests_go/lab_topology_test.go
package tests_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestGenerateTopology tests the topology generation endpoint
func TestGenerateTopology(t *testing.T) {
	// Login as regular user
	apiUserToken := login(t, cfg.APIUserUser, cfg.APIUserPass)
	userHeaders := getAuthHeaders(apiUserToken)

	// Generate a unique lab name
	generatedLabName := fmt.Sprintf("%s-gen-%s", cfg.LabNamePrefix, randomSuffix(5))

	logTest(t, "Generating topology for lab '%s'", generatedLabName)

	// Create the generate request
	generateRequest := map[string]interface{}{
		"name": generatedLabName,
		"tiers": []map[string]interface{}{
			{
				"count": 2,
				"kind":  "linux",
			},
		},
		"images": map[string]string{
			"linux": "alpine:latest",
		},
		"deploy": false, // Don't deploy, just generate
	}

	jsonPayload, err := json.Marshal(generateRequest)
	if err != nil {
		logError(t, "Failed to marshal generate topology request: %v", err)
		t.Fatalf("Failed to marshal generate topology request: %v", err)
	}

	generateURL := fmt.Sprintf("%s/api/v1/generate", cfg.APIURL)
	bodyBytes, statusCode, err := doRequest(t, "POST", generateURL, userHeaders, bytes.NewBuffer(jsonPayload), cfg.RequestTimeout)
	if err != nil {
		logError(t, "Failed to execute generate topology request: %v", err)
		t.Fatalf("Failed to execute generate topology request: %v", err)
	}

	if statusCode != http.StatusOK {
		logError(t, "Expected status %d generating topology for '%s', got %d", http.StatusOK, generatedLabName, statusCode)
		t.Fatalf("Expected status %d generating topology for '%s', got %d. Body: %s", http.StatusOK, generatedLabName, statusCode, string(bodyBytes))
	}

	// Verify we can parse the response
	var generateResponse struct {
		Message      string `json:"message"`
		TopologyYAML string `json:"topologyYaml"`
	}

	if err := json.Unmarshal(bodyBytes, &generateResponse); err != nil {
		logError(t, "Failed to unmarshal generate topology response: %v", err)
		t.Fatalf("Failed to unmarshal generate topology response: %v. Body: %s", err, string(bodyBytes))
	}

	if generateResponse.TopologyYAML == "" {
		logError(t, "Generate topology response missing YAML content")
		t.Errorf("Generate topology response missing YAML content")
	} else if !strings.Contains(generateResponse.TopologyYAML, generatedLabName) {
		logError(t, "Generated topology YAML doesn't contain the lab name")
		t.Errorf("Generated topology YAML doesn't contain the lab name")
	} else {
		logSuccess(t, "Successfully generated topology for lab '%s'", generatedLabName)
	}
}

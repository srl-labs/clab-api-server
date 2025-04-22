// tests_go/lab_topology_suite_test.go
package tests_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
)

// LabTopologySuite tests topology generation endpoints.
type LabTopologySuite struct {
	BaseSuite
	apiUserToken   string
	apiUserHeaders http.Header
}

// TestLabTopologySuite runs the LabTopologySuite.
func TestLabTopologySuite(t *testing.T) {
	suite.Run(t, new(LabTopologySuite))
}

// SetupSuite logs in the API user.
func (s *LabTopologySuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	s.apiUserToken = s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(s.apiUserToken)
	s.Require().NotEmpty(s.apiUserToken)
}

// TestGenerateTopology tests the topology generation endpoint
func (s *LabTopologySuite) TestGenerateTopology() {
	// Use headers obtained in SetupSuite
	userHeaders := s.apiUserHeaders

	// Generate a unique lab name for the topology definition
	generatedLabName := fmt.Sprintf("%s-gen-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))

	s.logTest("Generating topology for lab '%s'", generatedLabName)

	// Create the generate request payload
	generateRequest := map[string]interface{}{
		"name": generatedLabName,
		"tiers": []map[string]interface{}{
			{
				"count": 2,
				"kind":  "linux",
			},
		},
		"images": map[string]string{
			"linux": "alpine:latest", // Example image
		},
		"deploy": false, // Don't deploy, just generate YAML
	}

	jsonPayload := s.mustMarshal(generateRequest)

	generateURL := fmt.Sprintf("%s/api/v1/generate", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("POST", generateURL, userHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute generate topology request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 generating topology for '%s'. Body: %s", generatedLabName, string(bodyBytes))

	// Verify we can parse the response
	var generateResponse struct {
		Message      string `json:"message"`
		TopologyYAML string `json:"topologyYaml"`
	}

	err = json.Unmarshal(bodyBytes, &generateResponse)
	s.Require().NoError(err, "Failed to unmarshal generate topology response. Body: %s", string(bodyBytes))

	s.Assert().NotEmpty(generateResponse.TopologyYAML, "Generate topology response missing YAML content")
	if generateResponse.TopologyYAML != "" { // Avoid panic on Contains if YAML is empty
		s.Assert().Contains(generateResponse.TopologyYAML, generatedLabName, "Generated topology YAML doesn't contain the lab name")
	}

	if !s.T().Failed() {
		s.logSuccess("Successfully generated topology for lab '%s'", generatedLabName)
	}
}

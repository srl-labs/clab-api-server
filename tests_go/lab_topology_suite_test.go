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
	apiUserHeaders http.Header
}

// TestLabTopologySuite runs the LabTopologySuite.
func TestLabTopologySuite(t *testing.T) {
	suite.Run(t, new(LabTopologySuite))
}

// SetupSuite logs in the API user.
func (s *LabTopologySuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	apiUserToken := s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(apiUserToken)
	s.Require().NotEmpty(apiUserToken)
}

// TestGenerateTopology tests the topology generation endpoint
func (s *LabTopologySuite) TestGenerateTopology() {
	// Use headers obtained in SetupSuite
	userHeaders := s.apiUserHeaders

	// Generate a unique lab name for the topology definition
	generatedLabName := fmt.Sprintf("3-tier-clos-%s", s.randomSuffix(5))

	s.logTest("Generating topology for lab '%s'", generatedLabName)

	// Create the generate request payload with the CLOS configuration
	generateRequest := map[string]interface{}{
		"name":        generatedLabName,
		"defaultKind": "nokia_srlinux",
		"deploy":      true,
		"groupPrefix": "clos-tier",
		"images": map[string]string{
			"nokia_srlinux": "ghcr.io/nokia/srlinux:latest",
		},
		"ipv4Subnet": "172.20.20.0/24",
		"ipv6Subnet": "2001:172:20:20::/64",
		"nodePrefix": "clos-node",
		"outputFile": fmt.Sprintf("tests_go/tmp/%s.yml", generatedLabName),
		"tiers": []map[string]interface{}{
			{
				"count": 4,
				"kind":  "nokia_srlinux",
				"type":  "ixrd3",
			},
		},
	}

	// Set up cleanup for the generated lab when deploy is true
	if generateRequest["deploy"].(bool) {
		defer s.cleanupLab(generatedLabName, true)
	}

	jsonPayload := s.mustMarshal(generateRequest)

	generateURL := fmt.Sprintf("%s/api/v1/generate", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("POST", generateURL, userHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute generate topology request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 generating topology for '%s'. Body: %s", generatedLabName, string(bodyBytes))

	// Verify we can parse the response - this should match the actual response structure
	var generateResponse struct {
		Message       string `json:"message"`
		DeployOutput  string `json:"deployOutput,omitempty"`
		SavedFilePath string `json:"savedFilePath,omitempty"`
	}

	err = json.Unmarshal(bodyBytes, &generateResponse)
	s.Require().NoError(err, "Failed to unmarshal generate topology response. Body: %s", string(bodyBytes))

	// Verify response fields based on whether deploy was true or false
	s.Assert().NotEmpty(generateResponse.Message, "Generate response missing message content")

	if generateRequest["deploy"].(bool) {
		// For deploy=true cases
		s.Assert().Contains(generateResponse.Message, "deployed successfully", "Response message should indicate successful deployment")
		s.Assert().NotEmpty(generateResponse.DeployOutput, "Response missing deployOutput for a deployed topology")
		s.Assert().NotEmpty(generateResponse.SavedFilePath, "Response missing savedFilePath for a deployed topology")

		// Verify the output contains references to the expected resources
		s.Assert().Contains(generateResponse.DeployOutput, generatedLabName, "Deploy output doesn't reference the lab name")
		s.Assert().Contains(generateResponse.DeployOutput, "nokia_srlinux", "Deploy output doesn't reference the node kind")
		s.Assert().Contains(generateResponse.DeployOutput, "clos-tier-1", "Deploy output doesn't reference the group prefix")
	} else {
		// The test for deploy=false would check for topologyYaml field
		var yamlResponse struct {
			Message      string `json:"message"`
			TopologyYAML string `json:"topologyYaml"`
		}

		// Verify the YAML contains correct configuration
		err = json.Unmarshal(bodyBytes, &yamlResponse)
		if err == nil && yamlResponse.TopologyYAML != "" {
			s.Assert().Contains(yamlResponse.TopologyYAML, generatedLabName, "Generated YAML doesn't contain the lab name")
			s.Assert().Contains(yamlResponse.TopologyYAML, "nokia_srlinux", "Generated YAML doesn't contain the node kind")
		}
	}

	if !s.T().Failed() {
		s.logSuccess("Successfully generated topology for lab '%s'", generatedLabName)
	}
}

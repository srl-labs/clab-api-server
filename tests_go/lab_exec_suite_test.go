// tests_go/lab_exec_suite_test.go
package tests_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
)

// LabExecSuite tests command execution within lab nodes.
type LabExecSuite struct {
	BaseSuite
	apiUserToken   string
	apiUserHeaders http.Header
}

// TestLabExecSuite runs the LabExecSuite
func TestLabExecSuite(t *testing.T) {
	suite.Run(t, new(LabExecSuite))
}

// SetupSuite logs in the API user.
func (s *LabExecSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	s.apiUserToken = s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(s.apiUserToken)
	s.Require().NotEmpty(s.apiUserToken)
}

func (s *LabExecSuite) TestExecCommandInLab() {
	labName, userHeaders := s.setupEphemeralLab()
	defer s.cleanupLab(labName, true)

	// Simple Linux command
	command := "hostname"
	payload := map[string]string{"command": command}
	jsonPayload := s.mustMarshal(payload)

	s.logTest("Executing command '%s' in lab '%s'", command, labName)

	execURL := fmt.Sprintf("%s/api/v1/labs/%s/exec", s.cfg.APIURL, labName)
	bodyBytes, statusCode, err := s.doRequest("POST", execURL, userHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute command request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 executing command in lab '%s'. Body: %s", labName, string(bodyBytes))

	// Verify we can parse the response as JSON (map of nodes to exec results)
	var execResults map[string]interface{} // Adjust type based on actual response structure if known
	err = json.Unmarshal(bodyBytes, &execResults)
	s.Require().NoError(err, "Failed to unmarshal exec command response. Body: %s", string(bodyBytes))

	s.Assert().NotEmpty(execResults, "Exec command in lab '%s' returned empty results, expected at least one node", labName)

	// Optionally, check the content of the results if the structure is known
	// For example, if it's map[string]struct{ Stdout string; Stderr string; ReturnCode int }
	// for nodeName, result := range execResults {
	//     var nodeResult struct { Stdout string }
	//     jsonData, _ := json.Marshal(result)
	//     json.Unmarshal(jsonData, &nodeResult)
	//     s.Assert().NotEmpty(nodeResult.Stdout, "Stdout for node %s should not be empty", nodeName)
	// }

	if !s.T().Failed() {
		s.logSuccess("Successfully executed command in lab '%s'", labName)
	}
}

func (s *LabExecSuite) TestPlainFormatExecCommandInLab() {
	labName, userHeaders := s.setupEphemeralLab()
	defer s.cleanupLab(labName, true)

	// Simple Linux command
	command := "echo 'plain format test'"
	payload := map[string]string{"command": command}
	jsonPayload := s.mustMarshal(payload)

	s.logTest("Executing command '%s' in lab '%s' with plain format", command, labName)

	execURL := fmt.Sprintf("%s/api/v1/labs/%s/exec?format=plain", s.cfg.APIURL, labName)
	bodyBytes, statusCode, err := s.doRequest("POST", execURL, userHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute plain format command request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 executing plain format command in lab '%s'. Body: %s", labName, string(bodyBytes))

	// Response should be plain text
	responseText := string(bodyBytes)
	s.Assert().NotEmpty(responseText, "Plain format exec command in lab '%s' returned empty output", labName)
	s.Assert().Contains(responseText, "plain format test", "Plain format exec command output does not contain expected string.")

	if !s.T().Failed() {
		s.logSuccess("Successfully executed plain format command in lab '%s'", labName)
	}
}

func (s *LabExecSuite) TestNodeFilteredExec() {
	labName, userHeaders := s.setupEphemeralLab()
	defer s.cleanupLab(labName, true)

	// Get the full node name from the lab
	s.logTest("Finding node name for lab '%s' to use in filtered exec test", labName)

	inspectURL := fmt.Sprintf("%s/api/v1/labs/%s", s.cfg.APIURL, labName)
	inspectBytes, inspectCode, inspectErr := s.doRequest("GET", inspectURL, userHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(inspectErr, "Failed to inspect lab to find node name")
	s.Require().Equal(http.StatusOK, inspectCode, "Failed to inspect lab. Status: %d, Body: %s", inspectCode, string(inspectBytes))

	var labContainers []struct {
		Name string `json:"name"`
	}
	err := json.Unmarshal(inspectBytes, &labContainers)
	s.Require().NoError(err, "Failed to unmarshal lab inspect response. Body: %s", string(inspectBytes))
	s.Require().NotEmpty(labContainers, "Lab '%s' doesn't have any containers", labName)

	nodeFilter := labContainers[0].Name // Use the first node found
	s.logTest("Executing command with node filter '%s' in lab '%s'", nodeFilter, labName)

	// Simple Linux command
	command := "echo 'node filtered test'"
	payload := map[string]string{"command": command}
	jsonPayload := s.mustMarshal(payload)

	execURL := fmt.Sprintf("%s/api/v1/labs/%s/exec?nodeFilter=%s", s.cfg.APIURL, labName, nodeFilter)
	bodyBytes, statusCode, err := s.doRequest("POST", execURL, userHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute filtered command request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 executing filtered command. Body: %s", string(bodyBytes))

	// Verify response contains only the filtered node
	var execResults map[string]interface{} // Adjust type if known
	err = json.Unmarshal(bodyBytes, &execResults)
	s.Require().NoError(err, "Failed to unmarshal filtered exec response. Body: %s", string(bodyBytes))

	s.Assert().Len(execResults, 1, "Filtered exec should return exactly 1 node")
	s.Assert().Contains(execResults, nodeFilter, "Filtered exec results don't contain the specified node '%s'", nodeFilter)

	if !s.T().Failed() {
		s.logSuccess("Successfully executed filtered command on node '%s'", nodeFilter)
	}
}

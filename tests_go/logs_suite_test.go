// tests_go/logs_suite_test.go
package tests_go

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// LogsSuite tests the logs endpoint for retrieving container logs
type LogsSuite struct {
	BaseSuite
	apiUserToken     string
	apiUserHeaders   http.Header
	superuserToken   string
	superuserHeaders http.Header

	// Shared test resources
	sharedLabName  string
	sharedNodeName string

	// Superuser resources
	suLabName  string
	suNodeName string
}

// TestLogsSuite runs the LogsSuite
func TestLogsSuite(t *testing.T) {
	suite.Run(t, new(LogsSuite))
}

// SetupSuite logs in users and creates the shared test resources
func (s *LogsSuite) SetupSuite() {
	s.BaseSuite.SetupSuite() // Call base setup

	// Login both users
	s.apiUserToken = s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(s.apiUserToken)
	s.superuserToken = s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass)
	s.superuserHeaders = s.getAuthHeaders(s.superuserToken)
	s.Require().NotEmpty(s.apiUserToken)
	s.Require().NotEmpty(s.superuserToken)

	// Create a shared lab for the API user tests
	s.sharedLabName = fmt.Sprintf("%s-logs-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	topology := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", s.sharedLabName)

	s.logSetup("Creating shared test lab: %s", s.sharedLabName)
	bodyBytes, statusCode, err := s.createLab(s.apiUserHeaders, s.sharedLabName, topology, false, s.cfg.DeployTimeout)
	s.Require().NoError(err, "SETUP Failed: Could not create shared test lab")
	s.Require().Equal(http.StatusOK, statusCode, "SETUP Failed: Could not create shared test lab. Body: %s", string(bodyBytes))

	// Get the first node name
	s.sharedNodeName, err = s.getFirstNodeName(s.sharedLabName, s.apiUserHeaders)
	s.Require().NoError(err, "SETUP Failed: Could not get node name from shared lab")
	s.Require().NotEmpty(s.sharedNodeName, "SETUP Failed: No nodes found in shared lab")
	s.logSetup("Using node '%s' for logs tests", s.sharedNodeName)

	// Create a lab for the superuser tests
	s.suLabName = fmt.Sprintf("%s-logs-su-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	suTopology := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", s.suLabName)

	s.logSetup("Creating superuser test lab: %s", s.suLabName)
	bodyBytes, statusCode, err = s.createLab(s.superuserHeaders, s.suLabName, suTopology, false, s.cfg.DeployTimeout)
	s.Require().NoError(err, "SETUP Failed: Could not create superuser test lab")
	s.Require().Equal(http.StatusOK, statusCode, "SETUP Failed: Could not create superuser test lab. Body: %s", string(bodyBytes))

	// Get the first node name in the superuser lab
	s.suNodeName, err = s.getFirstNodeName(s.suLabName, s.superuserHeaders)
	s.Require().NoError(err, "SETUP Failed: Could not get node name from superuser lab")
	s.Require().NotEmpty(s.suNodeName, "SETUP Failed: No nodes found in superuser lab")
	s.logSetup("Using node '%s' for superuser logs tests", s.suNodeName)

	// Wait for labs to stabilize
	s.logDebug("Pausing for lab stabilization...")
	time.Sleep(s.cfg.StabilizePause)
}

// TearDownSuite cleans up all test resources
func (s *LogsSuite) TearDownSuite() {
	// Clean up the superuser lab first - use superuser credentials
	if s.suLabName != "" {
		s.logTeardown("Cleaning up superuser test lab: %s", s.suLabName)
		_, _, err := s.destroyLab(s.superuserHeaders, s.suLabName, true, s.cfg.CleanupTimeout)
		if err != nil {
			s.logWarning("Error during superuser lab cleanup: %v", err)
		}
		time.Sleep(s.cfg.CleanupPause)
	}

	// Refresh the API user token to ensure it's valid
	s.apiUserToken = s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(s.apiUserToken)

	// Make a direct API call to check if the lab still exists
	if s.sharedLabName != "" {
		s.logTeardown("Cleaning up shared test lab: %s", s.sharedLabName)

		// Try to destroy with apiUserHeaders first (the owner)
		bodyBytes, statusCode, err := s.destroyLab(s.apiUserHeaders, s.sharedLabName, true, s.cfg.CleanupTimeout)
		if err == nil && statusCode == http.StatusOK {
			s.logTeardown("Successfully cleaned up shared test lab using API user credentials")
		} else {
			s.logWarning("Could not clean up lab with API user: %v, status: %d", err, statusCode)

			// If that fails, try with superuser credentials
			s.logTeardown("Attempting cleanup of shared test lab using superuser credentials")
			bodyBytes, statusCode, err = s.destroyLab(s.superuserHeaders, s.sharedLabName, true, s.cfg.CleanupTimeout)
			if err == nil && statusCode == http.StatusOK {
				s.logTeardown("Successfully cleaned up shared test lab using superuser credentials")
			} else {
				s.logWarning("Failed to clean up lab with superuser as well: %v, status: %d, body: %s",
					err, statusCode, string(bodyBytes))
			}
		}

		// Double check if the lab is really gone
		checkURL := fmt.Sprintf("%s/api/v1/labs/%s", s.cfg.APIURL, s.sharedLabName)
		_, checkStatus, _ := s.doRequest("GET", checkURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)
		if checkStatus != http.StatusNotFound {
			s.logWarning("Lab '%s' may still exist after cleanup attempts! Status: %d",
				s.sharedLabName, checkStatus)
		} else {
			s.logTeardown("Confirmed lab '%s' no longer exists", s.sharedLabName)
		}

		time.Sleep(s.cfg.CleanupPause)
	}

	s.BaseSuite.TearDownSuite()
}

// TearDownTest ensures we log any test failures properly
func (s *LogsSuite) TearDownTest() {
	if s.T().Failed() {
		s.logError("Test '%s' FAILED", s.T().Name())
	}
	s.BaseSuite.TearDownTest()
}

// TestBasicLogsRetrieval tests basic logs retrieval in plain format
func (s *LogsSuite) TestBasicLogsRetrieval() {
	s.logTest("Retrieving logs for node '%s' in lab '%s'", s.sharedNodeName, s.sharedLabName)
	logsURL := fmt.Sprintf("%s/api/v1/labs/%s/nodes/%s/logs", s.cfg.APIURL, s.sharedLabName, s.sharedNodeName)

	bodyBytes, statusCode, err := s.doRequest("GET", logsURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute logs request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for logs request. Body: %s", string(bodyBytes))

	// For plain text logs, the response should have Content-Type: text/plain
	s.logSuccess("Successfully retrieved logs for node '%s'", s.sharedNodeName)
}

// TestLogsRetrievalJSON tests logs retrieval in JSON format
func (s *LogsSuite) TestLogsRetrievalJSON() {
	s.logTest("Retrieving JSON format logs for node '%s' in lab '%s'", s.sharedNodeName, s.sharedLabName)

	logsURL := fmt.Sprintf("%s/api/v1/labs/%s/nodes/%s/logs?format=json", s.cfg.APIURL, s.sharedLabName, s.sharedNodeName)
	bodyBytes, statusCode, err := s.doRequest("GET", logsURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute JSON logs request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for JSON logs request. Body: %s", string(bodyBytes))

	// Verify we can parse the response as JSON
	var logsResp struct {
		ContainerName string `json:"containerName"`
		Logs          string `json:"logs"`
	}
	err = json.Unmarshal(bodyBytes, &logsResp)
	s.Require().NoError(err, "Failed to unmarshal JSON logs response")

	// Verify the container name in the response
	s.Assert().Equal(s.sharedNodeName, logsResp.ContainerName, "Container name in response should match requested node")

	s.logSuccess("Successfully retrieved JSON format logs for node '%s'", s.sharedNodeName)
}

// TestLogsRetrievalWithTail tests logs retrieval with tail parameter
func (s *LogsSuite) TestLogsRetrievalWithTail() {
	s.logTest("Retrieving logs with tail=10 for node '%s' in lab '%s'", s.sharedNodeName, s.sharedLabName)

	logsURL := fmt.Sprintf("%s/api/v1/labs/%s/nodes/%s/logs?tail=10", s.cfg.APIURL, s.sharedLabName, s.sharedNodeName)
	bodyBytes, statusCode, err := s.doRequest("GET", logsURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute tail logs request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for tail logs request. Body: %s", string(bodyBytes))

	s.logSuccess("Successfully retrieved logs with tail=10 for node '%s'", s.sharedNodeName)
}

// TestInvalidFormat tests error handling for an invalid format parameter
func (s *LogsSuite) TestInvalidFormat() {
	s.logTest("Testing logs endpoint with invalid format parameter (expecting 400 Bad Request)")

	logsURL := fmt.Sprintf("%s/api/v1/labs/%s/nodes/%s/logs?format=invalid", s.cfg.APIURL, s.sharedLabName, s.sharedNodeName)
	bodyBytes, statusCode, err := s.doRequest("GET", logsURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute invalid format logs request")

	s.Assert().Equal(http.StatusBadRequest, statusCode, "Expected status 400 for invalid format. Body: %s", string(bodyBytes))

	var errResp struct {
		Error string `json:"error"`
	}
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response")
	s.Assert().Contains(errResp.Error, "Invalid format", "Error message should mention invalid format")

	s.logSuccess("Correctly received status 400 for invalid format parameter")
}

// TestInvalidTail tests error handling for an invalid tail parameter
func (s *LogsSuite) TestInvalidTail() {
	s.logTest("Testing logs endpoint with invalid tail parameter (expecting 400 Bad Request)")

	// Invalid tail parameter (negative number)
	logsURL := fmt.Sprintf("%s/api/v1/labs/%s/nodes/%s/logs?tail=-10", s.cfg.APIURL, s.sharedLabName, s.sharedNodeName)
	bodyBytes, statusCode, err := s.doRequest("GET", logsURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute invalid tail logs request")

	s.Assert().Equal(http.StatusBadRequest, statusCode, "Expected status 400 for invalid tail parameter. Body: %s", string(bodyBytes))

	var errResp struct {
		Error string `json:"error"`
	}
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response")
	s.Assert().Contains(errResp.Error, "Invalid 'tail' parameter", "Error message should mention invalid tail parameter")

	s.logSuccess("Correctly received status 400 for invalid tail parameter")
}

// TestInvalidLabName tests error handling for invalid lab names
func (s *LogsSuite) TestInvalidLabName() {
	s.logTest("Testing logs endpoint with invalid lab name (expecting 400 Bad Request)")

	invalidLabName := "invalid*lab@name"
	logsURL := fmt.Sprintf("%s/api/v1/labs/%s/nodes/%s/logs", s.cfg.APIURL, invalidLabName, s.sharedNodeName)
	bodyBytes, statusCode, err := s.doRequest("GET", logsURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute invalid lab name logs request")

	s.Assert().Equal(http.StatusBadRequest, statusCode, "Expected status 400 for invalid lab name. Body: %s", string(bodyBytes))

	var errResp struct {
		Error string `json:"error"`
	}
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response")
	s.Assert().Contains(errResp.Error, "Invalid", "Error message should mention invalid characters")

	s.logSuccess("Correctly received status 400 for invalid lab name")
}

// TestInvalidNodeName tests error handling for invalid node names
func (s *LogsSuite) TestInvalidNodeName() {
	s.logTest("Testing logs endpoint with invalid node name (expecting 400 Bad Request)")

	invalidNodeName := "invalid*node@name"
	logsURL := fmt.Sprintf("%s/api/v1/labs/%s/nodes/%s/logs", s.cfg.APIURL, s.sharedLabName, invalidNodeName)
	bodyBytes, statusCode, err := s.doRequest("GET", logsURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute invalid node name logs request")

	s.Assert().Equal(http.StatusBadRequest, statusCode, "Expected status 400 for invalid node name. Body: %s", string(bodyBytes))

	var errResp struct {
		Error string `json:"error"`
	}
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response")
	s.Assert().Contains(errResp.Error, "Invalid", "Error message should mention invalid container name")

	s.logSuccess("Correctly received status 400 for invalid node name")
}

// TestLabNotFound tests error handling for non-existent labs
func (s *LogsSuite) TestLabNotFound() {
	s.logTest("Testing logs endpoint with non-existent lab (expecting 404)")

	nonExistentLab := "non-existent-lab-" + s.randomSuffix(5)
	logsURL := fmt.Sprintf("%s/api/v1/labs/%s/nodes/%s/logs", s.cfg.APIURL, nonExistentLab, s.sharedNodeName)
	bodyBytes, statusCode, err := s.doRequest("GET", logsURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute non-existent lab logs request")

	s.Assert().Equal(http.StatusNotFound, statusCode,
		"Expected status 404 for non-existent lab. Got: %d, Body: %s", statusCode, string(bodyBytes))

	var errResp struct {
		Error string `json:"error"`
	}
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response")
	s.Assert().Contains(errResp.Error, "not found", "Error message should mention lab not found")

	s.logSuccess("Correctly received status 404 for non-existent lab")
}

// TestNodeNotFound tests error handling for non-existent nodes in existing labs
func (s *LogsSuite) TestNodeNotFound() {
	s.logTest("Testing logs endpoint with non-existent node in existing lab (expecting 404 Not Found)")

	nonExistentNode := "clab-" + s.sharedLabName + "-nonexistent" + s.randomSuffix(5)
	logsURL := fmt.Sprintf("%s/api/v1/labs/%s/nodes/%s/logs", s.cfg.APIURL, s.sharedLabName, nonExistentNode)
	bodyBytes, statusCode, err := s.doRequest("GET", logsURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute non-existent node logs request")

	s.Assert().Equal(http.StatusNotFound, statusCode,
		"Expected status 404 for non-existent node. Got: %d, Body: %s", statusCode, string(bodyBytes))

	var errResp struct {
		Error string `json:"error"`
	}
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response")
	s.Assert().Contains(errResp.Error, "not found", "Error message should mention node not found")

	s.logSuccess("Correctly received status 404 for non-existent node")
}

// TestNonOwnerAccess tests that a user cannot access logs of a lab they don't own
func (s *LogsSuite) TestNonOwnerAccess() {
	s.logTest("Testing logs endpoint for non-owner access (expecting 404)")

	// Try to access the logs of superuser's lab as a regular user
	logsURL := fmt.Sprintf("%s/api/v1/labs/%s/nodes/%s/logs", s.cfg.APIURL, s.suLabName, s.suNodeName)
	bodyBytes, statusCode, err := s.doRequest("GET", logsURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute non-owner logs request")

	s.Assert().Equal(http.StatusNotFound, statusCode,
		"Expected status 404 for non-owner access. Got: %d, Body: %s", statusCode, string(bodyBytes))

	var errResp struct {
		Error string `json:"error"`
	}
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response")
	s.Assert().Contains(errResp.Error, "not found", "Error message should mention lab not found or not owned")

	s.logSuccess("Correctly received status 404 when non-owner tries to access logs")
}

// TestSuperuserAccess tests that a superuser can access logs of any lab
func (s *LogsSuite) TestSuperuserAccess() {
	s.logTest("Testing logs endpoint for superuser access to API user's lab")

	// Try to access the logs of API user's lab as superuser
	logsURL := fmt.Sprintf("%s/api/v1/labs/%s/nodes/%s/logs", s.cfg.APIURL, s.sharedLabName, s.sharedNodeName)
	bodyBytes, statusCode, err := s.doRequest("GET", logsURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute superuser logs request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for superuser logs access. Body: %s", string(bodyBytes))

	s.logSuccess("Successfully accessed API user's lab logs as superuser")
}

// TestMismatchedLabNode tests error handling when container name doesn't match lab name
func (s *LogsSuite) TestMismatchedLabNode() {
	s.logTest("Testing logs endpoint with container from different lab (expecting 400 Bad Request)")

	// Try to access the logs of superuser's node but in the context of apiUser's lab
	// This should fail because the node name (clab-suLabName-xyz) doesn't match the lab name (sharedLabName)
	logsURL := fmt.Sprintf("%s/api/v1/labs/%s/nodes/%s/logs", s.cfg.APIURL, s.sharedLabName, s.suNodeName)
	bodyBytes, statusCode, err := s.doRequest("GET", logsURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute mismatched lab/node logs request")

	s.Assert().Equal(http.StatusBadRequest, statusCode, "Expected status 400 for mismatched lab/node. Body: %s", string(bodyBytes))

	var errResp struct {
		Error string `json:"error"`
	}
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response")
	s.Assert().Contains(errResp.Error, "not belong", "Error message should mention container not belonging to lab")

	s.logSuccess("Correctly received status 400 for container from different lab")
}

// getFirstNodeName is a helper to get the first node name from a lab
func (s *LogsSuite) getFirstNodeName(labName string, headers http.Header) (string, error) {
	inspectURL := fmt.Sprintf("%s/api/v1/labs/%s", s.cfg.APIURL, labName)
	bodyBytes, statusCode, err := s.doRequest("GET", inspectURL, headers, nil, s.cfg.RequestTimeout)
	if err != nil {
		return "", fmt.Errorf("failed to inspect lab: %w", err)
	}

	if statusCode != http.StatusOK {
		return "", fmt.Errorf("failed to inspect lab, status code: %d", statusCode)
	}

	var labContainers []struct {
		Name string `json:"name"`
	}
	err = json.Unmarshal(bodyBytes, &labContainers)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal lab inspect response: %w", err)
	}

	if len(labContainers) == 0 {
		return "", fmt.Errorf("no containers found in lab '%s'", labName)
	}

	return labContainers[0].Name, nil
}

// tests_go/lab_core_suite_test.go
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

// LabCoreSuite tests core lab lifecycle and access control endpoints
type LabCoreSuite struct {
	BaseSuite
	apiUserToken     string
	apiUserHeaders   http.Header
	superuserToken   string
	superuserHeaders http.Header
}

// TestLabCoreSuite runs the LabCoreSuite
func TestLabCoreSuite(t *testing.T) {
	suite.Run(t, new(LabCoreSuite))
}

// SetupSuite logs in users needed for the tests in this suite
func (s *LabCoreSuite) SetupSuite() {
	s.BaseSuite.SetupSuite() // Call base setup
	s.apiUserToken = s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(s.apiUserToken)
	s.superuserToken = s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass)
	s.superuserHeaders = s.getAuthHeaders(s.superuserToken)
	s.Require().NotEmpty(s.apiUserToken)
	s.Require().NotEmpty(s.superuserToken)
}

func (s *LabCoreSuite) TestListLabsIncludesCreated() {
	labName, userHeaders := s.setupEphemeralLab()
	defer s.cleanupLab(labName, true) // Register cleanup using superuser

	s.logTest("Verifying lab '%s' is in the list for the owner (%s)", labName, s.cfg.APIUserUser)

	listURL := fmt.Sprintf("%s/api/v1/labs", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", listURL, userHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute list labs request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 listing labs. Body: %s", string(bodyBytes))

	var labsData ClabInspectOutput
	err = json.Unmarshal(bodyBytes, &labsData)
	s.Require().NoError(err, "Failed to unmarshal labs list response. Body: %s", string(bodyBytes))

	s.Assert().Contains(labsData, labName, "Lab '%s' created by setup was not found in /api/v1/labs output for the user", labName)
	if nodes, exists := labsData[labName]; exists {
		s.Assert().NotEmpty(nodes, "Lab '%s' should have container entries in the list", labName)
	}

	if !s.T().Failed() {
		s.logSuccess("Lab '%s' found in list", labName)
	}
}

func (s *LabCoreSuite) TestInspectCreatedLab() {
	labName, userHeaders := s.setupEphemeralLab()
	defer s.cleanupLab(labName, true)

	s.logTest("Inspecting details for lab '%s'", labName)
	inspectURL := fmt.Sprintf("%s/api/v1/labs/%s", s.cfg.APIURL, labName)
	bodyBytes, statusCode, err := s.doRequest("GET", inspectURL, userHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute inspect lab request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 inspecting lab '%s'. Body: %s", labName, string(bodyBytes))

	var labDetails []ClabContainerInfo
	err = json.Unmarshal(bodyBytes, &labDetails)
	s.Require().NoError(err, "Failed to unmarshal inspect response. Body: %s", string(bodyBytes))

	s.Require().NotEmpty(labDetails, "Inspect output for lab '%s' should contain container details, but was empty", labName)
	s.Assert().Equal(labName, labDetails[0].LabName, "Expected lab name '%s' in inspect details, got '%s'", labName, labDetails[0].LabName)

	if !s.T().Failed() {
		s.logSuccess("Inspection successful for '%s'", labName)
	}
}

func (s *LabCoreSuite) TestCreateDuplicateLabFails() {
	labName, userHeaders := s.setupEphemeralLab() // Lab exists now
	defer s.cleanupLab(labName, true)

	s.logTest("Attempting to create duplicate lab '%s' (expecting 409 Conflict)", labName)

	topology := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", labName)
	// Call createLab helper, check status code directly
	bodyBytes, statusCode, err := s.createLab(userHeaders, labName, topology, false, s.cfg.DeployTimeout) // reconfigure=false

	s.Require().NoError(err, "Failed to execute create duplicate lab request") // Check transport errors

	// Assert the status code
	s.Assert().Equal(http.StatusConflict, statusCode, "Expected status 409 (Conflict) when creating duplicate lab. Body: %s", string(bodyBytes))

	if statusCode == http.StatusConflict {
		s.logSuccess("Correctly received status %d (Conflict) when creating duplicate lab", statusCode)
		// Optionally check error message in body
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(bodyBytes, &errResp) == nil {
			s.Assert().Contains(strings.ToLower(errResp.Error), "already exists", "Conflict response body should contain 'already exists'")
		} else {
			s.logWarning("Could not unmarshal conflict response body: %s", string(bodyBytes))
		}
	}
}

func (s *LabCoreSuite) TestReconfigureLabOwnerSucceeds() {
	labName, userHeaders := s.setupEphemeralLab() // Lab exists
	defer s.cleanupLab(labName, true)

	s.logTest("Attempting to reconfigure owned lab '%s' (expecting 200 OK)", labName)

	topology := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", labName)
	// Call createLab helper with reconfigure=true
	bodyBytes, statusCode, err := s.createLab(userHeaders, labName, topology, true, s.cfg.DeployTimeout)

	s.Require().NoError(err, "Failed to execute reconfigure owned lab request")
	s.Assert().Equal(http.StatusOK, statusCode, "Expected status 200 (OK) when reconfiguring owned lab. Body: %s", string(bodyBytes))

	if statusCode == http.StatusOK {
		s.logSuccess("Reconfigure successful")
	}

	s.logDebug("Pausing for stabilization...")
	time.Sleep(s.cfg.StabilizePause)
}

func (s *LabCoreSuite) TestReconfigureLabNonOwnerFails() {
	// 1. Create a lab as superuser
	suLabName, _ := s.setupSuperuserLab()
	defer s.cleanupLab(suLabName, true) // Cleanup using superuser creds

	// 2. Use headers for the regular apiuser (obtained in SetupSuite)
	apiUserHeaders := s.apiUserHeaders

	// 3. Attempt to reconfigure the superuser's lab as apiuser
	s.logTest("Attempting non-owner reconfigure on lab '%s' by user '%s' (expecting 403 Forbidden)",
		suLabName, s.cfg.APIUserUser)

	topology := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", suLabName)
	// Use the apiuser headers to attempt the reconfigure
	bodyBytes, statusCode, err := s.createLab(apiUserHeaders, suLabName, topology, true, s.cfg.DeployTimeout) // reconfigure=true

	s.Require().NoError(err, "Failed to execute non-owner reconfigure request")

	// Assert the status code
	s.Assert().Equal(http.StatusForbidden, statusCode, "Expected status 403 (Forbidden) when non-owner reconfiguring lab. Body: %s", string(bodyBytes))

	if statusCode == http.StatusForbidden {
		s.logSuccess("Correctly received status %d (Forbidden) when non-owner reconfiguring lab", statusCode)
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(bodyBytes, &errResp) == nil {
			s.Assert().Contains(strings.ToLower(errResp.Error), "permission denied", "Forbidden response body should contain 'permission denied'")
		} else {
			s.logWarning("Could not unmarshal forbidden response body: %s", string(bodyBytes))
		}
	}
}

func (s *LabCoreSuite) TestReconfigureLabSuperuserSucceeds() {
	// 1. Create a lab as apiuser
	apiLabName, _ := s.setupEphemeralLab()
	defer s.cleanupLab(apiLabName, true) // Cleanup using superuser creds

	// 2. Use headers for the superuser (obtained in SetupSuite)
	superuserHeaders := s.superuserHeaders

	// 3. Attempt to reconfigure the apiuser's lab as superuser
	s.logTest("Attempting superuser reconfigure on lab '%s' owned by '%s' (expecting 200 OK)",
		apiLabName, s.cfg.APIUserUser)

	topology := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", apiLabName)
	// Use the superuser headers to attempt the reconfigure
	bodyBytes, statusCode, err := s.createLab(superuserHeaders, apiLabName, topology, true, s.cfg.DeployTimeout) // reconfigure=true

	s.Require().NoError(err, "Failed to execute superuser reconfigure request")

	// Assert the status code
	s.Assert().Equal(http.StatusOK, statusCode, "Expected status 200 (OK) when superuser reconfiguring lab. Body: %s", string(bodyBytes))

	if statusCode == http.StatusOK {
		s.logSuccess("Superuser reconfigure successful")
	}

	s.logDebug("Pausing for stabilization...")
	time.Sleep(s.cfg.StabilizePause)
}

func (s *LabCoreSuite) TestListLabsSuperuser() {
	// Setup both types of labs
	apiLabName, _ := s.setupEphemeralLab()
	defer s.cleanupLab(apiLabName, true)
	suLabName, superuserHeaders := s.setupSuperuserLab()
	defer s.cleanupLab(suLabName, true)

	s.logTest("Verifying superuser sees labs '%s' (owned by %s) and '%s' (owned by %s)",
		apiLabName, s.cfg.APIUserUser, suLabName, s.cfg.SuperuserUser)

	listURL := fmt.Sprintf("%s/api/v1/labs", s.cfg.APIURL)
	// Use superuser headers for the request
	bodyBytes, statusCode, err := s.doRequest("GET", listURL, superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute list labs request as superuser")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 listing labs as superuser. Body: %s", string(bodyBytes))

	var labsData ClabInspectOutput
	err = json.Unmarshal(bodyBytes, &labsData)
	s.Require().NoError(err, "Failed to unmarshal labs list response (superuser). Body: %s", string(bodyBytes))

	s.Assert().Contains(labsData, apiLabName, "Superuser should see lab '%s' created by apiuser", apiLabName)
	s.Assert().Contains(labsData, suLabName, "Superuser should see lab '%s' created by superuser", suLabName)

	if s.Assert().Contains(labsData, apiLabName) && s.Assert().Contains(labsData, suLabName) {
		s.logSuccess("Superuser list check successful: Both labs found")
	}
}

func (s *LabCoreSuite) TestListLabsAPIUserFilters() {
	// Setup both types of labs
	apiLabName, apiUserHeaders := s.setupEphemeralLab()
	defer s.cleanupLab(apiLabName, true)
	suLabName, _ := s.setupSuperuserLab()
	defer s.cleanupLab(suLabName, true)

	s.logTest("Verifying apiuser '%s' sees '%s' but NOT '%s'",
		s.cfg.APIUserUser, apiLabName, suLabName)

	listURL := fmt.Sprintf("%s/api/v1/labs", s.cfg.APIURL)
	// Use apiuser headers for the request
	bodyBytes, statusCode, err := s.doRequest("GET", listURL, apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute list labs request as apiuser")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 listing labs as apiuser. Body: %s", string(bodyBytes))

	var labsData ClabInspectOutput
	err = json.Unmarshal(bodyBytes, &labsData)
	s.Require().NoError(err, "Failed to unmarshal labs list response (apiuser). Body: %s", string(bodyBytes))

	s.Assert().Contains(labsData, apiLabName, "Apiuser should see their own lab '%s'", apiLabName)
	s.Assert().NotContains(labsData, suLabName, "Apiuser should NOT see lab '%s' owned by superuser", suLabName)

	if s.Assert().Contains(labsData, apiLabName) && s.Assert().NotContains(labsData, suLabName) {
		s.logSuccess("Apiuser list filtering check successful")
	}
}

func (s *LabCoreSuite) TestNonOwnerAccessLab() {
	// Create a lab as the superuser
	suLabName, _ := s.setupSuperuserLab()
	defer s.cleanupLab(suLabName, true)

	// Try to access it as the regular apiuser
	apiUserHeaders := s.apiUserHeaders // Use headers from SetupSuite

	s.logTest("Attempting to access lab '%s' as non-owner user '%s' (expecting 404)",
		suLabName, s.cfg.APIUserUser)

	inspectURL := fmt.Sprintf("%s/api/v1/labs/%s", s.cfg.APIURL, suLabName)
	bodyBytes, statusCode, err := s.doRequest("GET", inspectURL, apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute non-owner inspect request")

	// Non-owners should get 404 Not Found for security (hide existence)
	s.Assert().Equal(http.StatusNotFound, statusCode, "Expected status 404 (Not Found) when non-owner inspects lab. Body: %s", string(bodyBytes))

	if statusCode == http.StatusNotFound {
		s.logSuccess("Correctly received status %d (Not Found) when non-owner tries to access a lab", statusCode)
	}
}

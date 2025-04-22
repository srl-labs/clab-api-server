// tests_go/lab_config_suite_test.go
package tests_go

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
)

// LabConfigSuite tests lab configuration related endpoints like interfaces and save.
type LabConfigSuite struct {
	BaseSuite
	apiUserToken     string
	apiUserHeaders   http.Header
	superuserToken   string
	superuserHeaders http.Header
}

// TestLabConfigSuite runs the LabConfigSuite
func TestLabConfigSuite(t *testing.T) {
	suite.Run(t, new(LabConfigSuite))
}

// SetupSuite logs in users needed for the tests in this suite
func (s *LabConfigSuite) SetupSuite() {
	s.BaseSuite.SetupSuite() // Call base setup
	s.apiUserToken = s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(s.apiUserToken)
	s.superuserToken = s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass)
	s.superuserHeaders = s.getAuthHeaders(s.superuserToken)
	s.Require().NotEmpty(s.apiUserToken)
	s.Require().NotEmpty(s.superuserToken)
}

func (s *LabConfigSuite) TestInspectLabInterfaces() {
	labName, userHeaders := s.setupEphemeralLab()
	defer s.cleanupLab(labName, true)

	s.logTest("Inspecting interfaces for lab '%s'", labName)

	interfacesURL := fmt.Sprintf("%s/api/v1/labs/%s/interfaces", s.cfg.APIURL, labName)
	bodyBytes, statusCode, err := s.doRequest("GET", interfacesURL, userHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute inspect interfaces request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 inspecting interfaces for lab '%s'. Body: %s", labName, string(bodyBytes))

	// Verify we can parse the response as JSON array
	var interfacesList []interface{}
	err = json.Unmarshal(bodyBytes, &interfacesList)
	s.Require().NoError(err, "Failed to unmarshal inspect interfaces response. Body: %s", string(bodyBytes))

	// Check if the list is not empty (assuming a simple lab has at least one node with interfaces)
	s.Assert().NotEmpty(interfacesList, "Inspect interfaces for lab '%s' returned empty array, expected at least one node", labName)

	if !s.T().Failed() {
		s.logSuccess("Successfully retrieved interfaces for lab '%s'", labName)
	}
}

func (s *LabConfigSuite) TestSaveLabConfig() {
	labName, userHeaders := s.setupEphemeralLab()
	defer s.cleanupLab(labName, true)

	s.logTest("Saving configuration for lab '%s'", labName)

	saveURL := fmt.Sprintf("%s/api/v1/labs/%s/save", s.cfg.APIURL, labName)
	bodyBytes, statusCode, err := s.doRequest("POST", saveURL, userHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute save config request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 saving config for lab '%s'. Body: %s", labName, string(bodyBytes))

	// Verify we can parse the response
	var saveResponse struct {
		Message string `json:"message"`
		Output  string `json:"output"` // Assuming there might be an output field
	}

	err = json.Unmarshal(bodyBytes, &saveResponse)
	s.Require().NoError(err, "Failed to unmarshal save config response. Body: %s", string(bodyBytes))

	s.Assert().NotEmpty(saveResponse.Message, "Save config response missing message field")
	// s.Assert().NotEmpty(saveResponse.Output, "Save config response missing output field") // Optional: check if output is expected

	if !s.T().Failed() {
		s.logSuccess("Successfully saved configuration for lab '%s'", labName)
	}
}

func (s *LabConfigSuite) TestAccessLabInterfacesSuperuser() {
	// Create a lab as the regular user
	apiLabName, _ := s.setupEphemeralLab()
	defer s.cleanupLab(apiLabName, true)

	// Access it as the superuser using headers from SetupSuite
	superuserHeaders := s.superuserHeaders

	s.logTest("Accessing interfaces for lab '%s' as superuser '%s'",
		apiLabName, s.cfg.SuperuserUser)

	interfacesURL := fmt.Sprintf("%s/api/v1/labs/%s/interfaces", s.cfg.APIURL, apiLabName)
	bodyBytes, statusCode, err := s.doRequest("GET", interfacesURL, superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute superuser lab interfaces request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for superuser accessing lab interfaces. Body: %s", string(bodyBytes))

	// Verify we can parse the response as JSON
	var interfacesList []interface{}
	err = json.Unmarshal(bodyBytes, &interfacesList)
	s.Require().NoError(err, "Failed to unmarshal superuser lab interfaces response. Body: %s", string(bodyBytes))

	s.Assert().NotEmpty(interfacesList, "Superuser should be able to retrieve interfaces for lab '%s'", apiLabName)

	if !s.T().Failed() {
		s.logSuccess("Superuser successfully accessed interfaces for lab '%s' owned by '%s'",
			apiLabName, s.cfg.APIUserUser)
	}
}

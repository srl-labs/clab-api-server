// tests_go/lab_network_suite_test.go
package tests_go

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
)

// LabNetworkSuite tests lab network inspection endpoints.
type LabNetworkSuite struct {
	BaseSuite
	apiUserToken   string
	apiUserHeaders http.Header
}

// TestLabNetworkSuite runs the LabNetworkSuite.
func TestLabNetworkSuite(t *testing.T) {
	suite.Run(t, new(LabNetworkSuite))
}

// SetupSuite logs in the API user.
func (s *LabNetworkSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	s.apiUserToken = s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(s.apiUserToken)
	s.Require().NotEmpty(s.apiUserToken)
}

// TestInspectLabNetworkInterfaces tests the endpoint for listing network interfaces.
// Note: This seems identical to TestInspectLabInterfaces in lab_config_test.go.
// Consider consolidating if they test the exact same endpoint and behavior.
// Keeping it separate for now as per the original file structure.
func (s *LabNetworkSuite) TestInspectLabNetworkInterfaces() {
	labName, userHeaders := s.setupEphemeralLab()
	defer s.cleanupLab(labName, true)

	s.logTest("Inspecting network interfaces for lab '%s'", labName)

	interfacesURL := fmt.Sprintf("%s/api/v1/labs/%s/interfaces", s.cfg.APIURL, labName)
	bodyBytes, statusCode, err := s.doRequest("GET", interfacesURL, userHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute inspect network interfaces request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 inspecting network interfaces for lab '%s'. Body: %s", labName, string(bodyBytes))

	// Verify we can parse the response as JSON array
	var interfacesList []interface{} // Use a more specific type if the structure is known
	err = json.Unmarshal(bodyBytes, &interfacesList)
	s.Require().NoError(err, "Failed to unmarshal inspect network interfaces response. Body: %s", string(bodyBytes))

	s.Assert().NotEmpty(interfacesList, "Inspect network interfaces for lab '%s' returned empty array, expected at least one interface", labName)

	if !s.T().Failed() {
		s.logSuccess("Successfully retrieved network interfaces for lab '%s'", labName)
	}
}

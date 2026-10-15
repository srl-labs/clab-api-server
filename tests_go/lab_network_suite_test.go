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

// TestListLabLinks verifies that the links endpoint pairs up the veth ends of
// the test topology's srl1:eth1 <-> srl2:eth1 link.
func (s *LabNetworkSuite) TestListLabLinks() {
	labName, userHeaders := s.setupEphemeralLab()
	defer s.cleanupLab(labName, true)

	type endpoint struct {
		Namespace string `json:"namespace"`
		Node      string `json:"node"`
		Interface string `json:"interface"`
	}
	type link struct {
		Type string   `json:"type"`
		A    endpoint `json:"a"`
		B    endpoint `json:"b"`
	}

	listLinks := func(query string) []link {
		linksURL := fmt.Sprintf("%s/api/v1/labs/%s/links%s", s.cfg.APIURL, labName, query)
		bodyBytes, statusCode, err := s.doRequest("GET", linksURL, userHeaders, nil, s.cfg.RequestTimeout)
		s.Require().NoError(err, "Failed to execute list links request")
		s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 listing links for lab '%s'. Body: %s", labName, string(bodyBytes))
		var links []link
		s.Require().NoError(json.Unmarshal(bodyBytes, &links), "Failed to unmarshal links response. Body: %s", string(bodyBytes))
		return links
	}

	s.logTest("Listing links for lab '%s'", labName)
	links := listLinks("")
	found := 0
	for _, l := range links {
		if l.Type == "veth" && l.A.Node == "srl1" && l.A.Interface == "eth1" && l.B.Node == "srl2" && l.B.Interface == "eth1" {
			found++
		}
		s.Assert().Equal("node", l.A.Namespace, "Endpoint A must be a lab node: %+v", l)
		s.Assert().False(l.B.Node == "srl1" && l.B.Interface == "eth1", "srl1:eth1 listed as endpoint B: %+v", l)
	}
	s.Assert().Equal(1, found, "Expected exactly one srl1:eth1 <-> srl2:eth1 link, got %+v", links)

	for _, l := range listLinks("?node=srl2") {
		s.Assert().True(l.A.Node == "srl2" || l.B.Node == "srl2", "Node filter returned unrelated link: %+v", l)
	}

	bodyBytes, statusCode, err := s.doRequest("GET", fmt.Sprintf("%s/api/v1/labs/%s/links?node=%s", s.cfg.APIURL, labName, "bad%20node"), userHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Assert().Equal(http.StatusBadRequest, statusCode, "Expected 400 for invalid node filter. Body: %s", string(bodyBytes))

	if !s.T().Failed() {
		s.logSuccess("Links of lab '%s' resolved correctly", labName)
	}
}

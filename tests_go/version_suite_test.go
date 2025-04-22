// tests_go/version_suite_test.go
package tests_go

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

// VersionSuite tests unauthenticated endpoints like version and health.
type VersionSuite struct {
	BaseSuite
}

// TestVersionSuite runs the VersionSuite.
func TestVersionSuite(t *testing.T) {
	suite.Run(t, new(VersionSuite))
}

// TestVersionInfoEndpoint tests the version information API endpoint.
func (s *VersionSuite) TestVersionInfoEndpoint() {
	s.logTest("Testing version information endpoint")

	// Get auth token for the API user
	apiUserToken := s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	userHeaders := s.getAuthHeaders(apiUserToken)

	versionURL := fmt.Sprintf("%s/api/v1/version", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", versionURL, userHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute version request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for version endpoint. Body: %s", string(bodyBytes))

	// Verify we can parse the response as JSON
	var versionResp struct {
		VersionInfo string `json:"versionInfo"`
	}

	err = json.Unmarshal(bodyBytes, &versionResp)
	s.Require().NoError(err, "Failed to unmarshal version response. Body: %s", string(bodyBytes))

	// Verify version info field is not empty
	s.Assert().NotEmpty(versionResp.VersionInfo, "VersionInfo field is empty in response")

	// Basic sanity check - containerlab version output should contain "containerlab"
	s.Assert().Contains(strings.ToLower(versionResp.VersionInfo), "containerlab",
		"VersionInfo doesn't appear to contain containerlab version information")

	if !s.T().Failed() {
		s.logSuccess("Successfully retrieved version information: %s", versionResp.VersionInfo)
	}
}

// TestCheckVersionEndpoint tests the version check API endpoint.
func (s *VersionSuite) TestCheckVersionEndpoint() {
	s.logTest("Testing version check endpoint")

	// Get auth token for the API user
	apiUserToken := s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	userHeaders := s.getAuthHeaders(apiUserToken)

	versionCheckURL := fmt.Sprintf("%s/api/v1/version/check", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", versionCheckURL, userHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute version check request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for version check endpoint. Body: %s", string(bodyBytes))

	// Verify we can parse the response as JSON
	var checkResp struct {
		CheckResult string `json:"checkResult"`
	}

	err = json.Unmarshal(bodyBytes, &checkResp)
	s.Require().NoError(err, "Failed to unmarshal version check response. Body: %s", string(bodyBytes))

	// Verify check result field is not empty
	s.Assert().NotEmpty(checkResp.CheckResult, "CheckResult field is empty in response")

	if !s.T().Failed() {
		s.logSuccess("Successfully performed version check. Result: %s", checkResp.CheckResult)
	}
}

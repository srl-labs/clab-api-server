// tests_go/version_suite_test.go
package tests_go

import (
	"encoding/json"
	"fmt"
	"net/http"
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
	// This endpoint should be accessible without authentication
	s.logTest("Testing version information endpoint")

	versionURL := fmt.Sprintf("%s/api/v1/version", s.cfg.APIURL)
	// No auth headers needed (nil)
	bodyBytes, statusCode, err := s.doRequest("GET", versionURL, nil, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute version request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for version endpoint. Body: %s", string(bodyBytes))

	// Verify we can parse the response as JSON
	var versionInfo struct {
		Version   string `json:"version"`
		BuildTime string `json:"buildTime"`
		GitCommit string `json:"gitCommit"`
	}

	err = json.Unmarshal(bodyBytes, &versionInfo)
	s.Require().NoError(err, "Failed to unmarshal version response. Body: %s", string(bodyBytes))

	// Verify version info has expected fields (basic check)
	s.Assert().NotEmpty(versionInfo.Version, "Version field is empty in response")
	// s.Assert().NotEmpty(versionInfo.BuildTime, "BuildTime field is empty in response") // Optional
	// s.Assert().NotEmpty(versionInfo.GitCommit, "GitCommit field is empty in response") // Optional

	if !s.T().Failed() {
		s.logSuccess("Successfully retrieved version information: %s", versionInfo.Version)
	}
}

// TestHealthCheckEndpoint tests the health check API endpoint.
func (s *VersionSuite) TestHealthCheckEndpoint() {
	// Health check endpoint should also be accessible without authentication
	s.logTest("Testing health check endpoint")

	healthURL := fmt.Sprintf("%s/api/v1/health", s.cfg.APIURL)
	// No auth headers needed (nil)
	bodyBytes, statusCode, err := s.doRequest("GET", healthURL, nil, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute health check request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for health check endpoint. Body: %s", string(bodyBytes))

	// Verify we can parse the response as JSON
	var healthInfo struct {
		Status  string `json:"status"`
		Message string `json:"message"` // Optional message field
	}

	err = json.Unmarshal(bodyBytes, &healthInfo)
	s.Require().NoError(err, "Failed to unmarshal health check response. Body: %s", string(bodyBytes))

	// Check status field is one of the expected healthy values
	s.Assert().Contains([]string{"ok", "healthy"}, healthInfo.Status, "Health check status not reporting healthy: %s", healthInfo.Status)
	// s.Assert().NotEmpty(healthInfo.Message, "Health check message field is empty") // Optional

	if !s.T().Failed() {
		s.logSuccess("Successfully confirmed API health status: %s", healthInfo.Status)
	}
}

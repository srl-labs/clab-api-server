// tests_go/health_suite_test.go
package tests_go

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// HealthSuite tests health and metrics endpoints.
type HealthSuite struct {
	BaseSuite
	apiUserToken     string
	apiUserHeaders   http.Header
	superuserToken   string
	superuserHeaders http.Header
}

// TestHealthSuite runs the HealthSuite.
func TestHealthSuite(t *testing.T) {
	suite.Run(t, new(HealthSuite))
}

// SetupSuite logs in users needed for the tests in this suite.
func (s *HealthSuite) SetupSuite() {
	s.BaseSuite.SetupSuite() // Call base setup
	s.apiUserToken = s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(s.apiUserToken)
	s.superuserToken = s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass)
	s.superuserHeaders = s.getAuthHeaders(s.superuserToken)
	s.Require().NotEmpty(s.apiUserToken)
	s.Require().NotEmpty(s.superuserToken)
}

type metricsEndpointResponse struct {
	ServerInfo struct {
		Version   string    `json:"version"`
		Uptime    string    `json:"uptime"`
		StartTime time.Time `json:"startTime"`
	} `json:"serverInfo"`
	Metrics struct {
		CPU  map[string]interface{} `json:"cpu"`
		Mem  map[string]interface{} `json:"mem"`
		Disk map[string]interface{} `json:"disk"`
	} `json:"metrics"`
}

func (s *HealthSuite) assertMetricsResponse(bodyBytes []byte) {
	var metricsResp metricsEndpointResponse

	err := json.Unmarshal(bodyBytes, &metricsResp)
	s.Require().NoError(err, "Failed to unmarshal metrics response. Body: %s", string(bodyBytes))

	// Verify server info
	s.Assert().NotEmpty(metricsResp.ServerInfo.Version, "Version field is empty")
	s.Assert().NotEmpty(metricsResp.ServerInfo.Uptime, "Uptime field is empty")
	s.Assert().NotZero(metricsResp.ServerInfo.StartTime, "StartTime should not be zero")

	// Verify metrics sections are present
	s.Assert().NotNil(metricsResp.Metrics.CPU, "CPU metrics section is missing")
	s.Assert().NotNil(metricsResp.Metrics.Mem, "Memory metrics section is missing")
	s.Assert().NotNil(metricsResp.Metrics.Disk, "Disk metrics section is missing")

	// Verify specific metrics fields
	s.Assert().Contains(metricsResp.Metrics.CPU, "usagePercent", "CPU metrics missing usagePercent")
	s.Assert().Contains(metricsResp.Metrics.CPU, "numCPU", "CPU metrics missing numCPU")

	s.Assert().Contains(metricsResp.Metrics.Mem, "totalMem", "Memory metrics missing totalMem")
	s.Assert().Contains(metricsResp.Metrics.Mem, "usedMem", "Memory metrics missing usedMem")
	s.Assert().Contains(metricsResp.Metrics.Mem, "usagePercent", "Memory metrics missing usagePercent")

	s.Assert().Contains(metricsResp.Metrics.Disk, "path", "Disk metrics missing path")
	s.Assert().Contains(metricsResp.Metrics.Disk, "totalDisk", "Disk metrics missing totalDisk")
	s.Assert().Contains(metricsResp.Metrics.Disk, "usagePercent", "Disk metrics missing usagePercent")
}

// TestPublicHealthEndpoint tests the public health endpoint without authentication.
func (s *HealthSuite) TestPublicHealthEndpoint() {
	s.logTest("Testing public health endpoint")

	healthURL := fmt.Sprintf("%s/health", s.cfg.APIURL)
	// No auth headers needed for this public endpoint
	bodyBytes, statusCode, err := s.doRequest("GET", healthURL, nil, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute health request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for health endpoint. Body: %s", string(bodyBytes))

	// Verify we can parse the response as JSON
	var healthResp struct {
		Status    string    `json:"status"`
		Uptime    string    `json:"uptime"`
		StartTime time.Time `json:"startTime"`
		Version   string    `json:"version"`
		Features  []string  `json:"features"`
	}

	err = json.Unmarshal(bodyBytes, &healthResp)
	s.Require().NoError(err, "Failed to unmarshal health response. Body: %s", string(bodyBytes))

	// Verify health status
	s.Assert().Equal("healthy", healthResp.Status, "Health status should be 'healthy'")

	// Verify other fields are present
	s.Assert().NotEmpty(healthResp.Uptime, "Uptime field is empty")
	s.Assert().NotZero(healthResp.StartTime, "StartTime should not be zero")
	s.Assert().NotEmpty(healthResp.Version, "Version field is empty")
	for _, feature := range []string{"validate", "graph-mermaid", "graph-dot", "sshx-readers", "gotty-options"} {
		s.Assert().Contains(healthResp.Features, feature, "Health features missing %q", feature)
	}

	if !s.T().Failed() {
		s.logSuccess("Successfully retrieved health information: status=%s, uptime=%s, version=%s",
			healthResp.Status, healthResp.Uptime, healthResp.Version)
	}
}

// TestMetricsEndpointSuperuser tests the metrics endpoint with superuser authentication.
func (s *HealthSuite) TestMetricsEndpointSuperuser() {
	s.logTest("Testing metrics endpoint with superuser credentials")

	metricsURL := fmt.Sprintf("%s/api/v1/health/metrics", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", metricsURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute metrics request as superuser")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for metrics endpoint as superuser. Body: %s", string(bodyBytes))

	s.assertMetricsResponse(bodyBytes)

	if !s.T().Failed() {
		s.logSuccess("Successfully retrieved system metrics as superuser")
	}
}

// TestMetricsEndpointAPIUser tests that authenticated API users can access the metrics endpoint.
func (s *HealthSuite) TestMetricsEndpointAPIUser() {
	s.logTest("Testing metrics endpoint with API user credentials")

	metricsURL := fmt.Sprintf("%s/api/v1/health/metrics", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", metricsURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute metrics request as API user")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for metrics endpoint as API user. Body: %s", string(bodyBytes))

	s.assertMetricsResponse(bodyBytes)

	if !s.T().Failed() {
		s.logSuccess("Successfully retrieved system metrics as API user")
	}
}

// TestHealthEndpointAuth tests that the public health endpoint remains accessible with auth too.
func (s *HealthSuite) TestHealthEndpointAuth() {
	s.logTest("Testing public health endpoint with authentication")

	healthURL := fmt.Sprintf("%s/health", s.cfg.APIURL)
	// Use auth headers to verify it still works with auth
	bodyBytes, statusCode, err := s.doRequest("GET", healthURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute health request with auth")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for health endpoint with auth. Body: %s", string(bodyBytes))

	// Verify we can parse the response as JSON
	var healthResp struct {
		Status string `json:"status"`
	}

	err = json.Unmarshal(bodyBytes, &healthResp)
	s.Require().NoError(err, "Failed to unmarshal health response with auth. Body: %s", string(bodyBytes))

	// Verify health status
	s.Assert().Equal("healthy", healthResp.Status, "Health status should be 'healthy' with auth")

	if !s.T().Failed() {
		s.logSuccess("Successfully accessed health endpoint with authentication")
	}
}

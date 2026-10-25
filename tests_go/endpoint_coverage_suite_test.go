package tests_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

type EndpointCoverageSuite struct {
	BaseSuite

	apiUserHeaders http.Header
	labName        string
}

func TestEndpointCoverageSuite(t *testing.T) {
	suite.Run(t, new(EndpointCoverageSuite))
}

func (s *EndpointCoverageSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	apiUserToken := s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(apiUserToken)

	s.labName, _ = s.setupEphemeralLab()
}

func (s *EndpointCoverageSuite) TearDownSuite() {
	if s.labName != "" {
		s.cleanupLab(s.labName, true)
	}
	s.BaseSuite.TearDownSuite()
}

func (s *EndpointCoverageSuite) TestRootEndpoint() {
	bodyBytes, statusCode, err := s.doRequest("GET", s.cfg.APIURL+"/", nil, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 for root endpoint. Body: %s", string(bodyBytes))

	var resp map[string]interface{}
	s.Require().NoError(json.Unmarshal(bodyBytes, &resp), "Expected root endpoint to return JSON. Body: %s", string(bodyBytes))
	s.Require().Contains(resp, "api_base_path")
}

func (s *EndpointCoverageSuite) TestImportTopologyFromURLRejectsUnsupportedSource() {
	importURL := fmt.Sprintf("%s/api/v1/labs/topology/import-from-url", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest(
		"POST",
		importURL,
		s.apiUserHeaders,
		bytes.NewBuffer(s.mustMarshal(map[string]string{"topologySourceUrl": "https://example.com/not-supported.git"})),
		s.cfg.RequestTimeout,
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for unsupported topology import source. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "Only GitHub and GitLab")
}

func (s *EndpointCoverageSuite) TestShareToolRoutesValidateAction() {
	for _, tool := range []string{"sshx", "gotty"} {
		actionURL := fmt.Sprintf("%s/api/v1/labs/%s/%s/not-an-action", s.cfg.APIURL, s.labName, tool)
		bodyBytes, statusCode, err := s.doRequest("POST", actionURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for invalid %s action. Body: %s", tool, string(bodyBytes))
		s.assertJSONError(bodyBytes, "Invalid action")
	}

	gottyURL := fmt.Sprintf("%s/api/v1/labs/%s/gotty/attach?port=not-a-port", s.cfg.APIURL, s.labName)
	bodyBytes, statusCode, err := s.doRequest("POST", gottyURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for invalid gotty port. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "Invalid gotty port")

	gottyAttachURL := fmt.Sprintf("%s/api/v1/labs/%s/gotty/attach", s.cfg.APIURL, s.labName)
	for _, body := range []map[string]string{
		{"username": "a'; rm -rf /", "password": "secret"},
		{"username": "alice", "password": "$(id)"},
		{"shell": "bash; id"},
		{"username": "alice"},
	} {
		bodyBytes, statusCode, err = s.doRequest("POST", gottyAttachURL, s.apiUserHeaders, bytes.NewBuffer(s.mustMarshal(body)), s.cfg.RequestTimeout)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for invalid gotty options %v. Body: %s", body, string(bodyBytes))
		s.assertJSONError(bodyBytes, "gotty")
		s.Require().NotContains(string(bodyBytes), "$(id)")
	}
}

func (s *EndpointCoverageSuite) TestTextGraphRoutesValidateInput() {
	mermaidURL := fmt.Sprintf("%s/api/v1/labs/%s/graph/mermaid", s.cfg.APIURL, s.labName)
	bodyBytes, statusCode, err := s.doRequest("POST", mermaidURL, s.apiUserHeaders, bytes.NewBuffer(s.mustMarshal(map[string]string{"direction": "sideways"})), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for invalid mermaid direction. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "invalid direction")

	bodyBytes, statusCode, err = s.doRequest("POST", mermaidURL, s.apiUserHeaders, bytes.NewBuffer(s.mustMarshal(map[string]string{"direction": "lr"})), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 for mermaid export. Body: %s", string(bodyBytes))
	var mermaidResp struct {
		FileName  string `json:"fileName"`
		Content   string `json:"content"`
		Format    string `json:"format"`
		Direction string `json:"direction"`
	}
	s.Require().NoError(json.Unmarshal(bodyBytes, &mermaidResp), "Body: %s", string(bodyBytes))
	s.Assert().Equal("mermaid", mermaidResp.Format)
	s.Assert().Equal("LR", mermaidResp.Direction)
	s.Assert().Contains(mermaidResp.Content, "graph LR")
	s.Assert().True(strings.HasSuffix(mermaidResp.FileName, ".mermaid"), "fileName = %q", mermaidResp.FileName)

	dotURL := fmt.Sprintf("%s/api/v1/labs/%s/graph/dot", s.cfg.APIURL, s.labName)
	bodyBytes, statusCode, err = s.doRequest("POST", dotURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 for dot export. Body: %s", string(bodyBytes))
	var dotResp struct {
		FileName string `json:"fileName"`
		Format   string `json:"format"`
	}
	s.Require().NoError(json.Unmarshal(bodyBytes, &dotResp), "Body: %s", string(bodyBytes))
	s.Assert().Equal("dot", dotResp.Format)
	s.Assert().True(strings.HasSuffix(dotResp.FileName, ".dot"), "fileName = %q", dotResp.FileName)
}

func (s *EndpointCoverageSuite) TestGracefulTimeoutValidation() {
	redeployURL := fmt.Sprintf("%s/api/v1/labs/%s?gracefulTimeout=5s", s.cfg.APIURL, s.labName)
	bodyBytes, statusCode, err := s.doRequest("PUT", redeployURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 when gracefulTimeout is used without graceful=true. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "gracefulTimeout")

	destroyURL := fmt.Sprintf("%s/api/v1/labs/%s?graceful=true&gracefulTimeout=0s", s.cfg.APIURL, s.labName)
	bodyBytes, statusCode, err = s.doRequest("DELETE", destroyURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for nonpositive gracefulTimeout. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "Invalid 'gracefulTimeout'")
}

func (s *EndpointCoverageSuite) TestFcliAndDrawioRoutesValidateInput() {
	fcliURL := fmt.Sprintf("%s/api/v1/labs/%s/fcli", s.cfg.APIURL, s.labName)
	bodyBytes, statusCode, err := s.doRequest("POST", fcliURL, s.apiUserHeaders, bytes.NewBuffer(s.mustMarshal(map[string]string{"command": ""})), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for empty fcli command. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "Invalid request body")

	drawioURL := fmt.Sprintf("%s/api/v1/labs/%s/graph/drawio", s.cfg.APIURL, s.labName)
	bodyBytes, statusCode, err = s.doRequest("POST", drawioURL, s.apiUserHeaders, bytes.NewBuffer(s.mustMarshal(map[string]string{"layout": "diagonal"})), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for invalid drawio layout. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "Invalid layout")
}

func (s *EndpointCoverageSuite) TestLabOpsRoutesValidateInput() {
	healthBody, statusCode, err := s.doRequest("GET", s.cfg.APIURL+"/health", nil, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 for health. Body: %s", string(healthBody))
	var health struct {
		Features []string `json:"features"`
	}
	s.Require().NoError(json.Unmarshal(healthBody, &health))
	for _, feature := range []string{"exec-filters", "lab-lifecycle-node-filter", "save-copy", "inspect-details", "snapshot-save", "deploy-restore"} {
		s.Require().Contains(health.Features, feature)
	}

	labURL := fmt.Sprintf("%s/api/v1/labs/%s", s.cfg.APIURL, s.labName)
	execBody := s.mustMarshal(map[string]string{"command": "true"})
	for _, tc := range []struct {
		method, target string
		body           []byte
		status         int
		contains       string
	}{
		{"POST", labURL + "/exec?label=missing-equals", execBody, http.StatusBadRequest, "label"},
		{"POST", labURL + "/exec?nodes=no-such-node", execBody, http.StatusNotFound, "No nodes"},
		{"POST", labURL + "/start?nodeFilter=bad%20node", nil, http.StatusBadRequest, "nodeFilter"},
		{"POST", labURL + "/restart?nodeFilter=no-such-node", nil, http.StatusNotFound, "no-such-node"},
		{"POST", labURL + "/save?copy=" + url.QueryEscape("/etc"), nil, http.StatusBadRequest, "copy"},
		{"GET", labURL + "?details=maybe", nil, http.StatusBadRequest, "details"},
		{"POST", labURL + "/snapshots", s.mustMarshal(map[string]string{"timeout": "2h"}), http.StatusBadRequest, "timeout"},
		{"POST", labURL + "/snapshots", s.mustMarshal(map[string]string{"outputDir": "/etc"}), http.StatusBadRequest, "outputDir"},
		{"POST", labURL + "/deploy?restore=r1", nil, http.StatusBadRequest, "restore"},
	} {
		var body io.Reader
		if tc.body != nil {
			body = bytes.NewBuffer(tc.body)
		}
		bodyBytes, statusCode, err := s.doRequest(tc.method, tc.target, s.apiUserHeaders, body, s.cfg.RequestTimeout)
		s.Require().NoError(err)
		s.Require().Equal(tc.status, statusCode, "%s %s. Body: %s", tc.method, tc.target, string(bodyBytes))
		s.assertJSONError(bodyBytes, tc.contains)
	}

	detailsBody, statusCode, err := s.doRequest("GET", labURL+"?details=true", s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 for inspect details. Body: %s", string(detailsBody))
	var details map[string][]map[string]interface{}
	s.Require().NoError(json.Unmarshal(detailsBody, &details))
	s.Require().NotEmpty(details[s.labName], "Expected runtime containers for lab %s", s.labName)
}

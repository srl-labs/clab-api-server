package tests_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

// Enable explicitly so the normal suite remains usable against servers where
// shared labs are disabled. The server needs CLAB_SHARED_LABS_ROOT configured.
func TestSharedLabsSuite(t *testing.T) {
	if os.Getenv("GOTEST_SHARED_LABS") != "true" {
		t.Skip("set GOTEST_SHARED_LABS=true and configure CLAB_SHARED_LABS_ROOT on the server")
	}
	suite.Run(t, new(SharedLabsSuite))
}

type SharedLabsSuite struct{ BaseSuite }

func (s *SharedLabsSuite) request(method, path string, headers http.Header, body string, expected int) []byte {
	s.T().Helper()
	response, status, err := s.doRequest(method, s.cfg.APIURL+"/api/v1"+path, headers, bytes.NewBufferString(body), s.cfg.DeployTimeout)
	s.Require().NoError(err)
	s.Require().Equal(expected, status, "%s %s: %s", method, path, response)
	return response
}

func (s *SharedLabsSuite) TestCollaboratingUsersAndPrivateIsolation() {
	ownerHeaders, adminHeaders := s.loginBothUsers()
	// A second regular API user proves sharing does not require either caller
	// to belong to SUPERUSER_GROUP.
	collaborator := "sharetest" + s.randomSuffix(7)
	password := "Shared-Test-" + s.randomSuffix(20)
	createUser := UserCreateRequest{Username: collaborator, Password: password, Groups: []string{getEnv("GOTEST_API_USER_GROUP", "clab_api")}}
	s.request("POST", "/users", adminHeaders, string(s.mustMarshal(createUser)), http.StatusCreated)
	defer s.request("DELETE", "/users/"+collaborator, adminHeaders, "", http.StatusOK)
	collaboratorHeaders := s.getAuthHeaders(s.login(collaborator, password))
	for _, userName := range []string{s.cfg.APIUserUser, collaborator} {
		var details UserDetails
		s.Require().NoError(json.Unmarshal(s.request("GET", "/users/"+userName, adminHeaders, "", http.StatusOK), &details))
		s.Require().False(details.IsSuperuser)
	}

	lab := fmt.Sprintf("%s-shared-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	privateLab := lab + "-private"
	sharedDir := "@shared/" + lab
	path := sharedDir + "/" + lab + ".clab.yml"
	fileURL := "/labs/workspace/file?path=" + url.QueryEscape(path)
	labURL := "/labs/" + lab
	topology := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", lab)
	defer func() {
		_, _, _ = s.doRequest("DELETE", s.cfg.APIURL+"/api/v1/labs/workspace/file?recursive=true&path="+url.QueryEscape(sharedDir), adminHeaders, nil, s.cfg.RequestTimeout)
	}()
	defer s.cleanupLab(lab, true)
	s.request("POST", "/labs/workspace/directory", ownerHeaders, string(s.mustMarshal(map[string]string{"path": sharedDir})), http.StatusOK)
	s.request("PUT", fileURL, ownerHeaders, topology, http.StatusOK)
	s.Require().JSONEq(topology, string(s.request("GET", fileURL, collaboratorHeaders, "", http.StatusOK)))
	s.request("GET", fileURL, s.getAuthHeaders(""), "", http.StatusUnauthorized)
	s.request("PUT", labURL+"/topology/file?path="+url.QueryEscape(path), collaboratorHeaders, topology, http.StatusOK)
	listing := s.request("GET", "/labs/topology/files", collaboratorHeaders, "", http.StatusOK)
	s.Require().Contains(string(listing), path)

	// Private topologies and running labs still belong only to their owner.
	privateTopology := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", privateLab)
	defer s.cleanupLab(privateLab, true)
	body, status, err := s.createLab(ownerHeaders, privateLab, privateTopology, false, s.cfg.DeployTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status, string(body))
	s.request("GET", "/labs/"+privateLab, collaboratorHeaders, "", http.StatusNotFound)
	s.request("DELETE", "/labs/"+privateLab, collaboratorHeaders, "", http.StatusNotFound)
	listing = s.request("GET", "/labs/topology/files", collaboratorHeaders, "", http.StatusOK)
	s.Require().NotContains(string(listing), privateLab)

	deployURL := labURL + "/deploy?path=" + url.QueryEscape(path)
	s.request("POST", deployURL, ownerHeaders, "", http.StatusOK)
	var deployed ClabInspectOutput
	s.Require().NoError(json.Unmarshal(s.request("GET", "/labs", collaboratorHeaders, "", http.StatusOK), &deployed))
	s.Require().Contains(deployed, lab)
	s.Require().NotContains(deployed, privateLab)
	s.Require().NotEmpty(deployed[lab])
	node := deployed[lab][0].Name
	s.Require().Equal(s.cfg.APIUserUser, deployed[lab][0].Owner)
	s.request("GET", labURL, collaboratorHeaders, "", http.StatusOK)
	s.request("GET", labURL+"/interfaces", collaboratorHeaders, "", http.StatusOK)
	s.request("GET", labURL+"/nodes/"+node+"/logs?tail=5", collaboratorHeaders, "", http.StatusOK)
	execResponse := s.request("POST", labURL+"/exec?nodeFilter="+node, collaboratorHeaders, `{"command":"echo shared-access"}`, http.StatusOK)
	s.Require().Contains(string(execResponse), "shared-access")

	// Container-level authorization and session ownership remain separate.
	terminal := s.request("POST", labURL+"/nodes/"+node+"/terminal-sessions", collaboratorHeaders, `{"protocol":"shell","cols":80,"rows":24}`, http.StatusOK)
	var session struct {
		SessionID string `json:"sessionId"`
	}
	s.Require().NoError(json.Unmarshal(terminal, &session))
	s.Require().NotEmpty(session.SessionID)
	defer s.request("DELETE", "/terminal-sessions/"+session.SessionID, collaboratorHeaders, "", http.StatusOK)
	s.request("GET", "/terminal-sessions/"+session.SessionID, ownerHeaders, "", http.StatusNotFound)
	sshResponse := s.request("POST", labURL+"/nodes/"+node+"/ssh", collaboratorHeaders, `{"sshUsername":"root","duration":"10m"}`, http.StatusOK)
	var sshSession struct {
		Port int `json:"port"`
	}
	s.Require().NoError(json.Unmarshal(sshResponse, &sshSession))
	s.Require().Positive(sshSession.Port)
	sshURL := fmt.Sprintf("/ssh/sessions/%d", sshSession.Port)
	defer s.request("DELETE", sshURL, collaboratorHeaders, "", http.StatusOK)
	s.request("DELETE", sshURL, ownerHeaders, "", http.StatusForbidden)

	capturePayload := s.mustMarshal(map[string]interface{}{"targets": []map[string]string{{"containerName": node, "interfaceName": "eth1"}}})
	captureBody, captureStatus, captureErr := s.doRequest("POST", s.cfg.APIURL+"/api/v1"+labURL+"/capture/packetflix", collaboratorHeaders, bytes.NewReader(capturePayload), s.cfg.RequestTimeout)
	s.Require().NoError(captureErr)
	// EdgeShark is optional, but both lab and container authorization run
	// before the capture manager checks whether it is installed.
	s.Require().Contains([]int{http.StatusOK, http.StatusServiceUnavailable}, captureStatus, string(captureBody))
	if captureStatus == http.StatusServiceUnavailable {
		s.Require().Contains(string(captureBody), "Edgeshark is not running")
	}

	// Both document APIs target the same shared files, including new sidecars.
	annotations := `{"nodes":{"srl1":{"x":10,"y":20}}}`
	s.request("GET", labURL+"/topology/yaml", collaboratorHeaders, "", http.StatusOK)
	s.request("PUT", labURL+"/topology/annotations", collaboratorHeaders, annotations, http.StatusOK)
	s.Require().JSONEq(annotations, string(s.request("GET", fileURL+".annotations.json", ownerHeaders, "", http.StatusOK)))

	events := &EventsSuite{}
	events.SetT(s.T())
	events.cfg = s.cfg
	seenShared := false
	lines, status, err := events.collectEventLinesUntil(s.cfg.APIURL+"/api/v1/events?initialState=true", collaboratorHeaders, events.streamTimeout(), initialEventSettleWindow, func(line string) bool {
		attrs, parseErr := parseEventAttributes(line)
		if parseErr == nil && eventLabName(attrs) == lab {
			seenShared = true
		}
		return seenShared
	})
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.Require().True(seenShared)
	for _, line := range lines {
		attrs, err := parseEventAttributes(line)
		s.Require().NoError(err)
		s.Require().NotEqual(privateLab, eventLabName(attrs))
	}

	// Reconfigure, apply and redeploy must keep the original deployment owner.
	s.request("POST", deployURL+"&reconfigure=true", collaboratorHeaders, "", http.StatusOK)
	// Inline reconfiguration must not move another user's shared lab into the
	// caller's personal workspace.
	s.request("POST", "/labs?reconfigure=true", collaboratorHeaders, string(s.mustMarshal(map[string]json.RawMessage{"topologyContent": json.RawMessage(topology)})), http.StatusConflict)
	s.request("POST", labURL+"/apply?dryRun=true", collaboratorHeaders, "", http.StatusOK)
	s.request("PUT", labURL, collaboratorHeaders, "", http.StatusOK)
	var inspected []ClabContainerInfo
	s.Require().NoError(json.Unmarshal(s.request("GET", labURL, collaboratorHeaders, "", http.StatusOK), &inspected))
	s.Require().NotEmpty(inspected)
	for _, container := range inspected {
		s.Require().Equal(s.cfg.APIUserUser, container.Owner)
	}

	// Another user can destroy, find the undeployed source and deploy it again.
	s.request("DELETE", labURL+"?cleanup=true", collaboratorHeaders, "", http.StatusOK)
	s.Require().Contains(string(s.request("GET", "/labs/topology/files", collaboratorHeaders, "", http.StatusOK)), path)
	s.request("POST", deployURL, collaboratorHeaders, "", http.StatusOK)
	s.request("GET", labURL, ownerHeaders, "", http.StatusOK)
	s.request("DELETE", labURL+"?cleanup=true&purgeLabDir=true", collaboratorHeaders, "", http.StatusOK)
	s.request("GET", fileURL, ownerHeaders, "", http.StatusNotFound)
	s.request("GET", "/labs/workspace/tree?path=@shared", ownerHeaders, "", http.StatusOK)
}

func (s *SharedLabsSuite) TestRootTopologyPurgeKeepsSharedWorkspace() {
	ownerHeaders, _ := s.loginBothUsers()
	lab := fmt.Sprintf("%s-shared-root-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	path := "@shared/" + lab + ".clab.yml"
	fileURL := "/labs/workspace/file?path=" + url.QueryEscape(path)
	markerURL := "/labs/workspace/file?path=" + url.QueryEscape("@shared/"+lab+"-keep.txt")
	defer s.request("DELETE", fileURL, ownerHeaders, "", http.StatusOK)
	defer s.request("DELETE", markerURL, ownerHeaders, "", http.StatusOK)
	defer s.cleanupLab(lab, true)
	s.request("PUT", markerURL, ownerHeaders, "keep", http.StatusOK)
	s.request("PUT", fileURL, ownerHeaders, strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", lab), http.StatusOK)
	s.request("POST", "/labs/"+lab+"/deploy?path="+url.QueryEscape(path), ownerHeaders, "", http.StatusOK)
	s.request("DELETE", "/labs/"+lab+"?cleanup=true&purgeLabDir=true", ownerHeaders, "", http.StatusOK)
	s.Require().Equal("keep", string(s.request("GET", markerURL, ownerHeaders, "", http.StatusOK)))
	s.request("GET", fileURL, ownerHeaders, "", http.StatusOK)
}

// tests_go/ssh_suite_test.go
package tests_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/ssh"
)

// SSHSuite tests SSH access/session management endpoints.
type SSHSuite struct {
	BaseSuite

	apiUserToken     string
	apiUserHeaders   http.Header
	superuserToken   string
	superuserHeaders http.Header

	labName       string
	containerName string

	createdPorts []int
}

func TestSSHSuite(t *testing.T) {
	suite.Run(t, new(SSHSuite))
}

func (s *SSHSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()

	s.apiUserToken = s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(s.apiUserToken)
	s.superuserToken = s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass)
	s.superuserHeaders = s.getAuthHeaders(s.superuserToken)
	s.Require().NotEmpty(s.apiUserToken)
	s.Require().NotEmpty(s.superuserToken)

	// Create a shared lab owned by the API user for SSH tests.
	// Use a Nokia SR Linux node so the SSH proxy can be validated end-to-end.
	s.labName = fmt.Sprintf("%s-ssh-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	topologyObj := map[string]interface{}{
		"name": s.labName,
		"topology": map[string]interface{}{
			"nodes": map[string]interface{}{
				"srl1": map[string]interface{}{
					"kind":  "nokia_srlinux",
					"type":  "ixr-d2l",
					"image": "ghcr.io/nokia/srlinux:latest",
				},
			},
		},
	}
	topology := string(s.mustMarshal(topologyObj))

	s.logSetup("Creating shared SSH test lab: %s", s.labName)
	deployTimeout := s.cfg.DeployTimeout
	if deployTimeout < 10*time.Minute {
		deployTimeout = 10 * time.Minute
	}
	bodyBytes, statusCode, err := s.createLab(s.apiUserHeaders, s.labName, topology, false, deployTimeout)
	s.Require().NoError(err, "SETUP Failed: Could not create SSH test lab")
	s.Require().Equal(http.StatusOK, statusCode, "SETUP Failed: Could not create SSH test lab. Body: %s", string(bodyBytes))

	// Resolve first container name in the lab to use for SSH access requests.
	// SR Linux boot can take time; wait until inspect provides a container with an IPv4 address.
	container := s.waitForFirstContainerWithIPv4(s.labName, s.apiUserHeaders, 3*time.Minute)
	s.containerName = container.Name
	s.Require().NotEmpty(s.containerName, "SETUP Failed: Container name is empty")

	s.logSetup("Using container '%s' for SSH access tests", s.containerName)
}

func (s *SSHSuite) TearDownSuite() {
	// Best-effort cleanup of any sessions created during the suite.
	for _, port := range s.createdPorts {
		terminateURL := fmt.Sprintf("%s/api/v1/ssh/sessions/%d", s.cfg.APIURL, port)
		_, _, _ = s.doRequest("DELETE", terminateURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)
	}

	if s.labName != "" {
		s.logTeardown("Cleaning up SSH test lab: %s", s.labName)
		s.cleanupLab(s.labName, true)
	}

	s.BaseSuite.TearDownSuite()
}

func (s *SSHSuite) waitForFirstContainerWithIPv4(labName string, headers http.Header, timeout time.Duration) ClabContainerInfo {
	s.T().Helper()

	inspectURL := fmt.Sprintf("%s/api/v1/labs/%s", s.cfg.APIURL, labName)
	deadline := time.Now().Add(timeout)

	var lastBody []byte
	var lastStatus int
	var lastErr error

	for time.Now().Before(deadline) {
		bodyBytes, statusCode, err := s.doRequest("GET", inspectURL, headers, nil, s.cfg.RequestTimeout)
		lastBody = bodyBytes
		lastStatus = statusCode
		lastErr = err

		if err == nil && statusCode == http.StatusOK {
			var containers []ClabContainerInfo
			if json.Unmarshal(bodyBytes, &containers) == nil && len(containers) > 0 {
				for _, c := range containers {
					// containerlab reports a container without an address as "N/A"
					if c.Name != "" && c.IPv4Address != "" && c.IPv4Address != "N/A" {
						return c
					}
				}
			}
		}

		time.Sleep(2 * time.Second)
	}

	s.Require().FailNowf("Timed out waiting for lab container IPv4", "lab=%s status=%d err=%v body=%s",
		labName, lastStatus, lastErr, string(lastBody))
	return ClabContainerInfo{}
}

func (s *SSHSuite) requireSRLSSHHandshake(port int, timeout time.Duration) {
	s.T().Helper()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(timeout)
	var lastErr error

	cfg := &ssh.ClientConfig{
		User:            "admin",
		Auth:            []ssh.AuthMethod{ssh.Password("NokiaSrl1!")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	for time.Now().Before(deadline) {
		// Fast check: port is accepting TCP connections.
		conn, dialErr := net.DialTimeout("tcp", addr, 2*time.Second)
		if dialErr != nil {
			lastErr = dialErr
			time.Sleep(2 * time.Second)
			continue
		}
		_ = conn.Close()

		client, err := ssh.Dial("tcp", addr, cfg)
		if err != nil {
			lastErr = err
			time.Sleep(2 * time.Second)
			continue
		}
		_ = client.Close()
		return
	}

	s.Require().FailNowf("SSH handshake failed", "addr=%s lastErr=%v", addr, lastErr)
}

func (s *SSHSuite) requestSSH(headers http.Header, duration string) (port int) {
	s.T().Helper()

	req := map[string]string{
		"sshUsername": "admin",
	}
	if duration != "" {
		req["duration"] = duration
	}

	reqBody := bytes.NewBuffer(s.mustMarshal(req))
	reqURL := fmt.Sprintf("%s/api/v1/labs/%s/nodes/%s/ssh", s.cfg.APIURL, s.labName, url.PathEscape(s.containerName))

	respBody, statusCode, err := s.doRequest("POST", reqURL, headers, reqBody, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 for SSH access request. Body: %s", string(respBody))

	var resp struct {
		Port       int       `json:"port"`
		Host       string    `json:"host"`
		Username   string    `json:"username"`
		Expiration time.Time `json:"expiration"`
		Command    string    `json:"command"`
	}
	s.Require().NoError(json.Unmarshal(respBody, &resp), "Failed to unmarshal SSH access response. Body: %s", string(respBody))
	s.Require().Greater(resp.Port, 0, "Expected port > 0 in SSH access response")
	s.Require().NotEmpty(resp.Host, "Expected host in SSH access response")
	s.Require().NotEmpty(resp.Username, "Expected username in SSH access response")
	s.Require().NotZero(resp.Expiration, "Expected expiration in SSH access response")
	s.Require().Contains(resp.Command, fmt.Sprintf("-p %d", resp.Port), "Expected command to reference allocated port")

	s.createdPorts = append(s.createdPorts, resp.Port)
	return resp.Port
}

func (s *SSHSuite) TestRequestSSHAccessCreatesSessionAndListsForUser() {
	s.logTest("Requesting SSH access as API user and listing sessions")

	port := s.requestSSH(s.apiUserHeaders, "10m")

	// Validate that we can actually SSH (handshake + auth) to the SR Linux node via the proxy.
	s.logTest("Attempting SSH handshake to SR Linux node via proxy port %d", port)
	s.requireSRLSSHHandshake(port, 2*time.Minute)

	listURL := fmt.Sprintf("%s/api/v1/ssh/sessions", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", listURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 listing SSH sessions. Body: %s", string(bodyBytes))

	var sessions []struct {
		Port    int    `json:"port"`
		LabName string `json:"labName"`
	}
	s.Require().NoError(json.Unmarshal(bodyBytes, &sessions), "Failed to unmarshal sessions list. Body: %s", string(bodyBytes))

	found := false
	for _, sess := range sessions {
		if sess.Port == port && sess.LabName == s.labName {
			found = true
			break
		}
	}
	s.Assert().True(found, "Expected sessions list to include created session (port=%d, lab=%s). Body: %s", port, s.labName, string(bodyBytes))

	terminateURL := fmt.Sprintf("%s/api/v1/ssh/sessions/%d", s.cfg.APIURL, port)
	termBody, termStatus, termErr := s.doRequest("DELETE", terminateURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(termErr)
	s.Assert().Equal(http.StatusOK, termStatus, "Expected 200 terminating own SSH session. Body: %s", string(termBody))
}

func (s *SSHSuite) TestListSessionsAllForbiddenForAPIUser() {
	s.logTest("Listing all sessions as API user with all=true (expecting 403)")

	port := s.requestSSH(s.apiUserHeaders, "10m")
	defer func() {
		terminateURL := fmt.Sprintf("%s/api/v1/ssh/sessions/%d", s.cfg.APIURL, port)
		_, _, _ = s.doRequest("DELETE", terminateURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	}()

	listAllURL := fmt.Sprintf("%s/api/v1/ssh/sessions?all=true", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", listAllURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Assert().Equal(http.StatusForbidden, statusCode, "Expected 403 when API user requests all sessions. Body: %s", string(bodyBytes))
}

func (s *SSHSuite) TestSuperuserAllSeesOtherUsersSessions() {
	s.logTest("Creating sessions as api user + superuser and listing as superuser with all=true")

	apiPort := s.requestSSH(s.apiUserHeaders, "10m")
	suPort := s.requestSSH(s.superuserHeaders, "10m")

	// Superuser listing without all=true should only show sessions owned by superuser.
	listURL := fmt.Sprintf("%s/api/v1/ssh/sessions", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", listURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 listing sessions as superuser. Body: %s", string(bodyBytes))

	var sessions []struct {
		Port int `json:"port"`
	}
	s.Require().NoError(json.Unmarshal(bodyBytes, &sessions), "Failed to unmarshal sessions list. Body: %s", string(bodyBytes))

	seenSU := false
	seenAPI := false
	for _, sess := range sessions {
		if sess.Port == suPort {
			seenSU = true
		}
		if sess.Port == apiPort {
			seenAPI = true
		}
	}
	s.Assert().True(seenSU, "Expected superuser list (all=false) to include superuser-created session")
	s.Assert().False(seenAPI, "Expected superuser list (all=false) to NOT include api user session")

	// Superuser listing with all=true should include both.
	listAllURL := fmt.Sprintf("%s/api/v1/ssh/sessions?all=true", s.cfg.APIURL)
	bodyBytes2, statusCode2, err2 := s.doRequest("GET", listAllURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err2)
	s.Require().Equal(http.StatusOK, statusCode2, "Expected 200 listing all sessions as superuser. Body: %s", string(bodyBytes2))

	var sessions2 []struct {
		Port int `json:"port"`
	}
	s.Require().NoError(json.Unmarshal(bodyBytes2, &sessions2), "Failed to unmarshal sessions list (all=true). Body: %s", string(bodyBytes2))

	seenSU = false
	seenAPI = false
	for _, sess := range sessions2 {
		if sess.Port == suPort {
			seenSU = true
		}
		if sess.Port == apiPort {
			seenAPI = true
		}
	}
	s.Assert().True(seenSU, "Expected superuser list (all=true) to include superuser-created session")
	s.Assert().True(seenAPI, "Expected superuser list (all=true) to include api user session")
}

func (s *SSHSuite) TestTerminateForbiddenForNonOwner() {
	s.logTest("Terminating superuser session as API user (expecting 403)")

	suPort := s.requestSSH(s.superuserHeaders, "10m")

	terminateURL := fmt.Sprintf("%s/api/v1/ssh/sessions/%d", s.cfg.APIURL, suPort)
	bodyBytes, statusCode, err := s.doRequest("DELETE", terminateURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Assert().Equal(http.StatusForbidden, statusCode, "Expected 403 when non-owner terminates SSH session. Body: %s", string(bodyBytes))

	// Cleanup.
	_, _, _ = s.doRequest("DELETE", terminateURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)
}

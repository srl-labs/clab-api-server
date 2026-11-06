package tests_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type CaptureSuite struct {
	BaseSuite

	apiUserHeaders   http.Header
	superuserHeaders http.Header
	labName          string
	containerName    string
}

func TestCaptureSuite(t *testing.T) {
	suite.Run(t, new(CaptureSuite))
}

func (s *CaptureSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	s.apiUserHeaders, s.superuserHeaders = s.loginBothUsers()

	s.labName, _ = s.setupEphemeralLab()
	container := s.firstContainerInLab(s.labName, s.apiUserHeaders)
	s.containerName = container.Name
}

func (s *CaptureSuite) TearDownSuite() {
	_, _, _ = s.doRequest("DELETE", fmt.Sprintf("%s/api/v1/capture/wireshark-vnc-sessions", s.cfg.APIURL), s.superuserHeaders, nil, s.cfg.RequestTimeout)
	if s.labName != "" {
		s.cleanupLab(s.labName, true)
	}
	s.BaseSuite.TearDownSuite()
}

func (s *CaptureSuite) TestEdgeSharkStatusAndPrivileges() {
	statusURL := fmt.Sprintf("%s/api/v1/tools/edgeshark/status", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", statusURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 getting EdgeShark status. Body: %s", string(bodyBytes))

	var statusResp struct {
		Running        bool   `json:"running"`
		Version        string `json:"version"`
		PacketflixPort int    `json:"packetflixPort"`
		Runtime        string `json:"runtime"`
	}
	s.Require().NoError(json.Unmarshal(bodyBytes, &statusResp), "Failed to unmarshal EdgeShark status. Body: %s", string(bodyBytes))
	s.Require().Greater(statusResp.PacketflixPort, 0)
	s.Require().NotEmpty(statusResp.Runtime)

	for _, endpoint := range []string{"install", "uninstall"} {
		actionURL := fmt.Sprintf("%s/api/v1/tools/edgeshark/%s", s.cfg.APIURL, endpoint)
		bodyBytes, statusCode, err = s.doRequest("POST", actionURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusForbidden, statusCode, "Expected 403 for API user EdgeShark %s. Body: %s", endpoint, string(bodyBytes))
		s.assertJSONError(bodyBytes, "Superuser privileges required")
	}
}

func (s *CaptureSuite) TestPacketflixCaptureValidationAndEnvironmentTolerantSuccess() {
	packetflixURL := fmt.Sprintf("%s/api/v1/labs/%s/capture/packetflix", s.cfg.APIURL, s.labName)

	bodyBytes, statusCode, err := s.doRequest(
		"POST",
		packetflixURL,
		s.apiUserHeaders,
		bytes.NewBuffer(s.mustMarshal(map[string]interface{}{"targets": []interface{}{}})),
		s.cfg.RequestTimeout,
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for empty capture targets. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "Targets")

	bodyBytes, statusCode, err = s.doRequest(
		"POST",
		packetflixURL,
		s.apiUserHeaders,
		bytes.NewBuffer(s.mustMarshal(map[string]interface{}{
			"targets": []map[string]string{
				{"containerName": s.containerName, "interfaceName": "bad iface"},
			},
		})),
		s.cfg.RequestTimeout,
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for invalid capture interface. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "Invalid interface name")

	bodyBytes, statusCode, err = s.doRequest(
		"POST",
		packetflixURL,
		s.apiUserHeaders,
		bytes.NewBuffer(s.mustMarshal(map[string]interface{}{
			"targets": []map[string]string{
				{"containerName": s.containerName, "interfaceName": "eth1"},
				{"containerName": s.containerName, "interfaceName": "eth1"},
			},
		})),
		s.cfg.RequestTimeout,
	)
	s.Require().NoError(err)

	switch statusCode {
	case http.StatusOK:
		var resp struct {
			Captures []struct {
				ContainerName  string   `json:"containerName"`
				InterfaceNames []string `json:"interfaceNames"`
				PacketflixURI  string   `json:"packetflixUri"`
			} `json:"captures"`
		}
		s.Require().NoError(json.Unmarshal(bodyBytes, &resp), "Failed to unmarshal packetflix response. Body: %s", string(bodyBytes))
		s.Require().Len(resp.Captures, 1)
		s.Require().Equal(s.containerName, resp.Captures[0].ContainerName)
		s.Require().Equal([]string{"eth1"}, resp.Captures[0].InterfaceNames)
		s.Require().Contains(resp.Captures[0].PacketflixURI, "packetflix:ws://")
	case http.StatusServiceUnavailable:
		s.assertJSONError(bodyBytes, "Edgeshark is not running")
	default:
		s.Require().Failf("unexpected packetflix status", "status=%d body=%s", statusCode, string(bodyBytes))
	}
}

func (s *CaptureSuite) TestWiresharkVncSessionErrorsAndCloseAll() {
	unknownSessionID := "missing-session-" + s.randomSuffix(6)

	readyURL := fmt.Sprintf("%s/api/v1/capture/wireshark-vnc-sessions/%s/ready", s.cfg.APIURL, unknownSessionID)
	bodyBytes, statusCode, err := s.doRequest("GET", readyURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusNotFound, statusCode, "Expected 404 for unknown capture session readiness. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "capture session not found")

	deleteURL := fmt.Sprintf("%s/api/v1/capture/wireshark-vnc-sessions/%s", s.cfg.APIURL, unknownSessionID)
	bodyBytes, statusCode, err = s.doRequest("DELETE", deleteURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusNotFound, statusCode, "Expected 404 deleting unknown capture session. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "capture session not found")

	proxyURL := fmt.Sprintf("%s/api/v1/capture/wireshark-vnc-sessions/%s/vnc/%s", s.cfg.APIURL, unknownSessionID, url.PathEscape("index.html"))
	bodyBytes, statusCode, err = s.doRequest("GET", proxyURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusNotFound, statusCode, "Expected 404 proxying unknown capture session. Body: %s", string(bodyBytes))
	s.assertJSONError(bodyBytes, "capture session not found")

	closeAllURL := fmt.Sprintf("%s/api/v1/capture/wireshark-vnc-sessions", s.cfg.APIURL)
	bodyBytes, statusCode, err = s.doRequest("DELETE", closeAllURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 closing capture sessions. Body: %s", string(bodyBytes))

	var closeResp struct {
		Message string `json:"message"`
		Closed  int    `json:"closed"`
	}
	s.Require().NoError(json.Unmarshal(bodyBytes, &closeResp), "Failed to unmarshal close-all response. Body: %s", string(bodyBytes))
	s.Require().GreaterOrEqual(closeResp.Closed, 0)
	s.Require().NotEmpty(closeResp.Message)
}

func (s *CaptureSuite) TestWiresharkVncSessionCreateIsEnvironmentTolerant() {
	createURL := fmt.Sprintf("%s/api/v1/labs/%s/capture/wireshark-vnc-sessions", s.cfg.APIURL, s.labName)
	bodyBytes, statusCode, err := s.doRequest(
		"POST",
		createURL,
		s.apiUserHeaders,
		bytes.NewBuffer(s.mustMarshal(map[string]interface{}{
			"theme": "dark",
			"targets": []map[string]string{
				{"containerName": s.containerName, "interfaceName": "eth1"},
			},
		})),
		s.cfg.RequestTimeout,
	)
	s.Require().NoError(err)

	switch statusCode {
	case http.StatusOK:
		var resp struct {
			Sessions []struct {
				SessionID     string `json:"sessionId"`
				LabName       string `json:"labName"`
				ContainerName string `json:"containerName"`
				VncPath       string `json:"vncPath"`
			} `json:"sessions"`
		}
		s.Require().NoError(json.Unmarshal(bodyBytes, &resp), "Failed to unmarshal VNC session response. Body: %s", string(bodyBytes))
		s.Require().Len(resp.Sessions, 1)
		s.Require().NotEmpty(resp.Sessions[0].SessionID)
		s.Require().Equal(s.labName, resp.Sessions[0].LabName)
		s.Require().Equal(s.containerName, resp.Sessions[0].ContainerName)
		s.Require().NotEmpty(resp.Sessions[0].VncPath)

		deleteURL := fmt.Sprintf("%s/api/v1/capture/wireshark-vnc-sessions/%s", s.cfg.APIURL, resp.Sessions[0].SessionID)
		deleteBody, deleteStatus, deleteErr := s.doRequest("DELETE", deleteURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
		s.Require().NoError(deleteErr)
		s.Require().Equal(http.StatusOK, deleteStatus, "Expected 200 deleting created VNC capture session. Body: %s", string(deleteBody))
	case http.StatusServiceUnavailable:
		s.assertJSONError(bodyBytes, "Edgeshark is not running")
	default:
		s.Require().Failf("unexpected VNC capture create status", "status=%d body=%s", statusCode, string(bodyBytes))
	}
}

// labExec runs a command in a node of the suite's lab.
func (s *CaptureSuite) labExec(node, command string) []byte {
	s.T().Helper()
	bodyBytes, statusCode, err := s.doRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/v1/labs/%s/exec?nodeFilter=clab-%s-%s", s.cfg.APIURL, s.labName, s.labName, node),
		s.apiUserHeaders,
		bytes.NewBuffer(s.mustMarshal(map[string]string{"command": command})),
		2*time.Minute,
	)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "exec %q on %s: %s", command, node, string(bodyBytes))
	return bodyBytes
}

// TestCaptureStreamNeedsNoEdgeshark captures a Docker or Podman lab's link through the server's
// capture stream, whether or not Edgeshark runs: both ends of a link in one pcapng.
func (s *CaptureSuite) TestCaptureStreamNeedsNoEdgeshark() {
	s.Run("health advertises capture-stream", func() {
		bodyBytes, statusCode, err := s.doRequest(http.MethodGet, s.cfg.APIURL+"/health", nil, nil, s.cfg.RequestTimeout)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusOK, statusCode)
		s.Require().Contains(string(bodyBytes), `"capture-stream"`)
	})

	s.Run("capturable interfaces with their peers", func() {
		bodyBytes, statusCode, err := s.doRequest(http.MethodGet,
			fmt.Sprintf("%s/api/v1/labs/%s/capture/interfaces", s.cfg.APIURL, s.labName),
			s.apiUserHeaders, nil, 2*time.Minute)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusOK, statusCode, string(bodyBytes))
		s.Require().JSONEq(`[
			{"node":"srl1","interface":"eth1","peerNode":"srl2","peerInterface":"eth1"},
			{"node":"srl2","interface":"eth1","peerNode":"srl1","peerInterface":"eth1"}]`, string(bodyBytes))
	})

	s.Run("stream a 5 s capture of both ends of the link", func() {
		s.labExec("srl1", "ip addr replace 10.97.0.1/24 dev eth1")
		s.labExec("srl2", "ip addr replace 10.97.0.2/24 dev eth1")
		var ping sync.WaitGroup
		ping.Go(func() {
			_, _, _ = s.doRequest(http.MethodPost,
				fmt.Sprintf("%s/api/v1/labs/%s/exec?nodeFilter=clab-%s-srl1", s.cfg.APIURL, s.labName, s.labName), s.apiUserHeaders,
				bytes.NewBuffer(s.mustMarshal(map[string]string{"command": "ping -c 30 -i 0.2 10.97.0.2"})), time.Minute)
		})
		defer ping.Wait()

		started := time.Now()
		bodyBytes, statusCode, err := s.doRequest(http.MethodGet,
			fmt.Sprintf("%s/api/v1/labs/%s/capture/stream?target=srl1:eth1&target=srl2:eth1&duration=5s", s.cfg.APIURL, s.labName),
			s.apiUserHeaders, nil, 2*time.Minute)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusOK, statusCode, string(bodyBytes))
		s.Require().GreaterOrEqual(time.Since(started), 5*time.Second)
		summary, err := readPCAPNG(bodyBytes)
		s.Require().NoError(err)
		s.Require().Equal([]string{"srl1:eth1", "srl2:eth1"}, summary.interfaces)
		s.Require().Positive(summary.icmp["srl1:eth1"], "ICMP on srl1:eth1: %+v", summary)
		s.Require().Positive(summary.icmp["srl2:eth1"], "ICMP on srl2:eth1: %+v", summary)
	})

	s.Run("the management interface is refused with what can be captured", func() {
		bodyBytes, statusCode, err := s.doRequest(http.MethodGet,
			fmt.Sprintf("%s/api/v1/labs/%s/capture/stream?target=srl1:eth0&duration=1s", s.cfg.APIURL, s.labName),
			s.apiUserHeaders, nil, 2*time.Minute)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusBadRequest, statusCode, string(bodyBytes))
		s.assertJSONError(bodyBytes, "capturable: eth1")
	})
}

// wiresharkContainerEnv returns the environment of a Wireshark VNC session's container, from the
// container runtime on this host; ok is false when the session's container cannot be seen.
func (s *CaptureSuite) wiresharkContainerEnv(containerName string) (string, bool) {
	s.T().Helper()
	names, err := exec.Command("docker", "ps", "--filter", "name=clab_ws_vnc_", "--format", "{{.Names}}").Output()
	if err != nil {
		return "", false
	}
	for _, name := range strings.Fields(string(names)) {
		if !strings.Contains(name, containerName) {
			continue
		}
		env, err := exec.Command("docker", "inspect", "-f", "{{.Config.Env}}", name).Output()
		if err == nil {
			return string(env), true
		}
	}
	return "", false
}

// TestWiresharkVncPrefersTheCaptureStream opens Wireshark VNC on a link, which needs no
// Edgeshark, and on the management interface, which only Edgeshark captures.
func (s *CaptureSuite) TestWiresharkVncPrefersTheCaptureStream() {
	createURL := fmt.Sprintf("%s/api/v1/labs/%s/capture/wireshark-vnc-sessions", s.cfg.APIURL, s.labName)
	create := func(containerName, iface string) ([]byte, int) {
		bodyBytes, statusCode, err := s.doRequest(http.MethodPost, createURL, s.apiUserHeaders,
			bytes.NewBuffer(s.mustMarshal(map[string]interface{}{
				"targets": []map[string]string{{"containerName": containerName, "interfaceName": iface}},
			})), 3*time.Minute)
		s.Require().NoError(err)
		return bodyBytes, statusCode
	}
	defer func() {
		_, _, _ = s.doRequest(http.MethodDelete, s.cfg.APIURL+"/api/v1/capture/wireshark-vnc-sessions", s.superuserHeaders, nil, s.cfg.RequestTimeout)
	}()

	s.Run("a link reads the capture stream from a pipe", func() {
		bodyBytes, statusCode := create(s.containerName, "eth1")
		s.Require().Equal(http.StatusOK, statusCode, string(bodyBytes))
		env, ok := s.wiresharkContainerEnv(s.containerName)
		if !ok {
			s.T().Skip("cannot inspect the session's container from here")
		}
		s.Require().Contains(env, "CLABWIRE_CAPTURE_PIPE=")
		s.Require().NotContains(env, "PACKETFLIX_LINK")
	})

	s.Run("the name the apps send, <lab>-<node>, finds the node", func() {
		bodyBytes, statusCode := create(s.labName+"-srl2", "eth1")
		s.Require().Equal(http.StatusOK, statusCode, string(bodyBytes))
		s.Require().Contains(string(bodyBytes), "clab-"+s.labName+"-srl2")
	})

	s.Run("the management interface goes through Edgeshark", func() {
		bodyBytes, statusCode := create(s.containerName, "eth0")
		if statusCode == http.StatusServiceUnavailable {
			s.assertJSONError(bodyBytes, "Edgeshark is not running")
			return
		}
		s.Require().Equal(http.StatusOK, statusCode, string(bodyBytes))
	})
}

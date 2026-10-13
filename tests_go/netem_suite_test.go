// tests_go/netem_suite_test.go
package tests_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// NetemSuite tests the netem tools endpoints for setting/showing/resetting link impairments.
type NetemSuite struct {
	BaseSuite

	apiUserToken     string
	apiUserHeaders   http.Header
	superuserToken   string
	superuserHeaders http.Header
}

// TestNetemSuite runs the NetemSuite.
func TestNetemSuite(t *testing.T) {
	suite.Run(t, new(NetemSuite))
}

func (s *NetemSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()

	s.apiUserToken = s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(s.apiUserToken)
	s.Require().NotEmpty(s.apiUserToken)

	s.superuserToken = s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass)
	s.superuserHeaders = s.getAuthHeaders(s.superuserToken)
	s.Require().NotEmpty(s.superuserToken)
}

func (s *NetemSuite) TestNetemRejectsNonOwner() {
	labName, superuserHeaders := s.setupSuperuserLab()
	defer s.cleanupLab(labName, true)

	inspectURL := fmt.Sprintf("%s/api/v1/labs/%s", s.cfg.APIURL, labName)
	bodyBytes, statusCode, err := s.doRequest("GET", inspectURL, superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 inspecting lab '%s'. Body: %s", labName, string(bodyBytes))

	var containers []struct {
		Name string `json:"name"`
	}
	s.Require().NoError(json.Unmarshal(bodyBytes, &containers))
	s.Require().NotEmpty(containers)

	containerName := containers[0].Name
	s.Require().NotEmpty(containerName)

	setURL := fmt.Sprintf("%s/api/v1/tools/netem/set", s.cfg.APIURL)
	payload := map[string]interface{}{
		"containerName": containerName,
		"interface":     "eth1",
		"delay":         "10ms",
	}
	reqBody := s.mustMarshal(payload)

	respBody, respStatus, reqErr := s.doRequest("POST", setURL, s.apiUserHeaders, bytes.NewBuffer(reqBody), s.cfg.RequestTimeout)
	s.Require().NoError(reqErr)
	s.Require().Equal(http.StatusNotFound, respStatus, "Expected 404 when non-owner calls netem set. Body: %s", string(respBody))
}

func (s *NetemSuite) TestNetemSetShowResetForLabOwner() {
	labName, userHeaders := s.setupEphemeralLab()
	defer s.cleanupLab(labName, true)

	inspectURL := fmt.Sprintf("%s/api/v1/labs/%s", s.cfg.APIURL, labName)
	bodyBytes, statusCode, err := s.doRequest("GET", inspectURL, userHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 inspecting lab '%s'. Body: %s", labName, string(bodyBytes))

	var containers []struct {
		Name string `json:"name"`
	}
	s.Require().NoError(json.Unmarshal(bodyBytes, &containers))
	s.Require().NotEmpty(containers)

	containerName := containers[0].Name
	s.Require().NotEmpty(containerName)

	iface := "eth1"

	// --- Set impairments ---
	setURL := fmt.Sprintf("%s/api/v1/tools/netem/set", s.cfg.APIURL)
	setPayload := map[string]interface{}{
		"containerName": containerName,
		"interface":     iface,
		"delay":         "100ms",
		"jitter":        "2ms",
		"loss":          10,
		"rate":          1000,
		"corruption":    2,
	}
	setReqBody := s.mustMarshal(setPayload)

	setRespBody, setStatus, setErr := s.doRequest("POST", setURL, userHeaders, bytes.NewBuffer(setReqBody), s.cfg.RequestTimeout)
	s.Require().NoError(setErr)
	s.Require().Equal(http.StatusOK, setStatus, "Expected 200 when setting netem. Body: %s", string(setRespBody))

	time.Sleep(500 * time.Millisecond)

	// --- Show impairments ---
	showURL := fmt.Sprintf("%s/api/v1/tools/netem/show?containerName=%s", s.cfg.APIURL, containerName)
	showBody, showStatus, showErr := s.doRequest("GET", showURL, userHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(showErr)
	s.Require().Equal(http.StatusOK, showStatus, "Expected 200 when showing netem. Body: %s", string(showBody))

	type netemIfInfo struct {
		Interface  string  `json:"interface"`
		Delay      string  `json:"delay"`
		Jitter     string  `json:"jitter"`
		PacketLoss float64 `json:"packet_loss"`
		Rate       int     `json:"rate"`
		Corruption float64 `json:"corruption"`
	}
	var showResp map[string][]netemIfInfo
	s.Require().NoError(json.Unmarshal(showBody, &showResp), "Failed to unmarshal netem show response. Body: %s", string(showBody))

	ifs, ok := showResp[containerName]
	s.Require().True(ok, "Expected show response to include key '%s'. Body: %s", containerName, string(showBody))
	s.Require().NotEmpty(ifs, "Expected at least one netem entry after set. Body: %s", string(showBody))

	var found *netemIfInfo
	for i := range ifs {
		// Allow "eth1 (alias)" display format.
		if strings.HasPrefix(ifs[i].Interface, iface) {
			found = &ifs[i]
			break
		}
	}
	s.Require().NotNil(found, "Expected to find netem entry for interface '%s'. Body: %s", iface, string(showBody))

	s.Require().Equal("100ms", found.Delay)
	s.Require().Equal("2ms", found.Jitter)
	s.Require().Equal(1000, found.Rate)
	s.Require().InDelta(10.0, found.PacketLoss, 0.05)
	s.Require().InDelta(2.0, found.Corruption, 0.05)

	// --- Reset impairments ---
	resetURL := fmt.Sprintf("%s/api/v1/tools/netem/reset", s.cfg.APIURL)
	resetPayload := map[string]interface{}{
		"containerName": containerName,
		"interface":     iface,
	}
	resetReqBody := s.mustMarshal(resetPayload)

	resetRespBody, resetStatus, resetErr := s.doRequest("POST", resetURL, userHeaders, bytes.NewBuffer(resetReqBody), s.cfg.RequestTimeout)
	s.Require().NoError(resetErr)
	s.Require().Equal(http.StatusOK, resetStatus, "Expected 200 when resetting netem. Body: %s", string(resetRespBody))

	time.Sleep(500 * time.Millisecond)

	// --- Show again, ensure interface entry is gone ---
	showBody2, showStatus2, showErr2 := s.doRequest("GET", showURL, userHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(showErr2)
	s.Require().Equal(http.StatusOK, showStatus2, "Expected 200 when showing netem after reset. Body: %s", string(showBody2))

	var showResp2 map[string][]netemIfInfo
	s.Require().NoError(json.Unmarshal(showBody2, &showResp2), "Failed to unmarshal netem show response (after reset). Body: %s", string(showBody2))

	ifs2, ok2 := showResp2[containerName]
	s.Require().True(ok2, "Expected show response (after reset) to include key '%s'. Body: %s", containerName, string(showBody2))

	for i := range ifs2 {
		s.Require().False(strings.HasPrefix(ifs2[i].Interface, iface), "Expected netem entry for '%s' to be removed after reset. Body: %s", iface, string(showBody2))
	}
}

// TestNetemByLabAndNodeName targets nodes by topology name, like
// `clab tools netem --name <lab> -n <node>`, and shows all nodes of a lab.
func (s *NetemSuite) TestNetemByLabAndNodeName() {
	labName, userHeaders := s.setupEphemeralLab()
	defer s.cleanupLab(labName, true)

	type netemIfInfo struct {
		Interface string `json:"interface"`
		Delay     string `json:"delay"`
	}
	showLab := func(query string) map[string][]netemIfInfo {
		showURL := fmt.Sprintf("%s/api/v1/tools/netem/show?%s", s.cfg.APIURL, query)
		body, status, err := s.doRequest("GET", showURL, userHeaders, nil, s.cfg.RequestTimeout)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusOK, status, "Expected 200 showing netem (%s). Body: %s", query, string(body))
		var resp map[string][]netemIfInfo
		s.Require().NoError(json.Unmarshal(body, &resp), "Body: %s", string(body))
		return resp
	}
	findIface := func(infos []netemIfInfo, iface string) *netemIfInfo {
		for i := range infos {
			if strings.HasPrefix(infos[i].Interface, iface) {
				return &infos[i]
			}
		}
		return nil
	}
	post := func(path string, payload map[string]interface{}) ([]byte, int) {
		body, status, err := s.doRequest("POST", fmt.Sprintf("%s/api/v1/tools/netem/%s", s.cfg.APIURL, path), userHeaders, bytes.NewBuffer(s.mustMarshal(payload)), s.cfg.RequestTimeout)
		s.Require().NoError(err)
		return body, status
	}

	body, status := post("set", map[string]interface{}{"labName": labName, "nodeName": "srl1", "interface": "eth1", "delay": "20ms"})
	s.Require().Equal(http.StatusOK, status, "Expected 200 setting netem by node name. Body: %s", string(body))
	time.Sleep(500 * time.Millisecond)

	allNodes := showLab("labName=" + labName)
	s.Require().Contains(allNodes, "srl1", "Expected lab show to include srl1: %v", allNodes)
	s.Require().Contains(allNodes, "srl2", "Expected lab show to include srl2: %v", allNodes)
	entry := findIface(allNodes["srl1"], "eth1")
	s.Require().NotNil(entry, "Expected eth1 impairment on srl1: %v", allNodes)
	s.Require().Equal("20ms", entry.Delay)

	oneNode := showLab(fmt.Sprintf("labName=%s&nodeName=srl1", labName))
	s.Require().NotNil(findIface(oneNode["srl1"], "eth1"), "Expected eth1 impairment in node show: %v", oneNode)

	body, status = post("reset", map[string]interface{}{"labName": labName, "nodeName": "srl1", "interface": "eth1"})
	s.Require().Equal(http.StatusOK, status, "Expected 200 resetting netem by node name. Body: %s", string(body))
	time.Sleep(500 * time.Millisecond)
	s.Require().Nil(findIface(showLab("labName=" + labName)["srl1"], "eth1"), "Expected eth1 impairment to be removed")

	body, status = post("set", map[string]interface{}{"labName": labName, "nodeName": "missing", "interface": "eth1", "delay": "20ms"})
	s.Require().Equal(http.StatusNotFound, status, "Expected 404 for unknown node. Body: %s", string(body))

	body, status = post("set", map[string]interface{}{"labName": labName, "interface": "eth1", "delay": "20ms"})
	s.Require().Equal(http.StatusBadRequest, status, "Expected 400 without nodeName. Body: %s", string(body))
}

// TestNetemOnStitchedLinkUsesHostInterface checks that impairments of a
// veth-stitch endpoint are applied to, shown on and reset from the host-side
// tools interface of the stitch, like the containerlab CLI does.
func (s *NetemSuite) TestNetemOnStitchedLinkUsesHostInterface() {
	labName := fmt.Sprintf("%s-stitch-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	topology := fmt.Sprintf(`{
  "name": %q,
  "topology": {
    "nodes": {
      "srl1": {"kind": "linux", "image": "ghcr.io/srl-labs/network-multitool:latest"},
      "srl2": {"kind": "linux", "image": "ghcr.io/srl-labs/network-multitool:latest"}
    },
    "links": [
      {"type": "veth-stitch", "endpoints": [{"node": "srl1", "interface": "eth1"}, {"node": "srl2", "interface": "eth1"}]}
    ]
  }
}`, labName)

	bodyBytes, statusCode, err := s.createLab(s.apiUserHeaders, labName, topology, false, s.cfg.DeployTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected stitched lab deploy to succeed. Body: %s", string(bodyBytes))
	defer s.cleanupLab(labName, true)
	time.Sleep(s.cfg.StabilizePause)

	post := func(path string, payload map[string]interface{}) ([]byte, int) {
		body, status, err := s.doRequest("POST", fmt.Sprintf("%s/api/v1/tools/netem/%s", s.cfg.APIURL, path), s.apiUserHeaders, bytes.NewBuffer(s.mustMarshal(payload)), s.cfg.RequestTimeout)
		s.Require().NoError(err)
		return body, status
	}
	show := func() []map[string]interface{} {
		showURL := fmt.Sprintf("%s/api/v1/tools/netem/show?labName=%s&nodeName=srl1", s.cfg.APIURL, labName)
		body, status, err := s.doRequest("GET", showURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusOK, status, "Body: %s", string(body))
		var resp map[string][]map[string]interface{}
		s.Require().NoError(json.Unmarshal(body, &resp), "Body: %s", string(body))
		return resp["srl1"]
	}

	body, status := post("set", map[string]interface{}{"labName": labName, "nodeName": "srl1", "interface": "eth1", "delay": "15ms"})
	s.Require().Equal(http.StatusOK, status, "Expected 200 setting netem on stitched interface. Body: %s", string(body))
	time.Sleep(500 * time.Millisecond)

	var hostEntry map[string]interface{}
	for _, entry := range show() {
		if entry["interface"] == "eth1 (host)" {
			hostEntry = entry
		}
	}
	s.Require().NotNil(hostEntry, "Expected impairment on the host side of the stitch: %v", show())
	s.Require().Equal("15ms", hostEntry["delay"])

	body, status = post("reset", map[string]interface{}{"labName": labName, "nodeName": "srl1", "interface": "eth1"})
	s.Require().Equal(http.StatusOK, status, "Expected 200 resetting stitched interface. Body: %s", string(body))
	time.Sleep(500 * time.Millisecond)
	for _, entry := range show() {
		s.Require().NotEqual("eth1 (host)", entry["interface"], "Expected host-side impairment to be removed")
	}
}

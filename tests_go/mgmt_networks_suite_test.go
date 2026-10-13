// tests_go/mgmt_networks_suite_test.go
package tests_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// MgmtNetworksSuite tests management network handling introduced with containerlab 0.80:
// topologies with several management networks, deploy-time management overrides,
// the per-node management network in inspect output, and the lab Tailscale status.
type MgmtNetworksSuite struct {
	BaseSuite

	apiUserHeaders http.Header
}

func TestMgmtNetworksSuite(t *testing.T) {
	suite.Run(t, new(MgmtNetworksSuite))
}

func (s *MgmtNetworksSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	s.apiUserHeaders = s.getAuthHeaders(s.login(s.cfg.APIUserUser, s.cfg.APIUserPass))
}

// deployWithQuery deploys topology content with extra deploy query parameters.
func (s *MgmtNetworksSuite) deployWithQuery(topology map[string]interface{}, query url.Values) ([]byte, int) {
	s.T().Helper()

	reqURL, err := url.Parse(fmt.Sprintf("%s/api/v1/labs", s.cfg.APIURL))
	s.Require().NoError(err)
	reqURL.RawQuery = query.Encode()

	payload := s.mustMarshal(map[string]interface{}{"topologyContent": topology})
	bodyBytes, statusCode, err := s.doRequest("POST", reqURL.String(), s.apiUserHeaders, bytes.NewBuffer(payload), s.cfg.DeployTimeout)
	s.Require().NoError(err)
	return bodyBytes, statusCode
}

func (s *MgmtNetworksSuite) inspectNodes(labName string) map[string]ClabContainerInfo {
	s.T().Helper()

	inspectURL := fmt.Sprintf("%s/api/v1/labs/%s", s.cfg.APIURL, labName)
	bodyBytes, statusCode, err := s.doRequest("GET", inspectURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, statusCode, "Expected 200 inspecting lab '%s'. Body: %s", labName, string(bodyBytes))

	var containers []ClabContainerInfo
	s.Require().NoError(json.Unmarshal(bodyBytes, &containers), "Body: %s", string(bodyBytes))

	nodes := make(map[string]ClabContainerInfo, len(containers))
	for _, container := range containers {
		nodes[container.NodeName] = container
	}
	return nodes
}

func (s *MgmtNetworksSuite) requireAddressIn(node ClabContainerInfo, subnet string) {
	s.T().Helper()

	addr, err := netip.ParsePrefix(node.IPv4Address)
	s.Require().NoError(err, "node %q has no IPv4 management address", node.NodeName)
	s.Require().True(netip.MustParsePrefix(subnet).Contains(addr.Addr()),
		"node %q address %s is outside %s", node.NodeName, node.IPv4Address, subnet)
}

func linuxNode(extra map[string]interface{}) map[string]interface{} {
	node := map[string]interface{}{
		"kind":  "linux",
		"image": "ghcr.io/srl-labs/network-multitool:latest",
	}
	for key, value := range extra {
		node[key] = value
	}
	return node
}

func (s *MgmtNetworksSuite) TestMultipleMgmtNetworks() {
	labName := fmt.Sprintf("%s-mgmt-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	oobNet, inbandNet := labName+"-oob", labName+"-inb"
	oobSubnet, inbandSubnet := "172.31.230.0/24", "172.31.231.0/24"

	topology := map[string]interface{}{
		"name": labName,
		"mgmt": []map[string]interface{}{
			{"network": oobNet, "ipv4-subnet": oobSubnet},
			{"network": inbandNet, "ipv4-subnet": inbandSubnet},
		},
		"topology": map[string]interface{}{
			"nodes": map[string]interface{}{
				"n1": linuxNode(map[string]interface{}{"mgmt-net": oobNet}),
				"n2": linuxNode(map[string]interface{}{"mgmt-net": inbandNet}),
			},
			"links": []map[string]interface{}{
				{"endpoints": []string{"n1:eth1", "n2:eth1"}},
			},
		},
	}

	bodyBytes, statusCode := s.deployWithQuery(topology, nil)
	s.Require().Equal(http.StatusOK, statusCode, "Expected deploy with two mgmt networks to succeed. Body: %s", string(bodyBytes))
	defer s.cleanupLab(labName, true)
	time.Sleep(s.cfg.StabilizePause)

	nodes := s.inspectNodes(labName)
	s.Require().Contains(nodes, "n1")
	s.Require().Contains(nodes, "n2")
	s.Require().Equal(oobNet, nodes["n1"].MgmtNetwork)
	s.Require().Equal(inbandNet, nodes["n2"].MgmtNetwork)
	s.requireAddressIn(nodes["n1"], oobSubnet)
	s.requireAddressIn(nodes["n2"], inbandSubnet)

	// A lab without Tailscale reports no devices.
	tsURL := fmt.Sprintf("%s/api/v1/labs/%s/tailscale", s.cfg.APIURL, labName)
	tsBody, tsStatus, err := s.doRequest("GET", tsURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, tsStatus, "Body: %s", string(tsBody))
	var tsResp struct {
		LabName string        `json:"labName"`
		Devices []interface{} `json:"devices"`
	}
	s.Require().NoError(json.Unmarshal(tsBody, &tsResp), "Body: %s", string(tsBody))
	s.Require().Equal(labName, tsResp.LabName)
	s.Require().Empty(tsResp.Devices)

	// Management overrides are ambiguous with several networks; redeploy must
	// reject them before destroying the lab.
	redeployBody, redeployStatus, err := s.redeployLab(s.apiUserHeaders, labName, map[string]string{"network": "other"}, s.cfg.DeployTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusBadRequest, redeployStatus, "Expected 400 for mgmt override on multi-network lab. Body: %s", string(redeployBody))
	s.assertJSONError(redeployBody, "multiple management networks")

	nodes = s.inspectNodes(labName)
	s.Require().Len(nodes, 2, "lab must stay deployed after the rejected redeploy")

	destroyBody, destroyStatus, err := s.destroyLab(s.apiUserHeaders, labName, true, s.cfg.CleanupTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, destroyStatus, "Expected destroy of multi-network lab to succeed. Body: %s", string(destroyBody))
}

func (s *MgmtNetworksSuite) TestDeployMgmtOverrides() {
	labName := fmt.Sprintf("%s-mgov-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	// Override both subnets: containerlab destroy recreates the topology's
	// default network, which must not collide with the overridden one.
	network, subnet, subnet6 := labName+"-net", "172.31.232.0/24", "3fff:172:31:232::/64"

	topology := map[string]interface{}{
		"name": labName,
		"topology": map[string]interface{}{
			"nodes": map[string]interface{}{"n1": linuxNode(nil)},
		},
	}

	bodyBytes, statusCode := s.deployWithQuery(topology, url.Values{
		"network": {network}, "ipv4Subnet": {subnet}, "ipv6Subnet": {subnet6},
	})
	s.Require().Equal(http.StatusOK, statusCode, "Expected deploy with mgmt overrides to succeed. Body: %s", string(bodyBytes))
	defer s.cleanupLab(labName, true)
	time.Sleep(s.cfg.StabilizePause)

	nodes := s.inspectNodes(labName)
	s.Require().Contains(nodes, "n1")
	s.Require().Equal(network, nodes["n1"].MgmtNetwork)
	s.requireAddressIn(nodes["n1"], subnet)

	destroyBody, destroyStatus, err := s.destroyLab(s.apiUserHeaders, labName, true, s.cfg.CleanupTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, destroyStatus, "Expected destroy of overridden lab to succeed. Body: %s", string(destroyBody))
}

func (s *MgmtNetworksSuite) TestDeployRejectsInvalidMgmtOverrides() {
	topology := map[string]interface{}{
		"name":     fmt.Sprintf("%s-mgbad-%s", s.cfg.LabNamePrefix, s.randomSuffix(5)),
		"topology": map[string]interface{}{"nodes": map[string]interface{}{"n1": linuxNode(nil)}},
	}

	for param, value := range map[string]string{
		"network":    "bad network",
		"ipv4Subnet": "3fff::/64",
		"ipv6Subnet": "172.31.233.0/24",
	} {
		bodyBytes, statusCode := s.deployWithQuery(topology, url.Values{param: {value}})
		s.Require().Equal(http.StatusBadRequest, statusCode, "Expected 400 for %s=%s. Body: %s", param, value, string(bodyBytes))
		s.Require().True(strings.Contains(string(bodyBytes), param), "Expected error to name %s. Body: %s", param, string(bodyBytes))
	}
}

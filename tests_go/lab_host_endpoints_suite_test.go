package tests_go

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// LabHostEndpointsSuite proves that host-namespace endpoints (the vx-*/ve-* interfaces of
// vxlan-stitch links, host links) do not leak from one request into the next inside the
// long-lived server process. Before the fix, the second deploy below failed with
// "duplicate endpoint host:vx-..." and, after a failed deploy, any deploy at all failed with
// "root network namespace endpoint ... defined by multiple nodes [host, host]".
type LabHostEndpointsSuite struct {
	BaseSuite
}

func TestLabHostEndpointsSuite(t *testing.T) {
	suite.Run(t, new(LabHostEndpointsSuite))
}

// createLab expects the topology as JSON
const vxlanStitchTopology = `{
  "name": "{lab_name}",
  "topology": {
    "nodes": { "{node}": { "kind": "linux", "image": "ghcr.io/srl-labs/network-multitool:latest" } },
    "links": [ { "type": "vxlan-stitch", "endpoint": { "node": "{node}", "interface": "eth1" },
                 "remote": "192.0.2.1", "vni": 65001, "dst-port": 4789 } ]
  }
}`

// two nodes claiming the same host interface name: rejected at parse time, nothing deployed
const clashingHostLinkTopology = `{
  "name": "{lab_name}",
  "topology": {
    "nodes": { "a": { "kind": "linux", "image": "ghcr.io/srl-labs/network-multitool:latest" },
               "b": { "kind": "linux", "image": "ghcr.io/srl-labs/network-multitool:latest" } },
    "links": [ { "endpoints": ["a:eth1", "host:{lab_name}-h"] },
               { "endpoints": ["b:eth1", "host:{lab_name}-h"] } ]
  }
}`

// the host-side vxlan interface is named vx-<node>_<iface>; a node name unique to this run keeps a
// leftover from an interrupted earlier run from colliding with it
func (s *LabHostEndpointsSuite) deployVxlan(headers http.Header, labName string) (int, string) {
	node := "n" + labName[strings.LastIndex(labName, "-")+1:]
	topo := strings.ReplaceAll(strings.ReplaceAll(vxlanStitchTopology, "{lab_name}", labName), "{node}", node)
	body, code, err := s.createLab(headers, labName, topo, false, s.cfg.DeployTimeout)
	s.Require().NoError(err)
	return code, string(body)
}

func (s *LabHostEndpointsSuite) TestVxlanStitchDeploysTwice() {
	headers := s.getAuthHeaders(s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass))
	labName := fmt.Sprintf("%s-vx-%d", s.cfg.LabNamePrefix, time.Now().UnixNano()%100000)
	defer s.cleanupLab(labName, true)

	s.logTest("first vxlan-stitch deploy of '%s'", labName)
	code, body := s.deployVxlan(headers, labName)
	s.Require().Equal(http.StatusOK, code, "first deploy must succeed: %s", body)

	s.logTest("destroy '%s'", labName)
	_, code, err := s.destroyLab(headers, labName, true, s.cfg.CleanupTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, code)

	s.logTest("second vxlan-stitch deploy of '%s' in the same server process", labName)
	code, body = s.deployVxlan(headers, labName)
	s.Require().Equal(http.StatusOK, code, "second deploy must succeed (leaked host endpoints): %s", body)
	s.logSuccess("vxlan-stitch lab deployed twice")
}

func (s *LabHostEndpointsSuite) TestPlainDeployAfterFailedHostLinkParse() {
	headers := s.getAuthHeaders(s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass))
	bad := fmt.Sprintf("%s-bad-%d", s.cfg.LabNamePrefix, time.Now().UnixNano()%100000)
	good := fmt.Sprintf("%s-ok-%d", s.cfg.LabNamePrefix, time.Now().UnixNano()%100000)
	defer s.cleanupLab(good, true)

	s.logTest("deploy of '%s' must fail at parse time (two nodes, one host interface)", bad)
	topo := strings.ReplaceAll(clashingHostLinkTopology, "{lab_name}", bad)
	body, code, err := s.createLab(headers, bad, topo, false, s.cfg.DeployTimeout)
	s.Require().NoError(err)
	s.Require().NotEqual(http.StatusOK, code, "clashing host links must be rejected: %s", string(body))

	s.logTest("a plain lab '%s' must still deploy afterwards", good)
	topo = strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", good)
	body, code, err = s.createLab(headers, good, topo, false, s.cfg.DeployTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, code, "plain deploy after a failed parse must succeed: %s", string(body))
	s.logSuccess("plain lab deployed after a failed host-link parse")
}

// A lab whose management network sits on a named bridge makes containerlab rename its process-wide
// mgmt-net node to that bridge (links.SetMgmtNetUnderlyingBridge, called by deploy, destroy, exec
// and save) and nothing renames it back. In the next request that node is registered under the
// bridge's name and shadows a topology bridge node of the same name: the link to it resolves to the
// special node, whose side nothing deploys, and the veth is left half-made without an error.
// Docker creates the bridge named here for the management network, so the lab is self-contained.
const mgmtBridgeLabTopology = `{
  "name": "{lab_name}",
  "mgmt": { "network": "{lab_name}", "bridge": "{br}", "ipv4-subnet": "{subnet}" },
  "topology": {
    "nodes": { "{br}": { "kind": "bridge" },
               "n1": { "kind": "linux", "image": "ghcr.io/srl-labs/network-multitool:latest" } },
    "links": [ { "endpoints": ["n1:eth1", "{br}:{br}-n1"] } ]
  }
}`

// the container side of a veth whose other end was never attached and brought up shows NO-CARRIER
func (s *LabHostEndpointsSuite) eth1HasCarrier(headers http.Header, labName string) bool {
	body, code, err := s.doRequest("POST", fmt.Sprintf("%s/api/v1/labs/%s/exec", s.cfg.APIURL, labName), headers,
		bytes.NewBufferString(`{"command":"ip -o link show eth1"}`), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, code, "exec must work: %s", string(body))
	return strings.Contains(string(body), "LOWER_UP")
}

func (s *LabHostEndpointsSuite) TestBridgeLinkAfterMgmtBridgeLab() {
	headers := s.getAuthHeaders(s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass))
	n := time.Now().UnixNano() % 100000
	labName := fmt.Sprintf("%s-br-%d", s.cfg.LabNamePrefix, n)
	br := fmt.Sprintf("tbr%d", n)
	topo := strings.NewReplacer("{lab_name}", labName, "{br}", br,
		"{subnet}", fmt.Sprintf("10.213.%d.0/24", n%200+1)).Replace(mgmtBridgeLabTopology)
	defer s.cleanupLab(labName, true)

	for i := 1; i <= 2; i++ {
		s.logTest("deploy %d of '%s': management network on bridge %s and a link to that bridge", i, labName, br)
		body, code, err := s.createLab(headers, labName, topo, false, s.cfg.DeployTimeout)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusOK, code, "deploy %d must succeed: %s", i, string(body))
		s.Require().True(s.eth1HasCarrier(headers, labName),
			"deploy %d: n1:eth1 has no carrier, the bridge side of the link was never attached (leaked mgmt-net node name)", i)
		if i == 1 {
			_, code, err = s.destroyLab(headers, labName, true, s.cfg.CleanupTimeout)
			s.Require().NoError(err)
			s.Require().Equal(http.StatusOK, code)
		}
	}
	s.logSuccess("bridge link formed on both deploys")
}

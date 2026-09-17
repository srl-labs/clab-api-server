package tests_go

import (
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

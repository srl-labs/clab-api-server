package clab

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clabconst "github.com/srl-labs/containerlab/constants"
	clabcore "github.com/srl-labs/containerlab/core"
	clabnodes "github.com/srl-labs/containerlab/nodes"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	clabtypes "github.com/srl-labs/containerlab/types"
	"gopkg.in/yaml.v3"

	"github.com/srl-labs/clab-api-server/internal/models"
)

func TestGenerateTopologyConfigKeepsMgmtBlock(t *testing.T) {
	s := &Service{}

	b, err := s.generateTopologyConfig(
		"demo", "custom-mgmt", "172.30.30.0/24", "<nil>",
		nil, nil, clabnodes.NewNodeRegistry(), "node", "tier",
		nodesDef{numNodes: 1, kind: "linux"},
	)
	if err != nil {
		t.Fatalf("generateTopologyConfig() error = %v", err)
	}

	var parsed struct {
		Mgmt struct {
			Network    string `yaml:"network"`
			IPv4Subnet string `yaml:"ipv4-subnet"`
		} `yaml:"mgmt"`
	}
	if err := yaml.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("generated topology is not a single mgmt map: %v\n%s", err, b)
	}
	if parsed.Mgmt.Network != "custom-mgmt" {
		t.Fatalf("mgmt.network = %q, want custom-mgmt\n%s", parsed.Mgmt.Network, b)
	}
	if parsed.Mgmt.IPv4Subnet != "172.30.30.0/24" {
		t.Fatalf("mgmt.ipv4-subnet = %q, want 172.30.30.0/24\n%s", parsed.Mgmt.IPv4Subnet, b)
	}
	if strings.Contains(string(b), "ipv6-subnet") {
		t.Fatalf("unset IPv6 subnet must not be rendered\n%s", b)
	}
}

func TestWithoutInternalContainersDropsHelperContainers(t *testing.T) {
	containers := []clabruntime.GenericContainer{
		{Names: []string{"clab-demo-sr1"}, Labels: map[string]string{}},
		{
			Names:  []string{"clab-demo-sr1-netns"},
			Labels: map[string]string{clabconst.InternalNode: "true"},
		},
		{Names: []string{"clab-demo-client"}},
	}

	got := withoutInternalContainers(containers)
	if len(got) != 2 {
		t.Fatalf("got %d containers, want 2: %+v", len(got), got)
	}
	for _, c := range got {
		if isInternalContainer(c) {
			t.Fatalf("internal container %q was kept", c.Names[0])
		}
	}
}

func TestMgmtOverridesRejectedForMultipleMgmtNetworks(t *testing.T) {
	topoPath := filepath.Join(t.TempDir(), "multi.clab.yml")
	topology := `name: multi
mgmt:
  - network: oob
    ipv4-subnet: 172.30.30.0/24
  - network: inband
    ipv4-subnet: 172.30.31.0/24
topology:
  nodes:
    n1:
      kind: linux
      image: alpine
      mgmt-net: oob
`
	if err := os.WriteFile(topoPath, []byte(topology), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := newContainerLab(
		clabcore.WithTopoPath(topoPath, nil),
		clabcore.WithManagementNetworkName("other"),
	)
	if !errors.Is(wrapMgmtOverrideError(err), ErrMgmtOverrideUnsupported) {
		t.Fatalf("override error = %v, want ErrMgmtOverrideUnsupported", err)
	}

	lab, err := newContainerLab(clabcore.WithTopoPath(topoPath, nil))
	if err != nil {
		t.Fatalf("loading topology without overrides: %v", err)
	}
	if got := lab.Config.Mgmt.Network; got != "oob" {
		t.Fatalf("default mgmt network = %q, want the first list entry oob", got)
	}
}

func TestMgmtOverrideOptionsApplyToTopology(t *testing.T) {
	topoPath := filepath.Join(t.TempDir(), "single.clab.yml")
	if err := os.WriteFile(topoPath, []byte("name: single\ntopology:\n  nodes:\n    n1:\n      kind: linux\n      image: alpine\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	clabOpts := append([]clabcore.ClabOption{clabcore.WithTopoPath(topoPath, nil)}, mgmtOverrideOptions(DeployOptions{
		MgmtNetwork:    "lab-mgmt",
		MgmtIPv4Subnet: "172.30.40.0/24",
		MgmtIPv6Subnet: "3fff:172:30:40::/64",
	})...)
	lab, err := newContainerLab(clabOpts...)
	if err != nil {
		t.Fatal(err)
	}

	mgmt := lab.Config.Mgmt
	if mgmt.Network != "lab-mgmt" || mgmt.IPv4Subnet != "172.30.40.0/24" || mgmt.IPv6Subnet != "3fff:172:30:40::/64" {
		t.Fatalf("mgmt = %+v, want overrides applied", mgmt)
	}
}

func TestContainerToClabContainerInfoReportsMgmtNetworkAndPorts(t *testing.T) {
	info := ContainerToClabContainerInfo(clabruntime.GenericContainer{
		Names:       []string{"clab-demo-n1"},
		NetworkName: "oob",
		Labels:      map[string]string{clabconst.Containerlab: "demo"},
		Ports: []*clabtypes.GenericPortBinding{
			{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
			nil,
		},
	})
	if info.MgmtNetwork != "oob" {
		t.Fatalf("mgmt network = %q, want oob", info.MgmtNetwork)
	}
	if len(info.Ports) != 1 || info.Ports[0] != (models.ClabPortBinding{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}) {
		t.Fatalf("ports = %+v", info.Ports)
	}

	if info := ContainerToClabContainerInfo(clabruntime.GenericContainer{NetworkName: "unknown"}); info.MgmtNetwork != "" {
		t.Fatalf("unknown network reported as %q", info.MgmtNetwork)
	}
}

func TestTailscaleDeviceClassification(t *testing.T) {
	tests := []struct {
		name     string
		labels   map[string]string
		wantRole string
		wantNode string
		wantOK   bool
	}{
		{
			name:     "sso proxy",
			labels:   map[string]string{clabconst.ToolType: "tailscale", clabconst.InternalNode: "true"},
			wantRole: models.TailscaleRoleProxy, wantOK: true,
		},
		{
			name: "auth-key sidecar",
			labels: map[string]string{
				clabconst.NodeKind: "tailscale", clabconst.InternalNode: "true",
				"clab-tailscale-parent": "srl1", clabconst.NodeName: "srl1-ts",
			},
			wantRole: models.TailscaleRoleSidecar, wantNode: "srl1", wantOK: true,
		},
		{
			name:     "tailscale kind node",
			labels:   map[string]string{clabconst.NodeKind: "tailscale", clabconst.NodeName: "ts1"},
			wantRole: models.TailscaleRoleNode, wantNode: "ts1", wantOK: true,
		},
		{
			name:   "regular node",
			labels: map[string]string{clabconst.NodeKind: "linux", clabconst.NodeName: "n1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device, ok := tailscaleDevice(clabruntime.GenericContainer{Names: []string{"c"}, Labels: tt.labels})
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && (device.Role != tt.wantRole || device.NodeName != tt.wantNode) {
				t.Fatalf("device = %+v, want role %q node %q", device, tt.wantRole, tt.wantNode)
			}
		})
	}
}

func TestTailscaleForwardsReadsServeConfig(t *testing.T) {
	stateDir := t.TempDir()
	serve := `{"TCP":{"2201":{"TCPForward":"172.20.20.2:22"},"8443":{"TCPForward":"[3fff:172:20:20::3]:443"},"bad":{"TCPForward":"x"}}}`
	if err := os.WriteFile(filepath.Join(stateDir, "serve.json"), []byte(serve), 0o600); err != nil {
		t.Fatal(err)
	}

	proxy := clabruntime.GenericContainer{
		Mounts: []clabruntime.ContainerMount{{Source: stateDir, Destination: tailscaleStateDir}},
	}
	containers := []clabruntime.GenericContainer{
		{Labels: map[string]string{clabconst.NodeName: "srl1"}, NetworkSettings: clabruntime.GenericMgmtIPs{IPv4addr: "172.20.20.2"}},
		{Labels: map[string]string{clabconst.NodeName: "srl2"}, NetworkSettings: clabruntime.GenericMgmtIPs{IPv6addr: "3fff:172:20:20::3"}},
	}

	got := tailscaleForwards(proxy, containers)
	want := []models.TailscaleForward{
		{ListenPort: 2201, Target: "172.20.20.2:22", NodeName: "srl1"},
		{ListenPort: 8443, Target: "[3fff:172:20:20::3]:443", NodeName: "srl2"},
	}
	if len(got) != len(want) {
		t.Fatalf("forwards = %+v, want %+v", got, want)
	}
	for idx := range want {
		if got[idx] != want[idx] {
			t.Fatalf("forward %d = %+v, want %+v", idx, got[idx], want[idx])
		}
	}

	if forwards := tailscaleForwards(clabruntime.GenericContainer{}, containers); forwards != nil {
		t.Fatalf("proxy without state mount returned %+v", forwards)
	}
}

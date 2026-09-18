package clab

import (
	"testing"

	clabconst "github.com/srl-labs/containerlab/constants"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	clabtypes "github.com/srl-labs/containerlab/types"
	"github.com/vishvananda/netlink"
)

func TestCaptureInterfacesVerifyStitchAssociation(t *testing.T) {
	tests := []struct {
		name      string
		lab       string
		node      string
		rootNode  string
		ifaceName string
		alias     string
		index     int
		wantHost  bool
	}{
		{name: "stitch endpoint", lab: "demo", node: "sros", ifaceName: "clab-s-12345678", alias: "1/1/c1/1", index: 42, wantHost: true},
		{name: "distributed node component", lab: "demo", node: "sros-1", rootNode: "sros", ifaceName: "clab-s-12345678", alias: "1/1/c1/1", index: 42, wantHost: true},
		{name: "ordinary interface with stitch name", lab: "other", node: "probe", ifaceName: "clab-s-12345678", index: 2},
		{name: "same name and alias in another lab", lab: "other", node: "sros", ifaceName: "clab-s-12345678", alias: "1/1/c1/1", index: 42},
		{name: "same name and alias on another node", lab: "demo", node: "probe", ifaceName: "clab-s-12345678", alias: "1/1/c1/1", index: 42},
		{name: "different endpoint alias", lab: "demo", node: "sros", ifaceName: "clab-s-12345678", alias: "1/1/c2/1", index: 42},
		{name: "unrelated interface name", lab: "demo", node: "sros", ifaceName: "eth1", alias: "1/1/c1/1", index: 42},
		{name: "stale interface index", lab: "demo", node: "sros", ifaceName: "clab-s-12345678", alias: "1/1/c1/1", index: 41},
		{name: "missing lab identity", node: "sros", ifaceName: "clab-s-12345678", alias: "1/1/c1/1", index: 42},
		{name: "missing node identity", lab: "demo", ifaceName: "clab-s-12345678", alias: "1/1/c1/1", index: 42},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const containerName = "test-container"
			containers := []clabruntime.GenericContainer{{
				Names: []string{containerName},
				Labels: map[string]string{
					clabconst.Containerlab: tt.lab,
					clabconst.NodeName:     tt.node,
					clabconst.RootNodeName: tt.rootNode,
				},
			}}
			inspected := []*clabtypes.ContainerInterfaces{{
				ContainerName: containerName,
				Interfaces: []*clabtypes.ContainerInterfaceDetails{{
					InterfaceName:  tt.ifaceName,
					InterfaceAlias: tt.alias,
					InterfaceIndex: tt.index,
				}},
			}}
			lookup := func(lab, node, iface string) (netlink.Link, bool) {
				if lab != "demo" || node != "sros" || iface != "1/1/c1/1" {
					return nil, false
				}
				return &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "clab-s-12345678", Index: 42}}, true
			}
			got := captureInterfacesByContainer(containers, inspected, lookup)[containerName]
			if len(got) != 1 {
				t.Fatalf("got %d interfaces, want 1", len(got))
			}
			want := CaptureInterface{Name: tt.ifaceName, Alias: tt.alias, HostNetworkNamespace: tt.wantHost}
			if got[0] != want {
				t.Fatalf("capture interface = %#v, want %#v", got[0], want)
			}
		})
	}
}

package api

import (
	"testing"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

func TestResolveCaptureInterfacePrefersStitchPeerByAlias(t *testing.T) {
	interfaces := map[string][]clab.CaptureInterface{
		"clab-demo-sros1": {
			{Name: "clab-s-12345678", Alias: "1/1/c1/1", HostNetworkNamespace: true},
		},
	}

	name, hostNetns := resolveCaptureInterface(interfaces, "clab-demo-sros1", "1/1/c1/1")
	if name != "clab-s-12345678" {
		t.Fatalf("resolved interface = %q, want host-side stitch peer", name)
	}
	if !hostNetns {
		t.Fatal("expected stitch peer to use the host network namespace")
	}
}

func TestResolveCaptureInterfaceKeepsContainerInterface(t *testing.T) {
	interfaces := map[string][]clab.CaptureInterface{
		"clab-demo-srl1": {
			{Name: "eth1", Alias: "e1-1"},
		},
	}

	name, hostNetns := resolveCaptureInterface(interfaces, "clab-demo-srl1", "e1-1")
	if name != "eth1" {
		t.Fatalf("resolved interface = %q, want container interface", name)
	}
	if hostNetns {
		t.Fatal("ordinary interface must stay in the container network namespace")
	}
}

func TestResolveCaptureInterfaceDoesNotTrustUnknownStitchName(t *testing.T) {
	name, hostNetns := resolveCaptureInterface(
		map[string][]clab.CaptureInterface{},
		"clab-demo-node1",
		"clab-s-deadbeef",
	)

	if name != "clab-s-deadbeef" {
		t.Fatalf("resolved interface = %q, want the original name", name)
	}
	if hostNetns {
		t.Fatal("unknown stitch interface must not select the host network namespace")
	}
}

func TestResolveCaptureInterfaceKeepsUnverifiedStitchNameInContainer(t *testing.T) {
	interfaces := map[string][]clab.CaptureInterface{
		"clab-demo-node1": {
			{Name: "clab-s-12345678", Alias: "eth1"},
		},
	}
	for _, requested := range []string{"clab-s-12345678", "eth1"} {
		name, hostNetns := resolveCaptureInterface(interfaces, "clab-demo-node1", requested)
		if name != "clab-s-12345678" || hostNetns {
			t.Fatalf("resolve %q = (%q, %v), want container-scoped interface", requested, name, hostNetns)
		}
	}
}

func TestResolveCaptureTargetKeepsNodeNamespacePort(t *testing.T) {
	interfaces := map[string][]clab.CaptureInterface{
		"clab-demo-srl1": {
			{Name: "clab-s-12345678", Alias: "e1-1", HostNetworkNamespace: true},
			{Name: "mgmt0"},
		},
	}

	name, hostNetns := resolveCaptureTargetInterface(interfaces, "clab-demo-srl1", models.CaptureTarget{
		ContainerName: "clab-demo-srl1",
		InterfaceName: "e1-1",
		NodeNamespace: true,
	})
	if name != "e1-1" {
		t.Fatalf("resolved interface = %q, want the port inside the node", name)
	}
	if hostNetns {
		t.Fatal("node-namespace target must stay in the container network namespace")
	}
}

func TestResolveCaptureTargetResolvesAliasByDefault(t *testing.T) {
	interfaces := map[string][]clab.CaptureInterface{
		"clab-demo-srl1": {
			{Name: "clab-s-12345678", Alias: "e1-1", HostNetworkNamespace: true},
		},
	}

	name, hostNetns := resolveCaptureTargetInterface(interfaces, "clab-demo-srl1", models.CaptureTarget{
		ContainerName: "clab-demo-srl1",
		InterfaceName: "e1-1",
	})
	if name != "clab-s-12345678" || !hostNetns {
		t.Fatalf("resolved %q (host netns %v), want the stitch peer in the host namespace", name, hostNetns)
	}
}

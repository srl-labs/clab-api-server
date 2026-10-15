package clab

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/srl-labs/clab-api-server/internal/models"
)

func fakeLink(linkType string, attrs netlink.LinkAttrs) netlink.Link {
	switch linkType {
	case "veth":
		return &netlink.Veth{LinkAttrs: attrs}
	case "macvlan":
		return &netlink.Macvlan{LinkAttrs: attrs}
	case "bridge":
		return &netlink.Bridge{LinkAttrs: attrs}
	default:
		return &netlink.Device{LinkAttrs: attrs}
	}
}

func TestBuildLabLinks(t *testing.T) {
	mac, err := net.ParseMAC("aa:c1:ab:00:00:01")
	require.NoError(t, err)

	host := &nsSnapshot{id: "host", host: true, links: []netlink.Link{
		fakeLink("bridge", netlink.LinkAttrs{Index: 3, Name: "br-clab", NetNsID: -1}),
		fakeLink("veth", netlink.LinkAttrs{Index: 10, Name: "veth1234", MasterIndex: 3, ParentIndex: 2, NetNsID: 0}),
		fakeLink("device", netlink.LinkAttrs{Index: 2, Name: "enp1s0", NetNsID: -1}),
	}}
	srl1 := &nsSnapshot{id: "ns1", node: "srl1", container: "clab-demo-srl1",
		peers: map[int]string{0: "host", 1: "ns2"},
		links: []netlink.Link{
			fakeLink("device", netlink.LinkAttrs{Index: 1, Name: "lo", NetNsID: -1}),
			// Peer in another lab node, listed by both namespaces.
			fakeLink("veth", netlink.LinkAttrs{Index: 5, Name: "e1-1", Alias: "ethernet-1/1", HardwareAddr: mac, MTU: 9500, ParentIndex: 7, NetNsID: 1}),
			// Management interface plugged into a host bridge.
			fakeLink("veth", netlink.LinkAttrs{Index: 2, Name: "eth0", ParentIndex: 10, NetNsID: 0}),
			// Peer in a namespace outside the lab.
			fakeLink("veth", netlink.LinkAttrs{Index: 6, Name: "e1-2", ParentIndex: 4, NetNsID: 9}),
			// Macvlan on a host interface.
			fakeLink("macvlan", netlink.LinkAttrs{Index: 8, Name: "e1-3", ParentIndex: 2, NetNsID: 0}),
		}}
	srl2 := &nsSnapshot{id: "ns2", node: "srl2", container: "clab-demo-srl2",
		peers: map[int]string{0: "ns1"},
		links: []netlink.Link{
			fakeLink("veth", netlink.LinkAttrs{Index: 7, Name: "e1-1", ParentIndex: 5, NetNsID: 0}),
			// Both ends inside the same node.
			fakeLink("veth", netlink.LinkAttrs{Index: 11, Name: "loopa", ParentIndex: 12, NetNsID: -1}),
			fakeLink("veth", netlink.LinkAttrs{Index: 12, Name: "loopb", ParentIndex: 11, NetNsID: -1}),
		}}

	links := buildLabLinks([]*nsSnapshot{host, srl2, srl1})

	srl1Ep := func(name string, index int) models.LinkEndpoint {
		return models.LinkEndpoint{Namespace: models.LinkNamespaceNode, Node: "srl1", Container: "clab-demo-srl1", Interface: name, IfIndex: index, State: "unknown"}
	}
	srl2Ep := func(name string, index int) models.LinkEndpoint {
		return models.LinkEndpoint{Namespace: models.LinkNamespaceNode, Node: "srl2", Container: "clab-demo-srl2", Interface: name, IfIndex: index, State: "unknown"}
	}
	nodeLink := srl1Ep("e1-1", 5)
	nodeLink.Alias = "ethernet-1/1"
	nodeLink.MAC = "aa:c1:ab:00:00:01"
	nodeLink.MTU = 9500

	require.Equal(t, models.LabLinks{
		{Type: "veth", A: nodeLink, B: srl2Ep("e1-1", 7)},
		{Type: "veth", A: srl1Ep("e1-2", 6), B: models.LinkEndpoint{Namespace: models.LinkNamespaceExternal, IfIndex: 4}},
		{Type: "macvlan", A: srl1Ep("e1-3", 8), B: models.LinkEndpoint{Namespace: models.LinkNamespaceHost, Interface: "enp1s0", IfIndex: 2, State: "unknown"}},
		{Type: "veth", A: srl1Ep("eth0", 2), B: models.LinkEndpoint{Namespace: models.LinkNamespaceHost, Interface: "veth1234", IfIndex: 10, State: "unknown", Master: "br-clab"}},
		{Type: "veth", A: srl2Ep("loopa", 11), B: srl2Ep("loopb", 12)},
	}, links)
}

func TestBuildLabLinksPeerGone(t *testing.T) {
	// The peer namespace is known but the interface vanished between listings.
	links := buildLabLinks([]*nsSnapshot{
		{id: "host", host: true},
		{id: "ns1", node: "srl1", container: "c1", peers: map[int]string{0: "host"}, links: []netlink.Link{
			fakeLink("veth", netlink.LinkAttrs{Index: 2, Name: "eth0", ParentIndex: 10, NetNsID: 0}),
		}},
	})
	require.Len(t, links, 1)
	require.Equal(t, models.LinkEndpoint{Namespace: models.LinkNamespaceHost, IfIndex: 10}, links[0].B)
}

package clab

import (
	"context"
	"fmt"
	"runtime"
	"testing"

	clabconst "github.com/srl-labs/containerlab/constants"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/srl-labs/clab-api-server/internal/models"
)

// nsPathRuntime resolves container namespaces from a fixed map.
type nsPathRuntime struct {
	clabruntime.ContainerRuntime
	paths map[string]string
}

func (r nsPathRuntime) GetNSPath(_ context.Context, name string) (string, error) {
	return r.paths[name], nil
}

// newTestNetNS creates a network namespace without moving the caller into it.
func newTestNetNS(t *testing.T) netns.NsHandle {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := netns.Get()
	require.NoError(t, err)
	defer orig.Close()

	handle, err := netns.New()
	if err != nil {
		t.Skipf("cannot create network namespaces: %v", err)
	}
	require.NoError(t, netns.Set(orig))
	t.Cleanup(func() { _ = handle.Close() })
	return handle
}

func TestListLabLinksResolvesNamespaces(t *testing.T) {
	require.NoError(t, hostNetNSErr)
	nsA := newTestNetNS(t)
	nsB := newTestNetNS(t)
	nsOutside := newTestNetNS(t)

	// The host namespace is the one the test process runs in. Use a dedicated
	// one when the process may touch the real host network.
	hostHandle, err := netlink.NewHandleAt(netns.NsHandle(hostNetNS.Fd()))
	require.NoError(t, err)
	defer hostHandle.Close()
	hostLinks, err := hostHandle.LinkList()
	require.NoError(t, err)
	if len(hostLinks) > 1 {
		t.Skip("run in a fresh network namespace, e.g. unshare -rn go test")
	}

	add := func(link netlink.Link) {
		t.Helper()
		require.NoError(t, hostHandle.LinkAdd(link))
	}
	bridge := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "br-test"}}
	add(bridge)
	add(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "dummy0"}})
	parent, err := hostHandle.LinkByName("dummy0")
	require.NoError(t, err)

	// a:eth1 <-> b:eth1
	add(&netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: "eth1", Namespace: netlink.NsFd(nsA)},
		PeerName:      "eth1",
		PeerNamespace: netlink.NsFd(nsB),
	})
	// a:eth0 <-> host:veth-a on br-test
	add(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth-a", MasterIndex: bridge.Index},
		PeerName:  "tmp-eth0",
	})
	tmp, err := hostHandle.LinkByName("tmp-eth0")
	require.NoError(t, err)
	require.NoError(t, hostHandle.LinkSetNsFd(tmp, int(nsA)))
	aHandle, err := netlink.NewHandleAt(nsA)
	require.NoError(t, err)
	defer aHandle.Close()
	tmp, err = aHandle.LinkByName("tmp-eth0")
	require.NoError(t, err)
	require.NoError(t, aHandle.LinkSetName(tmp, "eth0"))
	// a:eth2 <-> a namespace outside the lab
	add(&netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: "eth2", Namespace: netlink.NsFd(nsA)},
		PeerName:      "outside",
		PeerNamespace: netlink.NsFd(nsOutside),
	})
	// a:eth3 macvlan on host:dummy0
	add(&netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{Name: "eth3", ParentIndex: parent.Attrs().Index, Namespace: netlink.NsFd(nsA)},
		Mode:      netlink.MACVLAN_MODE_BRIDGE,
	})

	rt := nsPathRuntime{paths: map[string]string{
		"clab-demo-a":       fmt.Sprintf("/proc/self/fd/%d", int(nsA)),
		"clab-demo-a-extra": fmt.Sprintf("/proc/self/fd/%d", int(nsA)),
		"clab-demo-b":       fmt.Sprintf("/proc/self/fd/%d", int(nsB)),
	}}
	container := func(name, node string) clabruntime.GenericContainer {
		return clabruntime.GenericContainer{
			Names:   []string{name},
			Labels:  map[string]string{clabconst.Containerlab: "demo", clabconst.NodeName: node},
			Runtime: rt,
		}
	}

	links, err := (&Service{}).ListLabLinks(context.Background(), []clabruntime.GenericContainer{
		container("clab-demo-b", "b"),
		container("clab-demo-a", "a"),
		// Shares a's namespace, so its links must not be listed twice.
		container("clab-demo-a-extra", "a"),
	})
	require.NoError(t, err)

	type end struct{ ns, node, iface, master string }
	type summary struct {
		typ  string
		a, b end
	}
	got := make([]summary, 0, len(links))
	for _, l := range links {
		got = append(got, summary{
			typ: l.Type,
			a:   end{l.A.Namespace, l.A.Node, l.A.Interface, l.A.Master},
			b:   end{l.B.Namespace, l.B.Node, l.B.Interface, l.B.Master},
		})
	}
	require.Equal(t, []summary{
		{"veth", end{models.LinkNamespaceNode, "a", "eth0", ""}, end{models.LinkNamespaceHost, "", "veth-a", "br-test"}},
		{"veth", end{models.LinkNamespaceNode, "a", "eth1", ""}, end{models.LinkNamespaceNode, "b", "eth1", ""}},
		{"veth", end{models.LinkNamespaceNode, "a", "eth2", ""}, end{models.LinkNamespaceExternal, "", "", ""}},
		{"macvlan", end{models.LinkNamespaceNode, "a", "eth3", ""}, end{models.LinkNamespaceHost, "", "dummy0", ""}},
	}, got)
	require.Equal(t, "clab-demo-a", links[0].A.Container)
}

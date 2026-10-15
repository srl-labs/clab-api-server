package clab

import (
	"context"
	"fmt"
	"sort"

	"github.com/charmbracelet/log"
	clabcore "github.com/srl-labs/containerlab/core"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/srl-labs/clab-api-server/internal/models"
)

// nsSnapshot holds the links of one network namespace and the namespaces its
// link-netnsids point to.
type nsSnapshot struct {
	id        string
	host      bool
	node      string
	container string
	links     []netlink.Link
	// peers maps a netnsid as seen from this namespace to the id of the
	// namespace it refers to.
	peers map[int]string
}

// openNS is a namespace opened while reading lab links.
type openNS struct {
	snap   *nsSnapshot
	ns     netns.NsHandle
	owned  bool
	handle *netlink.Handle
}

func (n *openNS) label() string {
	if n.snap.host {
		return "the host namespace"
	}
	return "container " + n.snap.container
}

type linkKey struct {
	ns    string
	index int
}

// ListLabLinks reads the links of the given lab containers from their network
// namespaces. Each veth pair is reported once; peers in the host namespace or
// in namespaces outside the lab are reported as such.
func (s *Service) ListLabLinks(ctx context.Context, containers []clabruntime.GenericContainer) (models.LabLinks, error) {
	if hostNetNSErr != nil {
		return nil, fmt.Errorf("failed to open host network namespace: %w", hostNetNSErr)
	}

	hostNS := netns.NsHandle(hostNetNS.Fd())
	namespaces := []*openNS{{snap: &nsSnapshot{id: hostNS.UniqueId(), host: true}, ns: hostNS}}
	defer func() {
		for _, n := range namespaces {
			if n.handle != nil {
				n.handle.Close()
			}
			if n.owned {
				_ = n.ns.Close()
			}
		}
	}()

	sorted := make([]clabruntime.GenericContainer, 0, len(containers))
	for _, c := range containers {
		if len(c.Names) > 0 && c.Runtime != nil {
			sorted = append(sorted, c)
		}
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Names[0] < sorted[j].Names[0] })

	seen := map[string]bool{hostNS.UniqueId(): true}
	for _, c := range sorted {
		name := c.Names[0]
		nsPath, err := c.Runtime.GetNSPath(ctx, name)
		if err != nil || nsPath == "" {
			log.Warn("skipping links of container without a namespace", "container", name, "err", err)
			continue
		}
		handle, err := netns.GetFromPath(nsPath)
		if err != nil {
			log.Warn("failed to open network namespace", "container", name, "path", nsPath, "err", err)
			continue
		}
		id := handle.UniqueId()
		// Containers sharing a namespace (or the host's) report its links once.
		if seen[id] {
			_ = handle.Close()
			continue
		}
		seen[id] = true
		_, node := clabcore.TopoIdentity(c.Labels)
		namespaces = append(namespaces, &openNS{
			snap:  &nsSnapshot{id: id, node: node, container: name},
			ns:    handle,
			owned: true,
		})
	}

	for _, n := range namespaces {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		handle, err := netlink.NewHandleAt(n.ns)
		if err != nil {
			return nil, fmt.Errorf("failed to open netlink handle for %s: %w", n.label(), err)
		}
		n.handle = handle
		links, err := handle.LinkList()
		if err != nil {
			return nil, fmt.Errorf("failed to list links of %s: %w", n.label(), err)
		}
		n.snap.links = links
	}

	// link-netnsids are relative to the namespace holding the link, so ask
	// each node namespace which id it assigned to every other namespace.
	snapshots := make([]*nsSnapshot, 0, len(namespaces))
	for _, n := range namespaces {
		snapshots = append(snapshots, n.snap)
		if n.snap.host || !hasForeignPeers(n.snap.links) {
			continue
		}
		n.snap.peers = map[int]string{}
		for _, other := range namespaces {
			if other == n {
				continue
			}
			nsid, err := n.handle.GetNetNsIdByFd(int(other.ns))
			if err != nil || nsid < 0 {
				continue
			}
			n.snap.peers[nsid] = other.snap.id
		}
	}

	return buildLabLinks(snapshots), nil
}

func hasForeignPeers(links []netlink.Link) bool {
	for _, l := range links {
		if l.Attrs().NetNsID >= 0 {
			return true
		}
	}
	return false
}

// buildLabLinks pairs up the veth and macvlan interfaces of the node
// namespaces in snapshots with their peers.
func buildLabLinks(snapshots []*nsSnapshot) models.LabLinks {
	byID := make(map[string]*nsSnapshot, len(snapshots))
	index := make(map[linkKey]netlink.Link)
	for _, snap := range snapshots {
		byID[snap.id] = snap
		for _, l := range snap.links {
			index[linkKey{snap.id, l.Attrs().Index}] = l
		}
	}

	nodes := make([]*nsSnapshot, 0, len(snapshots))
	for _, snap := range snapshots {
		if !snap.host {
			nodes = append(nodes, snap)
		}
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].node != nodes[j].node {
			return nodes[i].node < nodes[j].node
		}
		return nodes[i].container < nodes[j].container
	})

	result := models.LabLinks{}
	reported := make(map[linkKey]bool)
	for _, snap := range nodes {
		links := append([]netlink.Link(nil), snap.links...)
		sort.Slice(links, func(i, j int) bool { return links[i].Attrs().Name < links[j].Attrs().Name })

		for _, l := range links {
			linkType := l.Type()
			if linkType != "veth" && linkType != "macvlan" {
				continue
			}
			attrs := l.Attrs()
			key := linkKey{snap.id, attrs.Index}
			if reported[key] {
				continue
			}
			reported[key] = true

			link := models.LabLink{
				Type: linkType,
				A:    linkEndpoint(snap, l, index),
				B:    models.LinkEndpoint{Namespace: models.LinkNamespaceExternal, IfIndex: attrs.ParentIndex},
			}

			peerNS := snap
			if attrs.NetNsID >= 0 {
				peerNS = byID[snap.peers[attrs.NetNsID]]
			}
			if peerNS != nil && attrs.ParentIndex > 0 {
				peerKey := linkKey{peerNS.id, attrs.ParentIndex}
				if peer, ok := index[peerKey]; ok {
					link.B = linkEndpoint(peerNS, peer, index)
					// A macvlan parent can carry several macvlans; only a veth
					// peer is fully described by this link.
					if linkType == "veth" {
						reported[peerKey] = true
					}
				} else {
					link.B.Namespace = namespaceKind(peerNS)
				}
			}

			result = append(result, link)
		}
	}

	return result
}

func namespaceKind(snap *nsSnapshot) string {
	if snap.host {
		return models.LinkNamespaceHost
	}
	return models.LinkNamespaceNode
}

func linkEndpoint(snap *nsSnapshot, l netlink.Link, index map[linkKey]netlink.Link) models.LinkEndpoint {
	attrs := l.Attrs()
	ep := models.LinkEndpoint{
		Namespace: namespaceKind(snap),
		Interface: attrs.Name,
		Alias:     attrs.Alias,
		IfIndex:   attrs.Index,
		MTU:       attrs.MTU,
		State:     attrs.OperState.String(),
	}
	if !snap.host {
		ep.Node = snap.node
		ep.Container = snap.container
	}
	if attrs.HardwareAddr != nil {
		ep.MAC = attrs.HardwareAddr.String()
	}
	if attrs.MasterIndex > 0 {
		if master, ok := index[linkKey{snap.id, attrs.MasterIndex}]; ok {
			ep.Master = master.Attrs().Name
		}
	}
	return ep
}

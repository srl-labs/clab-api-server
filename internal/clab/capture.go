package clab

import (
	clabcore "github.com/srl-labs/containerlab/core"
	clablinks "github.com/srl-labs/containerlab/links"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	clabtypes "github.com/srl-labs/containerlab/types"
	"github.com/vishvananda/netlink"
)

// CaptureInterface describes an inspected interface and its verified capture namespace.
type CaptureInterface struct {
	Name                 string
	Alias                string
	HostNetworkNamespace bool
}

// CaptureInterfacesByContainer verifies host-side interfaces against the stitch
// association published by containerlab for each container's topology identity.
func CaptureInterfacesByContainer(
	containers []clabruntime.GenericContainer,
	inspected []*clabtypes.ContainerInterfaces,
) map[string][]CaptureInterface {
	return captureInterfacesByContainer(containers, inspected, clablinks.ToolsInterface)
}

func captureInterfacesByContainer(
	containers []clabruntime.GenericContainer,
	inspected []*clabtypes.ContainerInterfaces,
	toolsInterface func(lab, node, iface string) (netlink.Link, bool),
) map[string][]CaptureInterface {
	type topologyIdentity struct{ lab, node string }
	identities := make(map[string]topologyIdentity, len(containers))
	for _, container := range containers {
		if len(container.Names) == 0 {
			continue
		}
		lab, node := clabcore.TopoIdentity(container.Labels)
		identities[container.Names[0]] = topologyIdentity{lab: lab, node: node}
	}

	result := make(map[string][]CaptureInterface, len(inspected))
	for _, container := range inspected {
		if container == nil {
			continue
		}
		identity := identities[container.ContainerName]
		for _, iface := range container.Interfaces {
			captureIface := CaptureInterface{
				Name:  iface.InterfaceName,
				Alias: iface.InterfaceAlias,
			}
			// Inspection preserves the topology endpoint as the alias when it
			// substitutes a host stitch interface. Ordinary container interfaces
			// can have the same name, so verify the lab/node/endpoint association
			// and the inspected link rather than trusting a clab-s-* prefix.
			if identity.lab != "" && identity.node != "" && iface.InterfaceAlias != "" {
				if link, ok := toolsInterface(identity.lab, identity.node, iface.InterfaceAlias); ok {
					attrs := link.Attrs()
					captureIface.HostNetworkNamespace = attrs.Name == iface.InterfaceName &&
						attrs.Index == iface.InterfaceIndex
				}
			}
			result[container.ContainerName] = append(result[container.ContainerName], captureIface)
		}
	}
	return result
}

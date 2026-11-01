// internal/clab/converters.go
package clab

import (
	"encoding/json"
	"slices"

	clabconst "github.com/srl-labs/containerlab/constants"
	clabcore "github.com/srl-labs/containerlab/core"
	clabexec "github.com/srl-labs/containerlab/exec"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	clabtypes "github.com/srl-labs/containerlab/types"

	"github.com/srl-labs/clab-api-server/internal/models"
)

// isInternalContainer reports whether a container is a helper containerlab
// creates on behalf of a node rather than a node users interact with.
func isInternalContainer(c clabruntime.GenericContainer) bool {
	return c.Labels[clabconst.InternalNode] == "true"
}

// isInternalNodeConfig reports whether a topology node is a helper containerlab
// adds on its own, such as a Tailscale sidecar.
func isInternalNodeConfig(cfg *clabtypes.NodeConfig) bool {
	return cfg != nil && cfg.Labels[clabconst.InternalNode] == "true"
}

func withoutInternalContainers(containers []clabruntime.GenericContainer) []clabruntime.GenericContainer {
	return slices.DeleteFunc(containers, isInternalContainer)
}

// ContainerToClabContainerInfo converts a containerlab GenericContainer to API ClabContainerInfo.
func ContainerToClabContainerInfo(c clabruntime.GenericContainer) models.ClabContainerInfo {
	name := ""
	if len(c.Names) > 0 {
		name = c.Names[0]
	}
	info := models.ClabContainerInfo{
		Name:        name,
		ContainerID: c.ShortID,
		Image:       c.Image,
		Kind:        c.Labels[clabconst.NodeKind],
		State:       c.State,
		Status:      c.Status,
		IPv4Address: c.GetContainerIPv4(),
		IPv6Address: c.GetContainerIPv6(),
		LabName:     c.Labels[clabconst.Containerlab],
		NodeName:    c.Labels[clabconst.NodeName],
		LabPath:     c.Labels[clabconst.TopoFile],
		AbsLabPath:  c.Labels[clabconst.TopoFile],
		Group:       c.Labels[clabconst.NodeGroup],
		Owner:       c.Labels[clabconst.Owner],
		MgmtNetwork: containerMgmtNetwork(c),
		Ports:       containerPorts(c),
	}
	if workload := c.Workload; workload != nil {
		info.Namespace = workload.Namespace
		info.Pod = workload.Pod
		info.Container = workload.Container
		info.NodeUID = workload.NodeUID
		info.LoadBalancerAddress = workload.LoadBalancerAddress
		for _, port := range workload.ExposedPorts {
			info.ExposedPorts = append(info.ExposedPorts, models.ClabExposedPort{
				Port:       port.Port,
				ExposePort: port.ExposePort,
				Protocol:   port.Protocol,
			})
		}
	}
	return info
}

// containerMgmtNetwork returns the management network name the runtime reports,
// leaving it empty when the runtime could not determine it.
func containerMgmtNetwork(c clabruntime.GenericContainer) string {
	if c.NetworkName == "unknown" {
		return ""
	}
	return c.NetworkName
}

func containerPorts(c clabruntime.GenericContainer) []models.ClabPortBinding {
	if len(c.Ports) == 0 {
		return nil
	}
	ports := make([]models.ClabPortBinding, 0, len(c.Ports))
	for _, port := range c.Ports {
		if port == nil {
			continue
		}
		ports = append(ports, models.ClabPortBinding{
			HostIP:        port.HostIP,
			HostPort:      port.HostPort,
			ContainerPort: port.ContainerPort,
			Protocol:      port.Protocol,
		})
	}
	return ports
}

// ContainersToClabInspectOutput converts a slice of containers to the API inspect output format.
func ContainersToClabInspectOutput(containers []clabruntime.GenericContainer) models.ClabInspectOutput {
	result := make(models.ClabInspectOutput)

	for _, c := range containers {
		labName := c.Labels[clabconst.Containerlab]
		if labName == "" {
			continue
		}

		containerInfo := ContainerToClabContainerInfo(c)
		result[labName] = append(result[labName], containerInfo)
	}

	return result
}

// ApplyOutcomeToResponse converts an apply outcome to the API response model.
func ApplyOutcomeToResponse(outcome *ApplyOutcome) models.ApplyLabResponse {
	if outcome == nil {
		return ApplyResultToResponse(nil)
	}
	response := ApplyResultToResponse(outcome.ApplyResult)
	if plan := outcome.RuntimePlan; plan != nil {
		response.RuntimePlan = &models.LabRuntimePlan{
			Namespace: plan.Namespace,
			Changes:   make([]models.LabRuntimePlanChange, 0, len(plan.Changes)),
		}
		for _, change := range plan.Changes {
			response.RuntimePlan.Changes = append(response.RuntimePlan.Changes, models.LabRuntimePlanChange{
				Action:    string(change.Action),
				Kind:      change.Kind,
				Namespace: change.Namespace,
				Name:      change.Name,
			})
		}
		if response.LabName == "" {
			response.LabName = plan.LabName
		}
	}
	return response
}

// ApplyResultToResponse converts a containerlab apply result to the API response model.
func ApplyResultToResponse(result *clabcore.ApplyResult) models.ApplyLabResponse {
	response := models.ApplyLabResponse{
		AddedNodes:        []string{},
		DeletedNodes:      []string{},
		RecreatedNodes:    []string{},
		StartedNodes:      []string{},
		AddedLinks:        []string{},
		DeletedEndpoints:  []string{},
		RestartedNodes:    []string{},
		NodeChangeReasons: map[string]string{},
	}
	if result == nil {
		return response
	}

	response.DryRun = result.DryRun
	response.DeployedLab = result.DeployedLab
	response.LabName = result.LabName
	response.AddedNodes = cloneStringSlice(result.AddedNodes)
	response.DeletedNodes = cloneStringSlice(result.DeletedNodes)
	response.RecreatedNodes = cloneStringSlice(result.RecreatedNodes)
	response.StartedNodes = cloneStringSlice(result.StartedNodes)
	response.AddedLinks = cloneStringSlice(result.AddedLinks)
	response.DeletedEndpoints = cloneStringSlice(result.DeletedEndpoints)
	response.RestartedNodes = cloneStringSlice(result.RestartedNodes)
	for nodeName, reason := range result.NodeChangeReasons {
		response.NodeChangeReasons[nodeName] = reason
	}

	return response
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return append([]string(nil), values...)
}

// ContainerInterfacesToNodeInterfaceInfo converts containerlab interfaces to API format.
func ContainerInterfacesToNodeInterfaceInfo(ci *clabtypes.ContainerInterfaces) models.NodeInterfaceInfo {
	var interfaces []models.InterfaceInfo

	for _, iface := range ci.Interfaces {
		interfaces = append(interfaces, models.InterfaceInfo{
			Name:    iface.InterfaceName,
			Alias:   iface.InterfaceAlias,
			Mac:     iface.InterfaceMAC,
			IfIndex: iface.InterfaceIndex,
			Mtu:     iface.InterfaceMTU,
			Type:    iface.InterfaceType,
			State:   iface.InterfaceState,
		})
	}

	return models.NodeInterfaceInfo{
		NodeName:   ci.ContainerName,
		Interfaces: interfaces,
	}
}

// ContainersInterfacesToInspectOutput converts a slice of container interfaces to API format.
func ContainersInterfacesToInspectOutput(cis []*clabtypes.ContainerInterfaces) models.ClabInspectInterfacesOutput {
	var result models.ClabInspectInterfacesOutput

	for _, ci := range cis {
		if ci != nil {
			result = append(result, ContainerInterfacesToNodeInterfaceInfo(ci))
		}
	}

	return result
}

// ExecCollectionToExecResponse converts containerlab exec results to API format.
func ExecCollectionToExecResponse(ec *clabexec.ExecCollection) models.ExecResponse {
	result := make(models.ExecResponse)

	if ec == nil {
		return result
	}

	// Use the Dump method to get JSON representation and unmarshal it
	// This is the only way to access the private execEntries map
	jsonStr, err := ec.Dump("json")
	if err != nil || jsonStr == "" {
		return result
	}

	// Define intermediate type matching ExecResult structure from containerlab
	// Note: containerlab uses capital case in JSON output
	type execResult struct {
		Cmd        []string `json:"Cmd"`
		ReturnCode int      `json:"ReturnCode"`
		Stdout     string   `json:"Stdout"`
		Stderr     string   `json:"Stderr"`
	}

	// Unmarshal JSON to map
	var rawResults map[string][]*execResult
	if err := json.Unmarshal([]byte(jsonStr), &rawResults); err != nil {
		return result
	}

	// Convert to API format
	for nodeName, execResults := range rawResults {
		var nodeResults []models.ClabExecInternalResult
		for _, er := range execResults {
			nodeResults = append(nodeResults, models.ClabExecInternalResult{
				Cmd:        er.Cmd,
				ReturnCode: er.ReturnCode,
				Stdout:     er.Stdout,
				Stderr:     er.Stderr,
			})
		}
		result[nodeName] = nodeResults
	}

	return result
}

// GetContainerName safely extracts the container name from a GenericContainer.
func GetContainerName(c *clabruntime.GenericContainer) string {
	if c == nil || len(c.Names) == 0 {
		return ""
	}
	return c.Names[0]
}

// GetContainerNodeName extracts the topology node name from a container's labels.
func GetContainerNodeName(c *clabruntime.GenericContainer) string {
	if c == nil {
		return ""
	}
	return c.Labels[clabconst.NodeName]
}

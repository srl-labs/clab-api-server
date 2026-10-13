package clab

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	clabconst "github.com/srl-labs/containerlab/constants"
	clabexec "github.com/srl-labs/containerlab/exec"
	clabnodestailscale "github.com/srl-labs/containerlab/nodes/tailscale"
	clabruntime "github.com/srl-labs/containerlab/runtime"

	"github.com/srl-labs/clab-api-server/internal/models"
)

const (
	// tailscaleSocket is the containerboot default socket of tailscaled.
	tailscaleSocket = "/tmp/tailscaled.sock"
	// tailscaleStateDir is where the SSO proxy mounts its lab directory.
	tailscaleStateDir    = "/var/lib/tailscale"
	tailscaleExecTimeout = 10 * time.Second
)

// tailscaleStatus is the subset of `tailscale status --json` reported by the API.
type tailscaleStatus struct {
	BackendState string `json:"BackendState"`
	AuthURL      string `json:"AuthURL"`
	Self         *struct {
		HostName     string   `json:"HostName"`
		DNSName      string   `json:"DNSName"`
		TailscaleIPs []string `json:"TailscaleIPs"`
		Online       bool     `json:"Online"`
	} `json:"Self"`
}

// tailscaleServeConfig is the Serve config containerlab writes for the SSO proxy.
type tailscaleServeConfig struct {
	TCP map[string]struct {
		TCPForward string `json:"TCPForward"`
	} `json:"TCP"`
}

// TailscaleStatus reports the Tailscale devices containerlab runs for a lab: the
// SSO proxy, the auth-key sidecars of nodes, and nodes of the tailscale kind.
// These containers are internal helpers, so their state (including the login
// URL the proxy waits on) is not visible through the regular node endpoints.
func (s *Service) TailscaleStatus(ctx context.Context, labName string) ([]models.TailscaleDevice, error) {
	containers, err := s.ListContainers(ctx, ListOptions{LabName: labName, IncludeInternal: true})
	if err != nil {
		return nil, err
	}

	devices := []models.TailscaleDevice{}
	for _, container := range containers {
		device, ok := tailscaleDevice(container)
		if !ok {
			continue
		}
		if container.State == "running" {
			s.fillTailscaleStatus(ctx, container, &device)
		}
		if device.Role == models.TailscaleRoleProxy {
			device.Forwards = tailscaleForwards(container, containers)
		}
		devices = append(devices, device)
	}

	slices.SortFunc(devices, func(a, b models.TailscaleDevice) int {
		return strings.Compare(a.Role+"/"+a.NodeName+"/"+a.ContainerName, b.Role+"/"+b.NodeName+"/"+b.ContainerName)
	})

	return devices, nil
}

// tailscaleDevice classifies a lab container as a Tailscale device.
func tailscaleDevice(container clabruntime.GenericContainer) (models.TailscaleDevice, bool) {
	device := models.TailscaleDevice{
		ContainerName: strings.TrimPrefix(firstContainerName(container), "/"),
		State:         container.State,
	}

	switch {
	case container.Labels[clabconst.ToolType] == clabnodestailscale.ToolType:
		device.Role = models.TailscaleRoleProxy
	case container.Labels[clabconst.NodeKind] == clabnodestailscale.KindName && isInternalContainer(container):
		device.Role = models.TailscaleRoleSidecar
		device.NodeName = container.Labels[clabnodestailscale.ParentLabel]
	case container.Labels[clabconst.NodeKind] == clabnodestailscale.KindName:
		device.Role = models.TailscaleRoleNode
		device.NodeName = container.Labels[clabconst.NodeName]
	default:
		return device, false
	}

	return device, true
}

func firstContainerName(container clabruntime.GenericContainer) string {
	if len(container.Names) == 0 {
		return container.ShortID
	}
	return container.Names[0]
}

// fillTailscaleStatus adds the tailnet state reported by tailscaled in the container.
func (s *Service) fillTailscaleStatus(ctx context.Context, container clabruntime.GenericContainer, device *models.TailscaleDevice) {
	if container.Runtime == nil || len(container.Names) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, tailscaleExecTimeout)
	defer cancel()

	result, err := container.RunExec(ctx, clabexec.NewExecCmdFromSlice(
		[]string{"tailscale", "--socket=" + tailscaleSocket, "status", "--json"},
	))
	if err != nil {
		device.Error = err.Error()
		return
	}

	// `tailscale status` exits non-zero while logged out but still prints the status.
	var status tailscaleStatus
	if err := json.Unmarshal(result.GetStdOutByteSlice(), &status); err != nil {
		device.Error = strings.TrimSpace(result.GetStdErrString())
		if device.Error == "" {
			device.Error = fmt.Sprintf("failed to parse tailscale status: %v", err)
		}
		return
	}

	device.BackendState = status.BackendState
	device.AuthURL = status.AuthURL
	if status.Self != nil {
		device.HostName = status.Self.HostName
		device.DNSName = strings.TrimSuffix(status.Self.DNSName, ".")
		device.TailscaleIPs = status.Self.TailscaleIPs
		device.Online = status.Self.Online
	}
}

// tailscaleForwards returns the tailnet ports the SSO proxy forwards to lab
// nodes, read from the Serve config in the proxy's lab directory.
func tailscaleForwards(proxy clabruntime.GenericContainer, containers []clabruntime.GenericContainer) []models.TailscaleForward {
	var stateDir string
	for _, mount := range proxy.Mounts {
		if mount.Destination == tailscaleStateDir {
			stateDir = mount.Source
			break
		}
	}
	if stateDir == "" {
		return nil
	}

	content, err := os.ReadFile(filepath.Join(stateDir, clabnodestailscale.ServeFile))
	if err != nil {
		return nil
	}
	var serve tailscaleServeConfig
	if err := json.Unmarshal(content, &serve); err != nil {
		return nil
	}

	nodesByIP := map[string]string{}
	for _, container := range containers {
		nodeName := container.Labels[clabconst.NodeName]
		if nodeName == "" {
			continue
		}
		for _, ip := range []string{container.NetworkSettings.IPv4addr, container.NetworkSettings.IPv6addr} {
			if ip != "" {
				nodesByIP[ip] = nodeName
			}
		}
	}

	forwards := make([]models.TailscaleForward, 0, len(serve.TCP))
	for listen, handler := range serve.TCP {
		port, err := strconv.Atoi(listen)
		if err != nil {
			continue
		}
		forward := models.TailscaleForward{ListenPort: port, Target: handler.TCPForward}
		if host, _, err := net.SplitHostPort(handler.TCPForward); err == nil {
			forward.NodeName = nodesByIP[host]
		}
		forwards = append(forwards, forward)
	}
	slices.SortFunc(forwards, func(a, b models.TailscaleForward) int { return a.ListenPort - b.ListenPort })

	return forwards
}

// internal/clab/capture_labruntime.go
package clab

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	clabcore "github.com/srl-labs/containerlab/core"
	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	clabtypes "github.com/srl-labs/containerlab/types"
)

// LabCaptureOptions selects what a packet capture streams.
type LabCaptureOptions struct {
	Username string
	LabName  string
	// Targets are the interfaces to capture, by node and interface name (or alias).
	Targets []clablabruntime.CaptureTarget
	// Duration ends the capture; zero captures until the context ends.
	Duration time.Duration
	// PacketLimit ends the capture after that many packets across all targets; zero means
	// no limit.
	PacketLimit int
	// SnapLength is the number of bytes kept of each packet; zero uses the runtime default.
	SnapLength int
}

// LocalCaptureLab captures a Docker or Podman lab on this host.
type LocalCaptureLab interface {
	CaptureInterfaces(ctx context.Context, nodeNames ...string) ([]clablabruntime.CaptureInterface, error)
	Capture(ctx context.Context, req clablabruntime.CaptureRequest, w io.Writer) error
}

// SetLocalCaptureLab replaces how the service opens Docker and Podman labs for capture.
func (s *Service) SetLocalCaptureLab(open func(labName string) (LocalCaptureLab, error)) {
	s.localCaptureLab = open
}

// openLocalCaptureLab loads a Docker or Podman lab from the topology file it was deployed
// from: capture reads the lab's links from it. The lock covers loading only, since resolving
// links uses containerlab's shared link nodes; a capture may then run for as long as it likes.
func (s *Service) openLocalCaptureLab(labName string) (LocalCaptureLab, error) {
	if s.localCaptureLab != nil {
		return s.localCaptureLab(labName)
	}
	unlock := lockContainerlabOperation()
	defer unlock()
	clab, err := clabcore.NewContainerLab(
		clabcore.WithTimeout(defaultTimeout),
		runtimeOption(defaultTimeout),
		clabcore.WithTopologyName(labName),
		clabcore.WithTopologyFromLab(labName, nil),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create containerlab instance: %w", err)
	}
	// Without its topology file the lab has no nodes, which capture reports itself.
	if len(clab.Nodes) > 0 {
		if err := clab.ResolveLinks(); err != nil {
			return nil, fmt.Errorf("failed to resolve the links of lab '%s': %w", labName, err)
		}
	}
	return clab, nil
}

// LabCaptureInterfaces lists the lab link interfaces packet capture accepts for the given
// nodes of the user's lab, or for every running node, with the peer of each link. On a lab
// runtime it runs as the user (c9s: impersonation in the lab's namespace); with Docker and
// Podman the caller has checked the user's access to the lab.
func (s *Service) LabCaptureInterfaces(
	ctx context.Context,
	username, labName string,
	nodes ...string,
) ([]clablabruntime.CaptureInterface, error) {
	if !IsLabRuntime() {
		lab, err := s.openLocalCaptureLab(strings.TrimSpace(labName))
		if err != nil {
			return nil, err
		}
		return lab.CaptureInterfaces(ctx, nodes...)
	}
	clab, _, err := s.openLabRuntimeLab(ctx, username, labName, "")
	if err != nil {
		return nil, err
	}
	return clab.CaptureInterfaces(ctx, nodes...)
}

// LabRuntimeInterfaces lists the interfaces of the lab's running nodes on the lab runtime, as
// the user, in the shape interface inspection reports for local containers: per node (named
// <lab>-<node>) the lab link interfaces, eth0 and lo, with their state.
func (s *Service) LabRuntimeInterfaces(ctx context.Context, username, labName string) ([]*clabtypes.ContainerInterfaces, error) {
	if err := requireLabRuntime("interface inspection"); err != nil {
		return nil, err
	}
	clab, _, err := s.openLabRuntimeLab(ctx, username, labName, "")
	if err != nil {
		return nil, err
	}
	return clab.LabRuntimeInterfaces(ctx, "")
}

// CaptureLab streams pcapng of lab link interfaces to w: on a lab runtime as the user, with
// Docker and Podman through packet sockets in the nodes' network namespaces. It returns when
// the duration passed, the packet limit was reached, or ctx ended (not an error); the library
// stops the capture when it returns. Errors before the capture starts reach the caller before
// anything was written to w.
func (s *Service) CaptureLab(ctx context.Context, opts LabCaptureOptions, w io.Writer) error {
	if len(opts.Targets) == 0 {
		return fmt.Errorf("at least one capture target is required")
	}
	if !IsLabRuntime() {
		labName := strings.TrimSpace(opts.LabName)
		lab, err := s.openLocalCaptureLab(labName)
		if err != nil {
			return err
		}
		return lab.Capture(ctx, clablabruntime.CaptureRequest{
			Name:        labName,
			Targets:     slices.Clone(opts.Targets),
			Duration:    opts.Duration,
			PacketLimit: opts.PacketLimit,
			SnapLength:  opts.SnapLength,
		}, w)
	}
	clab, scope, err := s.openLabRuntimeLab(ctx, opts.Username, strings.TrimSpace(opts.LabName), "")
	if err != nil {
		return err
	}
	return clab.Capture(ctx, clablabruntime.CaptureRequest{
		Name:        clab.Config.Name,
		Namespace:   scope.Namespace,
		Targets:     slices.Clone(opts.Targets),
		Duration:    opts.Duration,
		PacketLimit: opts.PacketLimit,
		SnapLength:  opts.SnapLength,
		Identity:    scope.Identity,
	}, w)
}

// internal/clab/capture_labruntime.go
package clab

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	clabtypes "github.com/srl-labs/containerlab/types"
)

// LabCaptureOptions selects what a lab runtime packet capture streams.
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

// LabCaptureInterfaces lists the lab link interfaces packet capture accepts for the given
// nodes of the user's lab, or for every running node, with the peer of each link. It runs as
// the user (c9s: impersonation in the lab's namespace).
func (s *Service) LabCaptureInterfaces(
	ctx context.Context,
	username, labName string,
	nodes ...string,
) ([]clablabruntime.CaptureInterface, error) {
	if err := requireLabRuntime("packet capture"); err != nil {
		return nil, err
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

// CaptureLab streams pcapng of lab link interfaces to w, as the user. It returns when the
// duration passed, the packet limit was reached, or ctx ended (not an error); the library
// stops the capture processes in the lab when it returns. Errors before the capture starts
// reach the caller before anything was written to w.
func (s *Service) CaptureLab(ctx context.Context, opts LabCaptureOptions, w io.Writer) error {
	if err := requireLabRuntime("packet capture"); err != nil {
		return err
	}
	if len(opts.Targets) == 0 {
		return fmt.Errorf("at least one capture target is required")
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

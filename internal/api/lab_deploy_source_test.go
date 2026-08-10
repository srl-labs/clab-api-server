package api

import (
	"errors"
	"testing"

	"github.com/srl-labs/clab-api-server/internal/clab"
)

type fakeDeployTopologySourceResolver struct {
	resolved     *clab.ResolveTopologySourceResult
	resolveErr   error
	resolveCalls int
}

func (f *fakeDeployTopologySourceResolver) ResolveTopologySource(
	clab.ResolveTopologySourceOptions,
) (*clab.ResolveTopologySourceResult, error) {
	f.resolveCalls++
	return f.resolved, f.resolveErr
}

func TestResolveURLDeploySourceUsesResolvedTopologyName(t *testing.T) {
	resolver := &fakeDeployTopologySourceResolver{
		resolved: &clab.ResolveTopologySourceResult{
			TopologyPath: "/tmp/source/victim.clab.yml",
			LabName:      "victim",
		},
	}

	topologyPath, labName, err := resolveURLDeploySource(
		resolver,
		"alice",
		"https://example.test/topology.git",
		"",
	)
	if err != nil {
		t.Fatalf("resolveURLDeploySource error: %v", err)
	}
	if topologyPath != resolver.resolved.TopologyPath {
		t.Fatalf("topology path = %q, want %q", topologyPath, resolver.resolved.TopologyPath)
	}
	if labName != "victim" {
		t.Fatalf("lab name = %q, want victim", labName)
	}
	if resolver.resolveCalls != 1 {
		t.Fatalf("ResolveTopologySource calls = %d, want 1", resolver.resolveCalls)
	}
}

func TestResolveURLDeploySourceUsesAuthorizedOverride(t *testing.T) {
	resolver := &fakeDeployTopologySourceResolver{
		resolved: &clab.ResolveTopologySourceResult{
			TopologyPath: "/tmp/source/unchecked.clab.yml",
			LabName:      "unchecked",
		},
	}

	topologyPath, labName, err := resolveURLDeploySource(
		resolver,
		"alice",
		"https://example.test/topology.git",
		"authorized",
	)
	if err != nil {
		t.Fatalf("resolveURLDeploySource error: %v", err)
	}
	if topologyPath != resolver.resolved.TopologyPath {
		t.Fatalf("topology path = %q, want %q", topologyPath, resolver.resolved.TopologyPath)
	}
	if labName != "authorized" {
		t.Fatalf("lab name = %q, want authorized", labName)
	}
	if resolver.resolveCalls != 1 {
		t.Fatalf("ResolveTopologySource calls = %d, want 1", resolver.resolveCalls)
	}
}

func TestResolveURLDeploySourcePropagatesResolutionFailure(t *testing.T) {
	wantErr := errors.New("invalid topology")
	resolver := &fakeDeployTopologySourceResolver{
		resolveErr: wantErr,
	}

	_, _, err := resolveURLDeploySource(
		resolver,
		"alice",
		"https://example.test/topology.git",
		"",
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("resolveURLDeploySource error = %v, want %v", err, wantErr)
	}
}

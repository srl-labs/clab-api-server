// internal/clab/labruntime.go
package clab

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	clabcore "github.com/srl-labs/containerlab/core"
	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	clabruntime "github.com/srl-labs/containerlab/runtime"

	"github.com/srl-labs/clab-api-server/internal/config"
)

// ErrNotSupportedByLabRuntime marks an operation that needs a local container runtime
// (Docker or Podman) while the server runs labs with a lab runtime such as c9s.
var ErrNotSupportedByLabRuntime = errors.New("not supported by lab runtime")

// UnsupportedByLabRuntimeError reports an operation the configured lab runtime cannot serve.
type UnsupportedByLabRuntimeError struct {
	// Operation names what was asked for, e.g. "image management".
	Operation string
	Runtime   string
}

func (e *UnsupportedByLabRuntimeError) Error() string {
	if e.Operation == "" {
		return fmt.Sprintf("not supported by lab runtime %s", e.Runtime)
	}
	return fmt.Sprintf("%s is not supported by lab runtime %s", e.Operation, e.Runtime)
}

func (e *UnsupportedByLabRuntimeError) Unwrap() error {
	return ErrNotSupportedByLabRuntime
}

// RuntimeKind returns the configured runtime: "docker", "podman" or "c9s".
func RuntimeKind() string {
	if runtime := strings.TrimSpace(config.AppConfig.ClabRuntime); runtime != "" {
		return runtime
	}
	return config.RuntimeDocker
}

// IsLabRuntime reports whether labs run on a lab runtime (c9s) instead of a local
// container runtime.
func IsLabRuntime() bool {
	return RuntimeKind() == config.RuntimeC9s
}

// RequireContainerRuntime returns an UnsupportedByLabRuntimeError when the server runs a
// lab runtime, so paths that talk to Docker or Podman directly refuse to run.
func RequireContainerRuntime(operation string) error {
	if IsLabRuntime() {
		return &UnsupportedByLabRuntimeError{Operation: operation, Runtime: RuntimeKind()}
	}
	return nil
}

// LabScope is where lab runtime calls for one lab go and who they act as. Local container
// runtimes ignore it.
type LabScope struct {
	// LabName is the lab the scope belongs to; empty for a listing scope.
	LabName string
	// Namespace is the Kubernetes namespace of the lab. Empty leaves the choice to
	// containerlab (CLAB_KUBE_NAMESPACE or c9s-<lab>).
	Namespace string
	// Owner is the user that owns the lab.
	Owner string
	// Identity is the Kubernetes identity lab runtime calls impersonate. The zero identity
	// acts with the server's own credentials.
	Identity clablabruntime.Identity
}

// LabScoper decides the namespaces and Kubernetes identities of lab runtime calls.
type LabScoper interface {
	// ScopeForLab returns the scope of an existing lab of the user.
	ScopeForLab(ctx context.Context, username, labName string) (LabScope, error)
	// PrepareDeploy returns the scope a deploy of the lab runs in, creating what the lab
	// needs before containerlab deploys it.
	PrepareDeploy(ctx context.Context, username, labName, topoPath string) (LabScope, error)
	// ListScopes returns the scopes a listing of the user's labs covers.
	ListScopes(ctx context.Context, username string) ([]LabScope, error)
	// AfterDestroy runs once containerlab destroyed the lab.
	AfterDestroy(ctx context.Context, scope LabScope, cleanup bool) error
}

// serverScoper runs every lab runtime call with the server's own credentials and lets
// containerlab choose the namespaces.
type serverScoper struct{}

func (serverScoper) ScopeForLab(_ context.Context, username, labName string) (LabScope, error) {
	return LabScope{LabName: labName, Owner: username}, nil
}

func (serverScoper) PrepareDeploy(_ context.Context, username, labName, _ string) (LabScope, error) {
	return LabScope{LabName: labName, Owner: username}, nil
}

func (serverScoper) ListScopes(_ context.Context, username string) ([]LabScope, error) {
	return []LabScope{{Owner: username}}, nil
}

func (serverScoper) AfterDestroy(context.Context, LabScope, bool) error { return nil }

// SetLabScoper replaces how the service scopes lab runtime calls.
func (s *Service) SetLabScoper(scoper LabScoper) {
	if scoper == nil {
		scoper = serverScoper{}
	}
	s.scoper = scoper
}

func (s *Service) labScoper() LabScoper {
	if s.scoper == nil {
		return serverScoper{}
	}
	return s.scoper
}

// scopeForLab resolves the scope of an existing lab. It is the zero scope with local
// container runtimes.
func (s *Service) scopeForLab(ctx context.Context, username, labName string) (*LabScope, error) {
	if !IsLabRuntime() {
		return nil, nil
	}
	if strings.TrimSpace(username) == "" {
		return nil, fmt.Errorf("lab runtime calls need the requesting user")
	}
	scope, err := s.labScoper().ScopeForLab(ctx, username, labName)
	if err != nil {
		return nil, err
	}
	return &scope, nil
}

// runtimeOptions selects the configured runtime, and for a lab runtime the namespace and
// identity of the scope.
func runtimeOptions(scope *LabScope, timeout time.Duration) []clabcore.ClabOption {
	rtConfig := &clabruntime.RuntimeConfig{Timeout: timeout}
	opts := []clabcore.ClabOption{}
	if scope != nil && IsLabRuntime() {
		rtConfig.LabNamespace = scope.Namespace
		opts = append(opts, clabcore.WithLabRuntimeIdentity(scope.Identity))
	}
	return append([]clabcore.ClabOption{clabcore.WithRuntime(RuntimeKind(), rtConfig)}, opts...)
}

// labRuntimeDeployOptions applies the server's c9s deploy settings.
func labRuntimeDeployOptions(deployOpts *clabcore.DeployOptions) {
	if !IsLabRuntime() || deployOpts == nil {
		return
	}
	deployOpts.SetExposeType(config.AppConfig.ClabC9sExposeType).
		SetNoPersistence(!config.AppConfig.ClabC9sPersistence).
		SetImagePullSecret(config.AppConfig.PullSecretName())
}

// labRuntimeLabOption selects a lab by name for a lab runtime: the topology file when it
// still exists, renamed to the lab name, or the lab name alone.
func labRuntimeLabOptions(topoPath, labName string) []clabcore.ClabOption {
	if strings.TrimSpace(topoPath) != "" && fileExists(topoPath) {
		return []clabcore.ClabOption{
			clabcore.WithTopoPath(topoPath, nil),
			clabcore.WithTopologyName(labName),
		}
	}
	return []clabcore.ClabOption{clabcore.WithLabNameOnly(labName)}
}

// runtimeOption selects the configured runtime without a lab scope, for calls that do not
// reach a lab runtime's cluster (or that a lab runtime refuses anyway).
func runtimeOption(timeout time.Duration) clabcore.ClabOption {
	return clabcore.WithRuntime(RuntimeKind(), &clabruntime.RuntimeConfig{Timeout: timeout})
}

// EventScopes returns the lab scopes an events stream of the user covers on a lab runtime:
// one stream per scope.
func (s *Service) EventScopes(ctx context.Context, username string) ([]LabScope, error) {
	if !IsLabRuntime() {
		return nil, fmt.Errorf("event scopes need a lab runtime")
	}
	if strings.TrimSpace(username) == "" {
		return nil, fmt.Errorf("lab runtime calls need the requesting user")
	}
	return s.labScoper().ListScopes(ctx, username)
}

// EventClabOptions returns the containerlab options of an events stream: the configured
// runtime and, on a lab runtime, the scope's namespace, identity and lab.
func EventClabOptions(scope *LabScope, timeout time.Duration) []clabcore.ClabOption {
	opts := append([]clabcore.ClabOption{clabcore.WithTimeout(timeout)}, runtimeOptions(scope, timeout)...)
	if scope != nil && IsLabRuntime() && scope.LabName != "" {
		opts = append(opts, clabcore.WithLabNameOnly(scope.LabName))
	}
	return opts
}

// internal/clab/labruntime_ops.go
package clab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	clabconst "github.com/srl-labs/containerlab/constants"
	clabcore "github.com/srl-labs/containerlab/core"
	clabexec "github.com/srl-labs/containerlab/exec"
	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	clabnames "github.com/srl-labs/containerlab/names"
	clabruntime "github.com/srl-labs/containerlab/runtime"
)

// ErrLabNotFound reports a lab the user has no lab runtime state for.
var ErrLabNotFound = errors.New("lab not found")

// ErrNodeNotFound reports a node that is not part of a lab.
var ErrNodeNotFound = clabcore.ErrNodeNotFound

// ErrMetricsUnavailable reports a cluster without the resource metrics API.
var ErrMetricsUnavailable = clablabruntime.ErrMetricsUnavailable

// isLabRuntimeNotFound reports the lab runtime's error for a lab without remote state.
func isLabRuntimeNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrLabNotFound) {
		return true
	}
	message := err.Error()
	return strings.Contains(message, "was not found") || strings.Contains(message, "not found in namespace")
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// ErrInvalidLabName reports a lab name a lab runtime cannot use as it is.
var ErrInvalidLabName = errors.New("invalid lab name")

// ValidateLabRuntimeLabName checks that a lab runtime can name its objects after the lab
// as it is: c9s needs lowercase DNS label names (letters, digits and dashes). Renaming
// silently would make the lab unreachable under the name the user chose.
func ValidateLabRuntimeLabName(labName string) error {
	if sanitized := clabnames.SanitizeName(labName); sanitized != labName {
		return fmt.Errorf("%w: lab runtime %s needs lowercase names of letters, digits and dashes that start with a letter; use %q instead of %q",
			ErrInvalidLabName, RuntimeKind(), sanitized, labName)
	}
	return nil
}

// validateLabRuntimeDeployOptions rejects deploy options only local container runtimes have.
func validateLabRuntimeDeployOptions(opts DeployOptions) error {
	if err := ValidateLabRuntimeLabName(strings.TrimSpace(opts.LabName)); err != nil {
		return err
	}
	unsupported := func(option string) error {
		return &UnsupportedByLabRuntimeError{Operation: option, Runtime: RuntimeKind()}
	}
	switch {
	case len(opts.NodeFilter) > 0:
		return unsupported("deploying with a node filter")
	case len(opts.RestoreNodeSnapshots) > 0:
		return unsupported("restoring node snapshots")
	case opts.MgmtNetwork != "" || opts.MgmtIPv4Subnet != "" || opts.MgmtIPv6Subnet != "":
		return unsupported("overriding the management network")
	case opts.ExportTemplate != "":
		return unsupported("a topology export template")
	}
	return nil
}

// openLabRuntimeLab builds a containerlab instance for an existing lab of the user on the
// lab runtime, scoped to the lab's namespace and the user's identity.
func (s *Service) openLabRuntimeLab(
	ctx context.Context,
	username, labName, topoPath string,
) (*clabcore.CLab, *LabScope, error) {
	labName = strings.TrimSpace(labName)
	if labName == "" {
		return nil, nil, fmt.Errorf("lab name is required")
	}
	scope, err := s.scopeForLab(ctx, username, labName)
	if err != nil {
		return nil, nil, err
	}
	opts := []clabcore.ClabOption{clabcore.WithTimeout(defaultTimeout)}
	opts = append(opts, runtimeOptions(scope, defaultTimeout)...)
	opts = append(opts, labRuntimeLabOptions(topoPath, labName)...)
	clab, err := newContainerLab(opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create containerlab instance: %w", err)
	}
	return clab, scope, nil
}

// listLabRuntimeContainers lists the nodes of the user's labs on the lab runtime as
// containers, one lab scope at a time.
func (s *Service) listLabRuntimeContainers(ctx context.Context, opts ListOptions) ([]clabruntime.GenericContainer, error) {
	username := strings.TrimSpace(opts.Username)
	if username == "" {
		return nil, fmt.Errorf("lab runtime calls need the requesting user")
	}

	var scopes []LabScope
	if labName := strings.TrimSpace(opts.LabName); labName != "" {
		scope, err := s.labScoper().ScopeForLab(ctx, username, labName)
		if err != nil {
			if isLabRuntimeNotFound(err) {
				return nil, nil
			}
			return nil, err
		}
		scopes = []LabScope{scope}
	} else {
		var err error
		scopes, err = s.labScoper().ListScopes(ctx, username)
		if err != nil {
			return nil, err
		}
	}

	listOpts := []clabcore.ListOption{}
	if opts.ContainerName != "" {
		listOpts = append(listOpts, clabcore.WithListContainerName(opts.ContainerName))
	}
	if opts.NodeName != "" {
		listOpts = append(listOpts, clabcore.WithListNodeName(opts.NodeName))
	}

	var containers []clabruntime.GenericContainer
	for idx := range scopes {
		scope := scopes[idx]
		clabOpts := []clabcore.ClabOption{clabcore.WithTimeout(defaultTimeout)}
		clabOpts = append(clabOpts, runtimeOptions(&scope, defaultTimeout)...)
		if scope.LabName != "" {
			clabOpts = append(clabOpts, clabcore.WithLabNameOnly(scope.LabName))
		}
		clab, err := newContainerLab(clabOpts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create containerlab instance: %w", err)
		}
		found, err := clab.ListLabRuntimeContainers(ctx, scope.LabName == "", listOpts...)
		if err != nil {
			if isLabRuntimeNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("failed to list containers: %w", err)
		}
		containers = append(containers, found...)
	}
	if err := s.VerifyLabRecords(ctx, containers); err != nil {
		return nil, err
	}
	return containers, nil
}

// destroyWithLabRuntime destroys a lab on the lab runtime and lets the scoper clean up
// after it.
func (s *Service) destroyWithLabRuntime(ctx context.Context, opts DestroyOptions) error {
	switch {
	case opts.Graceful:
		return &UnsupportedByLabRuntimeError{Operation: "graceful destroy", Runtime: RuntimeKind()}
	case len(opts.NodeFilter) > 0:
		return &UnsupportedByLabRuntimeError{Operation: "destroying with a node filter", Runtime: RuntimeKind()}
	}
	labName := strings.TrimSpace(opts.LabName)
	if labName == "" {
		return fmt.Errorf("lab name is required")
	}

	clab, scope, err := s.openLabRuntimeLab(ctx, opts.Username, labName, opts.TopoPath)
	if err != nil {
		return err
	}

	destroyOpts := []clabcore.DestroyOption{clabcore.WithDestroyMaxWorkers(opts.MaxWorkers)}
	if opts.Cleanup {
		destroyOpts = append(destroyOpts, clabcore.WithDestroyCleanup())
	}

	log.Info("Destroying lab", "username", opts.Username, "labName", labName,
		"namespace", scope.Namespace, "cleanup", opts.Cleanup)
	if err := clab.Destroy(ctx, destroyOpts...); err != nil {
		return fmt.Errorf("destroy failed: %w", err)
	}
	if err := s.labScoper().AfterDestroy(ctx, *scope, opts.Cleanup); err != nil {
		return fmt.Errorf("lab destroyed but its namespace was not released: %w", err)
	}
	log.Info("Lab destroyed successfully", "username", opts.Username, "labName", labName)
	return nil
}

// ApplyOutcome is the result of an apply: containerlab's summary and, on a lab runtime,
// the remote resource plan of a dry run.
type ApplyOutcome struct {
	*clabcore.ApplyResult
	RuntimePlan *clablabruntime.DeployPlan
}

// applyWithLabRuntime applies a topology on a lab runtime. Lab runtimes reconcile a
// deployed lab in place, so apply is a deploy; a dry run returns the runtime's plan.
func (s *Service) applyWithLabRuntime(ctx context.Context, opts ApplyOptions) (*ApplyOutcome, error) {
	labName := strings.TrimSpace(opts.LabName)
	if labName == "" {
		return nil, fmt.Errorf("lab name is required")
	}
	if opts.ExportTemplate != "" {
		return nil, &UnsupportedByLabRuntimeError{Operation: "a topology export template", Runtime: RuntimeKind()}
	}
	if err := ValidateLabRuntimeLabName(labName); err != nil {
		return nil, err
	}
	deployOpts := DeployOptions{TopoPath: opts.TopoPath, LabName: labName, Username: opts.Username, Actor: opts.Actor, MaxWorkers: opts.MaxWorkers}

	var scope *LabScope
	if opts.DryRun {
		existing, err := s.scopeForLab(ctx, actorOf(opts.Actor, opts.Username), labName)
		if err != nil && !isLabRuntimeNotFound(err) {
			return nil, err
		}
		scope = existing
	} else {
		prepared, err := s.labScoper().PrepareDeploy(ctx, actorOf(opts.Actor, opts.Username), labName, opts.TopoPath)
		if err != nil {
			return nil, err
		}
		scope = &prepared
	}

	clab, release, err := s.openDeployLab(deployOpts, scope)
	if err != nil {
		return nil, err
	}
	defer release()

	coreOpts, err := clabcore.NewDeployOptions(opts.MaxWorkers)
	if err != nil {
		return nil, fmt.Errorf("failed to create deploy options: %w", err)
	}
	coreOpts.SetDryRun(opts.DryRun).SetSkipPostDeploy(opts.SkipPostDeploy)
	labRuntimeDeployOptions(coreOpts)

	result, err := clab.Deploy(ctx, coreOpts)
	if err != nil {
		if !opts.DryRun && scope != nil {
			s.releaseAfterFailedDeploy(ctx, clab, *scope)
		}
		return nil, fmt.Errorf("apply failed: %w", err)
	}

	outcome := &ApplyOutcome{ApplyResult: &clabcore.ApplyResult{DryRun: opts.DryRun, LabName: clab.Config.Name}}
	if result != nil {
		if result.Apply != nil {
			outcome.ApplyResult = result.Apply
		}
		outcome.RuntimePlan = result.RuntimePlan
		if result.Apply == nil && result.RuntimePlan == nil && !opts.DryRun {
			outcome.DeployedLab = true
		}
	}
	if outcome.LabName == "" {
		outcome.LabName = clab.Config.Name
	}
	return outcome, nil
}

// labRuntimeNodeLifecycle starts, stops or restarts nodes of a lab on the lab runtime.
func (s *Service) labRuntimeNodeLifecycle(ctx context.Context, opts NodeLifecycleOptions) error {
	clab, _, err := s.openLabRuntimeLab(ctx, opts.Username, opts.LabName, opts.TopoPath)
	if err != nil {
		return err
	}
	nodeNames := cleanNodeNames(opts.NodeNames)
	log.Info("Running lab runtime lifecycle action", "username", opts.Username,
		"labName", opts.LabName, "action", opts.Action, "nodes", nodeNames)
	switch opts.Action {
	case NodeLifecycleActionStart:
		err = clab.StartNodes(ctx, nodeNames)
	case NodeLifecycleActionStop:
		err = clab.StopNodes(ctx, nodeNames)
	case NodeLifecycleActionRestart:
		err = clab.RestartNodes(ctx, nodeNames)
	default:
		return fmt.Errorf("unsupported topology lifecycle action: %q", opts.Action)
	}
	if err != nil {
		return fmt.Errorf("failed to %s node(s): %w", opts.Action, err)
	}
	return nil
}

// execWithLabRuntime runs commands in the lab's containers selected by the list options.
func (s *Service) execWithLabRuntime(ctx context.Context, opts ExecOptions) (*clabexec.ExecCollection, error) {
	clab, _, err := s.openLabRuntimeLab(ctx, opts.Username, opts.LabName, "")
	if err != nil {
		return nil, err
	}
	var listOpts []clabcore.ListOption
	if opts.ContainerName != "" {
		listOpts = append(listOpts, clabcore.WithListContainerName(opts.ContainerName))
	}
	if opts.NodeName != "" {
		listOpts = append(listOpts, clabcore.WithListNodeName(opts.NodeName))
	}
	result, err := clab.Exec(ctx, opts.Commands, listOpts...)
	if err != nil {
		return result, fmt.Errorf("exec failed: %w", err)
	}
	return result, nil
}

// execFilteredWithLabRuntime runs commands on the lab's nodes selected by node names and
// labels, like ExecFiltered does for container runtimes.
func (s *Service) execFilteredWithLabRuntime(
	ctx context.Context,
	opts ExecFilterOptions,
	execCmds []*clabexec.ExecCmd,
) (*clabexec.ExecCollection, error) {
	clab, scope, err := s.openLabRuntimeLab(ctx, opts.Username, opts.LabName, "")
	if err != nil {
		return nil, err
	}
	containers, err := clab.ListLabRuntimeContainers(ctx, false,
		clabcore.WithListFilter(execListFilters(opts.LabName, opts.Labels)))
	if err != nil {
		if isLabRuntimeNotFound(err) {
			return nil, ErrNoMatchingContainers
		}
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}
	containers = selectExecContainers(containers, opts.LabName, opts.NodeNames, opts.Labels)
	if len(containers) == 0 {
		return nil, ErrNoMatchingContainers
	}

	results := clabexec.NewExecCollection()
	for idx := range containers {
		container := containers[idx]
		namespace := scope.Namespace
		if container.Workload != nil && container.Workload.Namespace != "" {
			namespace = container.Workload.Namespace
		}
		for _, execCmd := range execCmds {
			result, err := clab.LabRuntime.Exec(ctx, clablabruntime.ExecRequest{
				Name:      opts.LabName,
				Namespace: namespace,
				NodeName:  container.Labels[clabconst.NodeName],
				Command:   execCmd.GetCmd(),
				Identity:  scope.Identity,
			})
			if err != nil {
				log.Warnf("exec on %s failed: %v", GetContainerName(&container), err)
				continue
			}
			results.Add(GetContainerName(&container), result)
		}
	}
	return results, nil
}

// saveWithLabRuntime saves the running configuration of the lab's nodes on the lab
// runtime, and copies the saved files out when asked.
func (s *Service) saveWithLabRuntime(ctx context.Context, opts SaveOptions) (*SaveResult, error) {
	clab, scope, err := s.openLabRuntimeLab(ctx, opts.Username, opts.LabName, "")
	if err != nil {
		return nil, err
	}

	log.Info("Saving lab configuration", "username", opts.Username, "labName", opts.LabName,
		"namespace", scope.Namespace)
	saved, err := clab.LabRuntime.Save(ctx, clablabruntime.SaveRequest{
		Name:      clab.Config.Name,
		Namespace: scope.Namespace,
		Nodes:     cleanNodeNames(opts.NodeFilter),
		Copy:      opts.CopyOut != nil,
		Identity:  scope.Identity,
	})
	if err != nil {
		return nil, fmt.Errorf("save failed: %w", err)
	}

	result := &SaveResult{}
	if opts.CopyOut == nil || saved == nil {
		return result, nil
	}
	copyDir, err := writeLabRuntimeSavedFiles(*opts.CopyOut, "clab-"+clab.Config.Name, saved.Files)
	result.CopyDir = copyDir
	if err != nil {
		return result, fmt.Errorf("save succeeded but copying the configuration failed: %w", err)
	}
	return result, nil
}

// writeLabRuntimeSavedFiles writes saved node files to <dst>/<labDirName>/<node>/<file>.
// Every write stays below the output root.
func writeLabRuntimeSavedFiles(dst OutputDir, labDirName string, files []clablabruntime.SavedFile) (string, error) {
	if !isPlainName(labDirName) {
		return "", fmt.Errorf("invalid lab directory name %q", labDirName)
	}
	root, err := openOutputRoot(dst)
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()

	base := filepath.Join(dst.Rel, labDirName)
	if err := mkdirAllInRoot(root, base, 0o750, dst); err != nil {
		return "", err
	}
	copyDir := filepath.Join(dst.Path(), labDirName)

	for _, file := range files {
		if !isPlainName(file.NodeName) || file.Name == "" {
			continue
		}
		rel := filepath.Clean(file.Name)
		if rel == "." || !filepath.IsLocal(rel) {
			return copyDir, fmt.Errorf("refusing to copy unsafe saved config path %q", file.Name)
		}
		target := filepath.Join(base, file.NodeName, rel)
		if err := mkdirAllInRoot(root, filepath.Dir(target), 0o750, dst); err != nil {
			return copyDir, err
		}
		if file.LinkTarget != "" {
			link := filepath.Clean(file.LinkTarget)
			if !filepath.IsLocal(link) {
				return copyDir, fmt.Errorf("refusing to create unsafe saved config symlink %q", file.LinkTarget)
			}
			if err := root.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return copyDir, err
			}
			if err := root.Symlink(link, target); err != nil {
				return copyDir, fmt.Errorf("failed to link %s: %w", target, err)
			}
			if err := lchownInRoot(root, target, dst); err != nil {
				return copyDir, err
			}
			continue
		}
		mode := fs.FileMode(file.Mode) & 0o777
		if mode == 0 {
			mode = 0o640
		}
		if err := root.WriteFile(target, file.Data, mode); err != nil {
			return copyDir, fmt.Errorf("failed to write %s: %w", target, err)
		}
		if err := lchownInRoot(root, target, dst); err != nil {
			return copyDir, err
		}
	}
	return copyDir, nil
}

// NodeLogsOptions selects the node log NodeLogs writes.
type NodeLogsOptions struct {
	Username string
	LabName  string
	// NodeName is the topology node name.
	NodeName   string
	Tail       *int64
	Follow     bool
	Timestamps bool
}

// NodeLogs writes a node's log with the configured runtime: the container log with Docker
// and Podman, the device container log with a lab runtime (one combined stream on stdout).
func (s *Service) NodeLogs(ctx context.Context, opts NodeLogsOptions, stdout, stderr io.Writer) error {
	labName := strings.TrimSpace(opts.LabName)
	if labName == "" {
		return fmt.Errorf("lab name is required")
	}
	var clab *clabcore.CLab
	var err error
	if IsLabRuntime() {
		clab, _, err = s.openLabRuntimeLab(ctx, opts.Username, labName, "")
	} else {
		clabOpts := []clabcore.ClabOption{clabcore.WithTimeout(defaultTimeout)}
		clabOpts = append(clabOpts, runtimeOptions(nil, defaultTimeout)...)
		clabOpts = append(clabOpts, clabcore.WithLabNameOnly(labName))
		clab, err = newContainerLab(clabOpts...)
	}
	if err != nil {
		return err
	}
	return clab.NodeLogs(ctx, clabcore.NodeLogOptions{
		NodeName:   opts.NodeName,
		Tail:       opts.Tail,
		Follow:     opts.Follow,
		Timestamps: opts.Timestamps,
	}, stdout, stderr)
}

// AttachNode runs an interactive command in a node's device container on the lab runtime.
// A command that exits nonzero returns a *labruntime.CommandExitError.
func (s *Service) AttachNode(
	ctx context.Context,
	username, labName, nodeName string,
	command []string,
	tty bool,
	streams clablabruntime.AttachStreams,
) error {
	if err := requireLabRuntime("attaching to nodes"); err != nil {
		return err
	}
	clab, scope, err := s.openLabRuntimeLab(ctx, username, labName, "")
	if err != nil {
		return err
	}
	return clab.AttachLabRuntimeNode(ctx, clablabruntime.AttachRequest{
		Name:      clab.Config.Name,
		Namespace: scope.Namespace,
		NodeName:  nodeName,
		Command:   slices.Clone(command),
		TTY:       tty,
		Identity:  scope.Identity,
	}, streams)
}

// DialNodePort opens a connection to a TCP port of a node through the lab runtime
// (a Kubernetes port-forward with c9s).
func (s *Service) DialNodePort(ctx context.Context, username, labName, nodeName string, port int) (net.Conn, error) {
	if err := requireLabRuntime("port-forwarding to nodes"); err != nil {
		return nil, err
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	clab, _, err := s.openLabRuntimeLab(ctx, username, labName, "")
	if err != nil {
		return nil, err
	}
	return clab.DialLabRuntimeNodePort(ctx, nodeName, port)
}

// SampleNodeStats reports the CPU and memory usage of the lab's running nodes on the lab
// runtime. It returns an error wrapping ErrMetricsUnavailable without a metrics API.
func (s *Service) SampleNodeStats(ctx context.Context, username, labName string) ([]clablabruntime.NodeStats, error) {
	if err := requireLabRuntime("sampling node stats"); err != nil {
		return nil, err
	}
	clab, _, err := s.openLabRuntimeLab(ctx, username, labName, "")
	if err != nil {
		return nil, err
	}
	return clab.SampleLabRuntimeNodeStats(ctx)
}

func requireLabRuntime(operation string) error {
	if !IsLabRuntime() {
		return fmt.Errorf("%s needs a lab runtime; CLAB_RUNTIME is %s", operation, RuntimeKind())
	}
	return nil
}

func actorOf(actor, username string) string {
	if strings.TrimSpace(actor) != "" {
		return strings.TrimSpace(actor)
	}
	return strings.TrimSpace(username)
}

// releaseAfterFailedDeploy lets the scoper release what it prepared for a deploy that
// failed and left no lab behind. A failed fresh deploy removes what containerlab created,
// so the namespace prepared for it would otherwise stay empty; a lab that still exists
// (a failed update) is left alone.
func (s *Service) releaseAfterFailedDeploy(ctx context.Context, clab *clabcore.CLab, scope LabScope) {
	checker, ok := clab.LabRuntime.(clablabruntime.LabExistenceChecker)
	if !ok {
		return
	}
	// The deploy's context may be what ended it; the release gets its own time.
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	exists, err := checker.LabExists(releaseCtx, clablabruntime.InspectRequest{
		Name:      clab.Config.Name,
		Namespace: scope.Namespace,
		Identity:  scope.Identity,
	})
	if err != nil || exists {
		return
	}
	if err := s.labScoper().AfterDestroy(releaseCtx, scope, false); err != nil {
		log.Warn("Failed to release the namespace of a failed deploy", "lab", clab.Config.Name,
			"namespace", scope.Namespace, "error", err)
	}
}

// internal/clab/service.go
package clab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/containernetworking/plugins/pkg/ns"
	gotc "github.com/florianl/go-tc"
	clabcert "github.com/srl-labs/containerlab/cert"
	clabcore "github.com/srl-labs/containerlab/core"
	clabexec "github.com/srl-labs/containerlab/exec"
	clabgit "github.com/srl-labs/containerlab/git"
	clablinks "github.com/srl-labs/containerlab/links"
	clabnetem "github.com/srl-labs/containerlab/netem"
	clabnodes "github.com/srl-labs/containerlab/nodes"
	clabnodesstate "github.com/srl-labs/containerlab/nodes/state"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	clabtypes "github.com/srl-labs/containerlab/types"
	clabutils "github.com/srl-labs/containerlab/utils"
	"github.com/vishvananda/netlink"
	"gopkg.in/yaml.v2"

	"github.com/srl-labs/clab-api-server/internal/config"
	workspacestore "github.com/srl-labs/clab-api-server/internal/workspace"
)

const (
	defaultTimeout         = 5 * time.Minute
	gracefulDestroyTimeout = 2 * time.Minute
	imagePullTimeout       = 30 * time.Minute
)

var ErrNetemInterfaceNotFound = errors.New("netem interface not found")

// Service provides an interface to containerlab operations using the library directly.
type Service struct{}

// NewService creates a new containerlab service.
func NewService() *Service {
	return &Service{}
}

// containerlabProcessMu protects the process-global state used by containerlab
// initialization and a few upstream operations. os.Chdir and environment
// variables affect every goroutine, so callers that need either must hold this
// lock for their complete operation, not only for initialization.
var containerlabProcessMu sync.Mutex

func newContainerLab(opts ...clabcore.ClabOption) (*clabcore.CLab, error) {
	containerlabProcessMu.Lock()
	defer containerlabProcessMu.Unlock()

	return clabcore.NewContainerLab(opts...)
}

func newContainerLabProcessLocked(opts ...clabcore.ClabOption) (*clabcore.CLab, error) {
	return clabcore.NewContainerLab(opts...)
}

func withContainerlabProcessState(workDir, owner string, run func() error) (returnErr error) {
	containerlabProcessMu.Lock()
	defer containerlabProcessMu.Unlock()

	originalDir := ""
	if strings.TrimSpace(workDir) != "" {
		var err error
		originalDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current working directory: %w", err)
		}
		if err := os.Chdir(workDir); err != nil {
			return fmt.Errorf("failed to change to work directory: %w", err)
		}
		defer func() {
			if err := os.Chdir(originalDir); err != nil {
				log.Error("Failed to restore working directory", "error", err)
				if returnErr == nil {
					returnErr = fmt.Errorf("failed to restore working directory: %w", err)
				}
			}
		}()
	}

	restoreOwnerEnv := setProcessOwnerEnv(owner)
	defer restoreOwnerEnv()

	return run()
}

func setProcessOwnerEnv(owner string) func() {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return func() {}
	}

	sudoUser, sudoUserSet := os.LookupEnv("SUDO_USER")
	userEnv, userSet := os.LookupEnv("USER")
	sudoUID, sudoUIDSet := os.LookupEnv("SUDO_UID")
	sudoGID, sudoGIDSet := os.LookupEnv("SUDO_GID")

	// containerlab falls back to SUDO_USER/USER when its owner option is ignored.
	_ = os.Setenv("SUDO_USER", owner)
	_ = os.Setenv("USER", owner)
	if usr, err := user.Lookup(owner); err == nil {
		_ = os.Setenv("SUDO_UID", usr.Uid)
		_ = os.Setenv("SUDO_GID", usr.Gid)
	}

	return func() {
		restoreEnv("SUDO_USER", sudoUser, sudoUserSet)
		restoreEnv("USER", userEnv, userSet)
		restoreEnv("SUDO_UID", sudoUID, sudoUIDSet)
		restoreEnv("SUDO_GID", sudoGID, sudoGIDSet)
	}
}

func restoreEnv(key, value string, wasSet bool) {
	if wasSet {
		_ = os.Setenv(key, value)
		return
	}
	_ = os.Unsetenv(key)
}

type rootLinkNode struct {
	shortName string
	endpoints []clablinks.Endpoint
	nspath    string
}

func newRootLinkNode(shortName string) (*rootLinkNode, error) {
	currns, err := ns.GetCurrentNS()
	if err != nil {
		return nil, err
	}
	defer currns.Close()

	return &rootLinkNode{
		shortName: shortName,
		endpoints: []clablinks.Endpoint{},
		nspath:    currns.Path(),
	}, nil
}

func (n *rootLinkNode) AddLinkToContainer(_ context.Context, link netlink.Link, f func(ns.NetNS) error) error {
	netns, err := ns.GetNS(n.nspath)
	if err != nil {
		return err
	}
	defer netns.Close()

	if err := netlink.LinkSetNsFd(link, int(netns.Fd())); err != nil {
		return err
	}

	return netns.Do(f)
}

func (n *rootLinkNode) AddEndpoint(e clablinks.Endpoint) error {
	n.endpoints = append(n.endpoints, e)
	return nil
}

func (*rootLinkNode) GetLinkEndpointType() clablinks.LinkEndpointType {
	return clablinks.LinkEndpointTypeHost
}

func (n *rootLinkNode) GetShortName() string {
	return n.shortName
}

func (n *rootLinkNode) GetEndpoints() []clablinks.Endpoint {
	return n.endpoints
}

func (n *rootLinkNode) ExecFunction(_ context.Context, f func(ns.NetNS) error) error {
	netns, err := ns.GetNS(n.nspath)
	if err != nil {
		return err
	}
	defer netns.Close()

	return netns.Do(f)
}

func (*rootLinkNode) GetState() clabnodesstate.NodeState {
	return clabnodesstate.Deployed
}

func (n *rootLinkNode) Delete(ctx context.Context) error {
	for _, e := range n.endpoints {
		if err := e.GetLink().Remove(ctx); err != nil {
			return err
		}
	}
	return nil
}

// DeployOptions contains options for deploying a lab.
type DeployOptions struct {
	TopoPath       string
	Username       string
	Reconfigure    bool
	MaxWorkers     uint
	ExportTemplate string
	NodeFilter     []string
	SkipPostDeploy bool
	SkipLabDirACLs bool
}

// ApplyOptions contains options for applying topology changes to a lab.
type ApplyOptions struct {
	TopoPath       string
	Username       string
	DryRun         bool
	MaxWorkers     uint
	ExportTemplate string
	SkipPostDeploy bool
}

// DestroyOptions contains options for destroying a lab.
type DestroyOptions struct {
	LabName         string
	TopoPath        string
	Username        string
	Graceful        bool
	GracefulTimeout time.Duration
	Cleanup         bool
	KeepMgmtNet     bool
	NodeFilter      []string
	MaxWorkers      uint
}

// ListOptions contains options for listing labs/containers.
type ListOptions struct {
	LabName       string
	ContainerName string
	NodeName      string
}

// ExecOptions contains options for executing commands.
type ExecOptions struct {
	TopoPath      string
	LabName       string
	ContainerName string
	NodeName      string
	Commands      []string
	Username      string
}

// SaveOptions contains options for saving lab configuration.
type SaveOptions struct {
	TopoPath   string
	Username   string
	NodeFilter []string
}

// InspectOptions contains options for inspecting labs.
type InspectOptions struct {
	LabName  string
	Username string
	Details  bool
}

// InterfacesOptions contains options for listing interfaces.
type InterfacesOptions struct {
	LabName    string
	Username   string
	NodeFilter string
}

type NodeLifecycleAction string

const (
	NodeLifecycleActionStart   NodeLifecycleAction = "start"
	NodeLifecycleActionStop    NodeLifecycleAction = "stop"
	NodeLifecycleActionRestart NodeLifecycleAction = "restart"
	NodeLifecycleActionPause   NodeLifecycleAction = "pause"
	NodeLifecycleActionUnpause NodeLifecycleAction = "unpause"
)

type NodeLifecycleOptions struct {
	ContainerName string
	LabName       string
	TopoPath      string
	Username      string
	NodeNames     []string
	Action        NodeLifecycleAction
}

type ContainerlabToolRunOptions struct {
	Args []string
}

type DrawioGenerateOptions struct {
	TopoPath      string
	Runtime       string
	Layout        string
	Theme         string
	Interactive   bool
	DrawioVersion string
}

type DrawioGenerateResult struct {
	Path   string
	Output string
}

type FcliRunOptions struct {
	Runtime      string
	Network      string
	TopologyPath string
	CommandArgs  []string
}

type CloneTopologySourceOptions struct {
	SourceURL string
	Username  string
}

type CloneTopologySourceResult struct {
	RepoDir      string
	RepoName     string
	TopologyPath string
}

type RuntimeImageSummary struct {
	ID          string
	ShortID     string
	RepoTags    []string
	RepoDigests []string
	CreatedAt   string
	Size        string
	VirtualSize string
}

type runtimeImageCliRecord struct {
	ID           string `json:"ID"`
	Repository   string `json:"Repository"`
	Tag          string `json:"Tag"`
	Digest       string `json:"Digest"`
	CreatedAt    string `json:"CreatedAt"`
	CreatedSince string `json:"CreatedSince"`
	Size         string `json:"Size"`
	VirtualSize  string `json:"VirtualSize"`
}

// CloneTopologySource clones a supported topology source URL and resolves the topology file path.
func (s *Service) CloneTopologySource(opts CloneTopologySourceOptions) (*CloneTopologySourceResult, error) {
	sourceURL := strings.TrimSpace(opts.SourceURL)
	if sourceURL == "" {
		return nil, fmt.Errorf("topology source URL is required")
	}
	if strings.TrimSpace(opts.Username) == "" {
		return nil, fmt.Errorf("username is required")
	}

	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare working directory: %w", err)
	}

	normalizedURL := sourceURL
	if clabgit.IsGitHubShortURL(normalizedURL) {
		normalizedURL = "https://github.com/" + normalizedURL
	}

	repo, err := clabgit.NewRepo(normalizedURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse git URL: %w", err)
	}

	topoPath, err := s.processGitTopoFile(sourceURL, workDir)
	if err != nil {
		return nil, err
	}

	return &CloneTopologySourceResult{
		RepoDir:      filepath.Join(workDir, repo.GetName()),
		RepoName:     repo.GetName(),
		TopologyPath: topoPath,
	}, nil
}

// Deploy deploys a lab using the containerlab library.
func (s *Service) Deploy(ctx context.Context, opts DeployOptions) ([]clabruntime.GenericContainer, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Prepare clab working directory
	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare working directory: %w", err)
	}

	// Handle GitHub/GitLab URLs by cloning the repo first
	topoPath := opts.TopoPath
	if s.isGitURL(topoPath) {
		log.Debug("Detected git URL, cloning repository", "url", topoPath)
		var gitErr error
		topoPath, gitErr = s.processGitTopoFile(topoPath, workDir)
		if gitErr != nil {
			return nil, fmt.Errorf("failed to process git URL: %w", gitErr)
		}
		log.Debug("Using cloned topology file", "path", topoPath)
	}

	// Build clab options
	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithTopoPath(topoPath, nil),
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{
			Timeout: defaultTimeout,
		}),
	}

	if len(opts.NodeFilter) > 0 {
		clabOpts = append(clabOpts, clabcore.WithNodeFilter(opts.NodeFilter))
	}

	log.Debug("Creating containerlab instance",
		"topoPath", opts.TopoPath,
		"username", opts.Username,
		"runtime", config.AppConfig.ClabRuntime,
	)

	// Build deploy options
	deployOpts, err := clabcore.NewDeployOptions(opts.MaxWorkers)
	if err != nil {
		return nil, fmt.Errorf("failed to create deploy options: %w", err)
	}

	deployOpts.SetReconfigure(opts.Reconfigure).
		SetSkipPostDeploy(opts.SkipPostDeploy).
		SetSkipLabDirFileACLs(opts.SkipLabDirACLs)

	if opts.ExportTemplate != "" {
		deployOpts.SetExportTemplate(opts.ExportTemplate)
	}

	log.Info("Deploying lab",
		"username", opts.Username,
		"topoPath", opts.TopoPath,
		"reconfigure", opts.Reconfigure,
	)

	// Containerlab uses process-global cwd and owner environment during both
	// initialization and deployment, so keep the entire sequence in one critical
	// section.
	var containers []clabruntime.GenericContainer
	err = withContainerlabProcessState(workDir, opts.Username, func() error {
		clab, initErr := newContainerLabProcessLocked(clabOpts...)
		if initErr != nil {
			return fmt.Errorf("failed to create containerlab instance: %w", initErr)
		}
		var deployErr error
		containers, deployErr = clab.Deploy(ctx, deployOpts)
		return deployErr
	})
	if err != nil {
		return nil, fmt.Errorf("deployment failed: %w", err)
	}

	log.Info("Lab deployed successfully",
		"username", opts.Username,
		"containerCount", len(containers),
	)

	return containers, nil
}

// Apply applies topology changes to a lab using the containerlab library.
func (s *Service) Apply(ctx context.Context, opts ApplyOptions) (*clabcore.ApplyResult, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	if strings.TrimSpace(opts.TopoPath) == "" {
		return nil, fmt.Errorf("topology path is required")
	}

	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare working directory: %w", err)
	}

	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithTopoPath(opts.TopoPath, nil),
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{
			Timeout: defaultTimeout,
		}),
	}

	log.Debug("Creating containerlab instance for apply",
		"topoPath", opts.TopoPath,
		"username", opts.Username,
		"runtime", config.AppConfig.ClabRuntime,
	)

	applyOpts, err := clabcore.NewApplyOptions(opts.MaxWorkers)
	if err != nil {
		return nil, fmt.Errorf("failed to create apply options: %w", err)
	}
	applyOpts.SetDryRun(opts.DryRun).
		SetSkipPostDeploy(opts.SkipPostDeploy).
		SetExportTemplate(opts.ExportTemplate)

	log.Info("Applying lab topology",
		"username", opts.Username,
		"topoPath", opts.TopoPath,
		"dryRun", opts.DryRun,
	)

	var result *clabcore.ApplyResult
	var configuredLabName string
	err = withContainerlabProcessState(workDir, opts.Username, func() error {
		clab, initErr := newContainerLabProcessLocked(clabOpts...)
		if initErr != nil {
			return fmt.Errorf("failed to create containerlab instance: %w", initErr)
		}
		configuredLabName = clab.Config.Name
		var applyErr error
		result, applyErr = clab.Apply(ctx, applyOpts)
		return applyErr
	})
	if err != nil {
		return nil, fmt.Errorf("apply failed: %w", err)
	}
	if result != nil && strings.TrimSpace(result.LabName) == "" {
		result.LabName = configuredLabName
	}

	return result, nil
}

// Destroy destroys a lab using the containerlab library.
func (s *Service) Destroy(ctx context.Context, opts DestroyOptions) error {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Prepare clab working directory
	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return fmt.Errorf("failed to prepare working directory: %w", err)
	}

	// Build clab options - use topology path if available, otherwise use lab name
	clabTimeout := defaultTimeout
	if opts.Graceful {
		clabTimeout = gracefulDestroyTimeout
		if opts.GracefulTimeout > 0 {
			clabTimeout = opts.GracefulTimeout
		}
	}
	var clabOpts []clabcore.ClabOption
	clabOpts = append(clabOpts, clabcore.WithTimeout(clabTimeout))

	if opts.TopoPath != "" {
		clabOpts = append(clabOpts, clabcore.WithTopoPath(opts.TopoPath, nil))
	} else if opts.LabName != "" {
		clabOpts = append(clabOpts, clabcore.WithTopologyFromLab(opts.LabName, nil))
	} else {
		return fmt.Errorf("either lab name or topology path is required")
	}

	clabOpts = append(clabOpts,
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: clabTimeout}),
	)

	if opts.KeepMgmtNet {
		clabOpts = append(clabOpts, clabcore.WithKeepMgmtNet())
	}

	log.Debug("Creating containerlab instance for destroy",
		"labName", opts.LabName,
		"topoPath", opts.TopoPath,
		"username", opts.Username,
	)

	// Build destroy options
	destroyOpts := []clabcore.DestroyOption{
		clabcore.WithDestroyMaxWorkers(opts.MaxWorkers),
	}

	if opts.Graceful {
		destroyOpts = append(destroyOpts, clabcore.WithDestroyGraceful())
	}

	if opts.Cleanup {
		destroyOpts = append(destroyOpts, clabcore.WithDestroyCleanup())
	}

	if opts.KeepMgmtNet {
		destroyOpts = append(destroyOpts, clabcore.WithDestroyKeepMgmtNet())
	}

	if len(opts.NodeFilter) > 0 {
		destroyOpts = append(destroyOpts, clabcore.WithDestroyNodeFilter(opts.NodeFilter))
	}

	log.Info("Destroying lab",
		"username", opts.Username,
		"labName", opts.LabName,
		"graceful", opts.Graceful,
		"gracefulTimeout", opts.GracefulTimeout,
		"cleanup", opts.Cleanup,
	)

	// Destroy the lab while protecting the process-global working directory.
	if err := withContainerlabProcessState(workDir, "", func() error {
		clab, initErr := newContainerLabProcessLocked(clabOpts...)
		if initErr != nil {
			return fmt.Errorf("failed to create containerlab instance: %w", initErr)
		}
		return clab.Destroy(ctx, destroyOpts...)
	}); err != nil {
		return fmt.Errorf("destroy failed: %w", err)
	}

	log.Info("Lab destroyed successfully",
		"username", opts.Username,
		"labName", opts.LabName,
	)

	return nil
}

// ListContainers lists containers matching the given options.
func (s *Service) ListContainers(ctx context.Context, opts ListOptions) ([]clabruntime.GenericContainer, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Create a minimal clab instance for listing (no topology needed)
	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: defaultTimeout}),
	}

	clab, err := newContainerLab(clabOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	// Build list options
	listOpts := []clabcore.ListOption{
		clabcore.WithListclabLabelExists(), // Only list containerlab-managed containers
	}

	if opts.LabName != "" {
		listOpts = append(listOpts, clabcore.WithListLabName(opts.LabName))
	}

	if opts.ContainerName != "" {
		listOpts = append(listOpts, clabcore.WithListContainerName(opts.ContainerName))
	}

	if opts.NodeName != "" {
		listOpts = append(listOpts, clabcore.WithListNodeName(opts.NodeName))
	}

	log.Debug("Listing containers",
		"labName", opts.LabName,
		"containerName", opts.ContainerName,
		"nodeName", opts.NodeName,
	)

	containers, err := clab.ListContainers(ctx, listOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	return containers, nil
}

func (s *Service) RunNodeLifecycleAction(ctx context.Context, opts NodeLifecycleOptions) error {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	switch opts.Action {
	case NodeLifecycleActionStart, NodeLifecycleActionStop, NodeLifecycleActionRestart:
		return s.runTopologyNodeLifecycleAction(ctx, opts)
	case NodeLifecycleActionPause, NodeLifecycleActionUnpause:
	default:
		return fmt.Errorf("unsupported node lifecycle action: %q", opts.Action)
	}

	containerName := strings.TrimSpace(opts.ContainerName)
	if containerName == "" {
		return fmt.Errorf("container name is required")
	}

	rt, err := s.getContainerRuntime()
	if err != nil {
		return err
	}

	switch opts.Action {
	case NodeLifecycleActionPause:
		err = rt.PauseContainer(ctx, containerName)
	case NodeLifecycleActionUnpause:
		err = rt.UnpauseContainer(ctx, containerName)
	}

	if err != nil {
		return fmt.Errorf("failed to %s container %q: %w", opts.Action, containerName, err)
	}

	return nil
}

func (s *Service) RunLabLifecycleAction(ctx context.Context, opts NodeLifecycleOptions) error {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	switch opts.Action {
	case NodeLifecycleActionStart, NodeLifecycleActionStop, NodeLifecycleActionRestart:
		return s.runTopologyNodeLifecycleAction(ctx, opts)
	default:
		return fmt.Errorf("unsupported lab lifecycle action: %q", opts.Action)
	}
}

func (s *Service) runTopologyNodeLifecycleAction(ctx context.Context, opts NodeLifecycleOptions) error {
	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return fmt.Errorf("failed to prepare working directory: %w", err)
	}

	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: defaultTimeout}),
	}

	topoPath := strings.TrimSpace(opts.TopoPath)
	labName := strings.TrimSpace(opts.LabName)
	switch {
	case topoPath != "":
		clabOpts = append(clabOpts, clabcore.WithTopoPath(topoPath, nil))
	case labName != "":
		clabOpts = append(clabOpts, clabcore.WithTopologyFromLab(labName, nil))
	default:
		return fmt.Errorf("either lab name or topology path is required")
	}

	nodeNames := cleanNodeNames(opts.NodeNames)
	log.Info("Running topology lifecycle action",
		"username", opts.Username,
		"labName", opts.LabName,
		"topoPath", opts.TopoPath,
		"action", opts.Action,
		"nodes", nodeNames,
	)

	err = withContainerlabProcessState(workDir, "", func() error {
		clab, initErr := newContainerLabProcessLocked(clabOpts...)
		if initErr != nil {
			return fmt.Errorf("failed to create containerlab instance: %w", initErr)
		}
		switch opts.Action {
		case NodeLifecycleActionStart:
			return clab.StartNodes(ctx, nodeNames)
		case NodeLifecycleActionStop:
			return clab.StopNodes(ctx, nodeNames)
		case NodeLifecycleActionRestart:
			return clab.RestartNodes(ctx, nodeNames)
		default:
			return fmt.Errorf("unsupported topology lifecycle action: %q", opts.Action)
		}
	})
	if err != nil {
		return fmt.Errorf("failed to %s node(s): %w", opts.Action, err)
	}

	return nil
}

func cleanNodeNames(nodeNames []string) []string {
	cleaned := make([]string, 0, len(nodeNames))
	for _, nodeName := range nodeNames {
		trimmed := strings.TrimSpace(nodeName)
		if trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	return cleaned
}

func (s *Service) RunContainerlabTool(ctx context.Context, opts ContainerlabToolRunOptions) (string, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	if len(opts.Args) == 0 {
		return "", fmt.Errorf("at least one command argument is required")
	}

	return s.runCommand(ctx, "containerlab", opts.Args)
}

func configuredRuntimeName() string {
	runtimeName := strings.TrimSpace(config.AppConfig.ClabRuntime)
	if runtimeName == "" {
		return "docker"
	}
	return runtimeName
}

func shortRuntimeImageID(id string) string {
	trimmed := strings.TrimPrefix(strings.TrimSpace(id), "sha256:")
	if len(trimmed) <= 12 {
		return trimmed
	}
	return trimmed[:12]
}

func validImageTag(repository, tag string) string {
	repository = strings.TrimSpace(repository)
	tag = strings.TrimSpace(tag)
	if repository == "" || repository == "<none>" || tag == "" || tag == "<none>" {
		return ""
	}
	return repository + ":" + tag
}

func validImageDigest(repository, digest string) string {
	repository = strings.TrimSpace(repository)
	digest = strings.TrimSpace(digest)
	if repository == "" || repository == "<none>" || digest == "" || digest == "<none>" {
		return ""
	}
	return repository + "@" + digest
}

func appendUniqueString(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func (s *Service) ListRuntimeImages(ctx context.Context) ([]RuntimeImageSummary, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	runtimeName := configuredRuntimeName()
	output, err := s.runCommand(ctx, runtimeName, []string{
		"image",
		"ls",
		"--all",
		"--digests",
		"--no-trunc",
		"--format",
		"{{json .}}",
	})
	if err != nil {
		return nil, err
	}

	imagesByID := map[string]*RuntimeImageSummary{}
	order := []string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var record runtimeImageCliRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, fmt.Errorf("failed to parse %s image listing: %w", runtimeName, err)
		}
		id := strings.TrimSpace(record.ID)
		if id == "" {
			continue
		}
		image := imagesByID[id]
		if image == nil {
			image = &RuntimeImageSummary{
				ID:          id,
				ShortID:     shortRuntimeImageID(id),
				RepoTags:    []string{},
				RepoDigests: []string{},
				CreatedAt:   strings.TrimSpace(record.CreatedAt),
				Size:        strings.TrimSpace(record.Size),
				VirtualSize: strings.TrimSpace(record.VirtualSize),
			}
			if image.CreatedAt == "" {
				image.CreatedAt = strings.TrimSpace(record.CreatedSince)
			}
			imagesByID[id] = image
			order = append(order, id)
		}
		image.RepoTags = appendUniqueString(image.RepoTags, validImageTag(record.Repository, record.Tag))
		image.RepoDigests = appendUniqueString(image.RepoDigests, validImageDigest(record.Repository, record.Digest))
	}

	images := make([]RuntimeImageSummary, 0, len(order))
	for _, id := range order {
		images = append(images, *imagesByID[id])
	}
	return images, nil
}

func (s *Service) PullRuntimeImage(ctx context.Context, image string) (string, error) {
	baseCtx := ctx
	if _, hasDeadline := baseCtx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		baseCtx, cancel = context.WithTimeout(baseCtx, imagePullTimeout)
		defer cancel()
	}
	return s.runCommand(baseCtx, configuredRuntimeName(), []string{"pull", image})
}

func (s *Service) RemoveRuntimeImage(ctx context.Context, reference string, force bool) (string, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	args := []string{"image", "rm"}
	if force {
		args = append(args, "--force")
	}
	args = append(args, reference)
	return s.runCommand(ctx, configuredRuntimeName(), args)
}

func (s *Service) RunFcliCommand(ctx context.Context, opts FcliRunOptions) (string, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	topologyPath := strings.TrimSpace(opts.TopologyPath)
	if topologyPath == "" {
		return "", fmt.Errorf("topology path is required")
	}

	if len(opts.CommandArgs) == 0 {
		return "", fmt.Errorf("fcli command is required")
	}

	runtimeName := strings.TrimSpace(opts.Runtime)
	if runtimeName == "" {
		runtimeName = strings.TrimSpace(config.AppConfig.ClabRuntime)
	}
	if runtimeName == "" {
		runtimeName = "docker"
	}

	networkName := strings.TrimSpace(opts.Network)
	if networkName == "" {
		networkName = "clab"
	}

	args := []string{
		"run",
		"--pull", "always",
		"--rm",
		"--network", networkName,
		"-v", "/etc/hosts:/etc/hosts:ro",
		"-v", fmt.Sprintf("%s:/topo.yml", topologyPath),
		"ghcr.io/srl-labs/nornir-srl:latest",
		"-t", "/topo.yml",
	}
	args = append(args, opts.CommandArgs...)

	return s.runCommand(ctx, runtimeName, args)
}

func (s *Service) GenerateDrawioFile(ctx context.Context, opts DrawioGenerateOptions) (DrawioGenerateResult, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	topoPath := strings.TrimSpace(opts.TopoPath)
	if topoPath == "" {
		return DrawioGenerateResult{}, fmt.Errorf("topology path is required")
	}

	runtimeName := strings.TrimSpace(opts.Runtime)
	if runtimeName == "" {
		runtimeName = strings.TrimSpace(config.AppConfig.ClabRuntime)
	}
	if runtimeName == "" {
		runtimeName = "docker"
	}

	layout := strings.ToLower(strings.TrimSpace(opts.Layout))
	if layout == "" {
		layout = "horizontal"
	}
	if layout != "horizontal" && layout != "vertical" {
		return DrawioGenerateResult{}, fmt.Errorf("unsupported drawio layout: %q", layout)
	}

	theme := strings.TrimSpace(opts.Theme)
	if theme == "" {
		theme = "nokia_modern"
	}

	args := []string{
		"graph",
		"-r", runtimeName,
		"--drawio",
	}

	if drawioVersion := strings.TrimSpace(opts.DrawioVersion); drawioVersion != "" {
		args = append(args, "--drawio-version", drawioVersion)
	}

	if opts.Interactive {
		args = append(args, "--drawio-args", "-I")
	} else {
		args = append(args, "--drawio-args", fmt.Sprintf("--theme %s --layout %s", theme, layout))
	}

	args = append(args, "-t", topoPath)

	output, err := s.runCommand(ctx, "containerlab", args)
	if err != nil {
		return DrawioGenerateResult{}, err
	}

	drawioPath := drawioOutputPathFromTopo(topoPath)
	if _, err := os.Stat(drawioPath); err != nil {
		return DrawioGenerateResult{}, fmt.Errorf("drawio output file not found at %q: %w", drawioPath, err)
	}

	return DrawioGenerateResult{
		Path:   drawioPath,
		Output: output,
	}, nil
}

// ListContainerInterfaces lists interfaces for a specific container.
func (s *Service) ListContainerInterfaces(ctx context.Context, container *clabruntime.GenericContainer) (*clabtypes.ContainerInterfaces, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: defaultTimeout}),
	}

	clab, err := newContainerLab(clabOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	interfaces, err := clab.ListContainerInterfaces(ctx, container)
	if err != nil {
		return nil, fmt.Errorf("failed to list container interfaces: %w", err)
	}

	return interfaces, nil
}

// ListContainersInterfaces lists interfaces for multiple containers.
func (s *Service) ListContainersInterfaces(ctx context.Context, containers []clabruntime.GenericContainer) ([]*clabtypes.ContainerInterfaces, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: defaultTimeout}),
	}

	clab, err := newContainerLab(clabOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	interfaces, err := clab.ListContainersInterfaces(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers interfaces: %w", err)
	}

	return interfaces, nil
}

// Exec executes commands on containers.
func (s *Service) Exec(ctx context.Context, opts ExecOptions) (*clabexec.ExecCollection, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Prepare clab working directory
	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare working directory: %w", err)
	}

	// Build clab options
	var clabOpts []clabcore.ClabOption
	clabOpts = append(clabOpts, clabcore.WithTimeout(defaultTimeout))
	if opts.TopoPath != "" {
		clabOpts = append(clabOpts, clabcore.WithTopoPath(opts.TopoPath, nil))
	}
	clabOpts = append(clabOpts,
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: defaultTimeout}),
	)

	// Build list options for targeting containers
	var listOpts []clabcore.ListOption
	if opts.LabName != "" {
		listOpts = append(listOpts, clabcore.WithListLabName(opts.LabName))
	}
	if opts.ContainerName != "" {
		listOpts = append(listOpts, clabcore.WithListContainerName(opts.ContainerName))
	}
	if opts.NodeName != "" {
		listOpts = append(listOpts, clabcore.WithListNodeName(opts.NodeName))
	}

	log.Debug("Executing commands on containers",
		"commands", opts.Commands,
		"labName", opts.LabName,
		"containerName", opts.ContainerName,
	)

	var result *clabexec.ExecCollection
	err = withContainerlabProcessState(workDir, "", func() error {
		clab, initErr := newContainerLabProcessLocked(clabOpts...)
		if initErr != nil {
			return fmt.Errorf("failed to create containerlab instance: %w", initErr)
		}
		var execErr error
		result, execErr = clab.Exec(ctx, opts.Commands, listOpts...)
		return execErr
	})
	if err != nil {
		return nil, fmt.Errorf("exec failed: %w", err)
	}

	return result, nil
}

// SaveConfig saves the configuration of lab nodes.
func (s *Service) SaveConfig(ctx context.Context, opts SaveOptions) error {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Prepare clab working directory
	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return fmt.Errorf("failed to prepare working directory: %w", err)
	}

	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithTopoPath(opts.TopoPath, nil),
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: defaultTimeout}),
	}

	if len(opts.NodeFilter) > 0 {
		clabOpts = append(clabOpts, clabcore.WithNodeFilter(opts.NodeFilter))
	}

	log.Info("Saving lab configuration",
		"username", opts.Username,
		"topoPath", opts.TopoPath,
	)

	// Save config for each node
	if err := withContainerlabProcessState(workDir, "", func() error {
		clab, initErr := newContainerLabProcessLocked(clabOpts...)
		if initErr != nil {
			return fmt.Errorf("failed to create containerlab instance: %w", initErr)
		}
		return clab.Save(ctx)
	}); err != nil {
		return fmt.Errorf("save failed: %w", err)
	}

	log.Info("Lab configuration saved successfully",
		"username", opts.Username,
	)

	return nil
}

// CACreateOptions contains options for creating a CA.
type CACreateOptions struct {
	Name         string
	Expiry       time.Duration
	CommonName   string
	Country      string
	Locality     string
	Organization string
	OrgUnit      string
	KeySize      int
	OutputPath   string
}

// CreateCA creates a new Certificate Authority.
func (s *Service) CreateCA(ctx context.Context, opts CACreateOptions) (*clabcert.Certificate, error) {
	_, cancel := s.ensureTimeout(ctx)
	defer cancel()

	ca := clabcert.NewCA()

	// Go crypto/rsa rejects insecure key sizes; containerlab cert helpers
	// accept 0 which used to imply a default. Enforce a safe default here.
	keySize := opts.KeySize
	if keySize == 0 {
		keySize = 2048
	}
	if keySize < 2048 {
		keySize = 2048
	}

	input := &clabcert.CACSRInput{
		CommonName:       opts.CommonName,
		Country:          opts.Country,
		Locality:         opts.Locality,
		Organization:     opts.Organization,
		OrganizationUnit: opts.OrgUnit,
		Expiry:           opts.Expiry,
		KeySize:          keySize,
	}

	log.Info("Generating CA certificate",
		"name", opts.Name,
		"commonName", opts.CommonName,
		"expiry", opts.Expiry,
		"keySize", keySize,
	)

	cert, err := ca.GenerateCACert(input)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA certificate: %w", err)
	}

	// Write certificate to disk
	certPath := filepath.Join(opts.OutputPath, opts.Name+".pem")
	keyPath := filepath.Join(opts.OutputPath, opts.Name+".key")
	csrPath := filepath.Join(opts.OutputPath, opts.Name+".csr")

	if err := cert.Write(certPath, keyPath, csrPath); err != nil {
		return nil, fmt.Errorf("failed to write CA certificate: %w", err)
	}

	log.Info("CA certificate created successfully",
		"certPath", certPath,
		"keyPath", keyPath,
	)

	return cert, nil
}

// CertSignOptions contains options for signing a certificate.
type CertSignOptions struct {
	Name         string
	Hosts        []string
	CommonName   string
	Country      string
	Locality     string
	Organization string
	OrgUnit      string
	KeySize      int
	CACertPath   string
	CAKeyPath    string
	OutputPath   string
}

// SignCert signs a certificate with a CA.
func (s *Service) SignCert(ctx context.Context, opts CertSignOptions) (*clabcert.Certificate, error) {
	_, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Load CA certificate
	caCert, err := clabcert.NewCertificateFromFile(opts.CACertPath, opts.CAKeyPath, "")
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	ca := clabcert.NewCA()
	if err := ca.SetCACert(caCert); err != nil {
		return nil, fmt.Errorf("failed to set CA certificate: %w", err)
	}

	input := &clabcert.NodeCSRInput{
		Hosts:            opts.Hosts,
		CommonName:       opts.CommonName,
		Country:          opts.Country,
		Locality:         opts.Locality,
		Organization:     opts.Organization,
		OrganizationUnit: opts.OrgUnit,
		KeySize:          opts.KeySize,
	}

	log.Info("Signing certificate",
		"name", opts.Name,
		"hosts", opts.Hosts,
	)

	cert, err := ca.GenerateAndSignNodeCert(input)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Write certificate to disk
	certPath := filepath.Join(opts.OutputPath, opts.Name+".pem")
	keyPath := filepath.Join(opts.OutputPath, opts.Name+".key")
	csrPath := filepath.Join(opts.OutputPath, opts.Name+".csr")

	if err := cert.Write(certPath, keyPath, csrPath); err != nil {
		return nil, fmt.Errorf("failed to write signed certificate: %w", err)
	}

	log.Info("Certificate signed successfully",
		"certPath", certPath,
		"keyPath", keyPath,
	)

	return cert, nil
}

// DisableTxOffloadOptions contains options for disabling TX offload.
type DisableTxOffloadOptions struct {
	ContainerName string
	InterfaceName string
}

// DisableTxOffload disables TX checksum offload on a container's interface.
func (s *Service) DisableTxOffload(ctx context.Context, opts DisableTxOffloadOptions) error {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: defaultTimeout}),
	}

	clab, err := newContainerLab(clabOpts...)
	if err != nil {
		return fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	// Get the runtime - there should be exactly one configured
	var runtime clabruntime.ContainerRuntime
	for _, r := range clab.Runtimes {
		runtime = r
		break
	}
	if runtime == nil {
		return fmt.Errorf("no container runtime configured")
	}

	ifaceName := opts.InterfaceName
	if ifaceName == "" {
		ifaceName = "eth0"
	}

	log.Info("Disabling TX offload",
		"container", opts.ContainerName,
		"interface", ifaceName,
	)

	// Get the container's network namespace path directly from the runtime
	nsPath, err := runtime.GetNSPath(ctx, opts.ContainerName)
	if err != nil {
		return fmt.Errorf("failed to get namespace path for container %s: %w", opts.ContainerName, err)
	}

	// Get the namespace handle and execute the ethtool function
	netns, err := ns.GetNS(nsPath)
	if err != nil {
		return fmt.Errorf("failed to open network namespace %s: %w", nsPath, err)
	}
	defer netns.Close()

	// Execute the ethtool function in the container's namespace
	err = netns.Do(clabutils.NSEthtoolTXOff(opts.ContainerName, ifaceName))
	if err != nil {
		return fmt.Errorf("failed to disable TX offload: %w", err)
	}

	log.Info("TX offload disabled successfully",
		"container", opts.ContainerName,
		"interface", ifaceName,
	)

	return nil
}

// VethCreateOptions contains options for creating a veth pair.
type VethCreateOptions struct {
	AEndpoint string
	BEndpoint string
	MTU       int
}

// CreateVeth creates a veth pair between two endpoints.
func (s *Service) CreateVeth(ctx context.Context, opts VethCreateOptions) error {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	parsedAEnd, err := s.parseVethEndpoint(opts.AEndpoint)
	if err != nil {
		return fmt.Errorf("failed to parse A endpoint: %w", err)
	}

	parsedBEnd, err := s.parseVethEndpoint(opts.BEndpoint)
	if err != nil {
		return fmt.Errorf("failed to parse B endpoint: %w", err)
	}

	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: defaultTimeout}),
	}

	clab, err := newContainerLab(clabOpts...)
	if err != nil {
		return fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	// Create fake nodes to make links resolve work
	err = s.createVethNodes(ctx, clab, parsedAEnd, parsedBEnd, config.AppConfig.ClabRuntime)
	if err != nil {
		return fmt.Errorf("failed to create nodes: %w", err)
	}

	hostNode, err := newRootLinkNode("host")
	if err != nil {
		return fmt.Errorf("failed to create host link node: %w", err)
	}

	linkRaw := &clablinks.LinkVEthRaw{
		Endpoints: []*clablinks.EndpointRaw{
			clablinks.NewEndpointRaw(parsedAEnd.Node, parsedAEnd.Iface, ""),
			clablinks.NewEndpointRaw(parsedBEnd.Node, parsedBEnd.Iface, ""),
		},
		LinkCommonParams: clablinks.LinkCommonParams{
			MTU: opts.MTU,
		},
	}

	// Copy nodes to links.Nodes
	resolveNodes := make(map[string]clablinks.Node, len(clab.Nodes))
	for k, v := range clab.Nodes {
		resolveNodes[k] = v
	}
	resolveNodes["host"] = hostNode

	link, err := linkRaw.Resolve(&clablinks.ResolveParams{Nodes: resolveNodes})
	if err != nil {
		return fmt.Errorf("failed to resolve link: %w", err)
	}

	// Deploy the endpoints
	for _, ep := range link.GetEndpoints() {
		if err := ep.GetLink().Deploy(ctx, ep); err != nil {
			return fmt.Errorf("failed to deploy endpoint %s: %w", ep, err)
		}
	}

	log.Info("veth pair created successfully",
		"aEndpoint", opts.AEndpoint,
		"bEndpoint", opts.BEndpoint,
	)

	return nil
}

// parsedEndpoint represents a parsed veth endpoint.
type parsedEndpoint struct {
	Node  string
	Iface string
	Kind  clablinks.LinkEndpointType
}

// parseVethEndpoint parses a veth endpoint definition.
func (s *Service) parseVethEndpoint(endpoint string) (parsedEndpoint, error) {
	endpoint = strings.TrimSpace(endpoint)
	ep := parsedEndpoint{}
	arr := strings.Split(endpoint, ":")

	switch len(arr) {
	case 2:
		ep.Kind = clablinks.LinkEndpointTypeVeth
		if arr[0] == "host" {
			ep.Kind = clablinks.LinkEndpointTypeHost
		}
		ep.Node = arr[0]
		ep.Iface = arr[1]
	case 3:
		switch arr[0] {
		case "bridge", "ovs-bridge":
			ep.Kind = clablinks.LinkEndpointTypeBridge
		case "bridge-ns":
			ep.Kind = clablinks.LinkEndpointTypeBridgeNS
		default:
			ep.Kind = clablinks.LinkEndpointTypeVeth
		}
		ep.Node = arr[1]
		ep.Iface = arr[2]
	default:
		return ep, fmt.Errorf("malformed veth endpoint reference: %s", endpoint)
	}

	return ep, nil
}

// createVethNodes creates fake nodes for veth link resolution.
func (s *Service) createVethNodes(ctx context.Context, clab *clabcore.CLab, aEnd, bEnd parsedEndpoint, rt string) error {
	for _, epDef := range []parsedEndpoint{aEnd, bEnd} {
		var kind string
		switch epDef.Kind {
		case clablinks.LinkEndpointTypeHost:
			kind = "host"
		case clablinks.LinkEndpointTypeBridge, clablinks.LinkEndpointTypeBridgeNS:
			kind = "bridge"
		default:
			kind = "linux"
		}

		nodeCfg := &clabtypes.NodeConfig{
			ShortName: epDef.Node,
			LongName:  epDef.Node,
			Runtime:   rt,
		}

		n, err := clab.Reg.NewNodeOfKind(kind)
		if err != nil {
			return fmt.Errorf("error constructing node %s: %w", epDef.Node, err)
		}

		err = n.Init(nodeCfg, clabnodes.WithRuntime(clab.Runtimes[rt]))
		if err != nil {
			return fmt.Errorf("failed to initialize node %s: %w", epDef.Node, err)
		}

		n.SetState(clabnodesstate.Deployed)
		clab.Nodes[epDef.Node] = n
	}

	return nil
}

// VxlanCreateOptions contains options for creating a VxLAN tunnel.
type VxlanCreateOptions struct {
	Remote       string
	Link         string
	ID           int
	DstPort      int
	SrcPort      int
	ParentDevice string
	MTU          int
}

// CreateVxlan creates a VxLAN tunnel.
func (s *Service) CreateVxlan(ctx context.Context, opts VxlanCreateOptions) error {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Verify link exists
	if _, err := netlink.LinkByName(opts.Link); err != nil {
		return fmt.Errorf("failed to lookup link %q: %w", opts.Link, err)
	}

	// If parent device not set, find route to remote
	parentDevice := opts.ParentDevice
	if parentDevice == "" {
		r, err := clabutils.GetRouteForIP(net.ParseIP(opts.Remote))
		if err != nil {
			return fmt.Errorf("failed to find route to VxLAN remote address %s: %w", opts.Remote, err)
		}
		parentDevice = r.Interface.Name
	}

	hostNode, err := newRootLinkNode("host")
	if err != nil {
		return fmt.Errorf("failed to create host link node: %w", err)
	}

	vxlanIface := "vx-" + opts.Link
	vxlraw := &clablinks.LinkVxlanRaw{
		Remote:          opts.Remote,
		VNI:             opts.ID,
		ParentInterface: parentDevice,
		LinkCommonParams: clablinks.LinkCommonParams{
			MTU: opts.MTU,
		},
		DstPort:  opts.DstPort,
		SrcPort:  opts.SrcPort,
		LinkType: clablinks.LinkTypeVxlan,
		Endpoint: *clablinks.NewEndpointRaw("host", vxlanIface, ""),
	}

	rp := &clablinks.ResolveParams{
		Nodes: map[string]clablinks.Node{
			"host": hostNode,
		},
	}

	link, err := vxlraw.Resolve(rp)
	if err != nil {
		return fmt.Errorf("failed to resolve VxLAN link: %w", err)
	}

	vxl, ok := link.(*clablinks.LinkVxlan)
	if !ok {
		return fmt.Errorf("resolved link is not a LinkVxlan link")
	}

	endpoints := vxl.GetEndpoints()
	if len(endpoints) == 0 {
		return fmt.Errorf("resolved VxLAN link has no endpoints")
	}

	if err := vxl.Deploy(ctx, endpoints[0]); err != nil {
		return fmt.Errorf("failed to deploy VxLAN: %w", err)
	}

	if err := stitchInterfaces(vxlanIface, opts.Link); err != nil {
		_ = vxl.Remove(ctx)
		return fmt.Errorf("failed to stitch VxLAN to link: %w", err)
	}

	if err := stitchInterfaces(opts.Link, vxlanIface); err != nil {
		_ = vxl.Remove(ctx)
		return fmt.Errorf("failed to stitch link to VxLAN: %w", err)
	}

	log.Info("VxLAN tunnel created successfully",
		"remote", opts.Remote,
		"link", opts.Link,
		"vni", opts.ID,
	)

	return nil
}

func stitchInterfaces(srcIface, dstIface string) error {
	src, err := netlink.LinkByName(srcIface)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %w", srcIface, err)
	}

	dst, err := netlink.LinkByName(dstIface)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %w", dstIface, err)
	}

	qdisc := &netlink.Ingress{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: src.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_INGRESS,
		},
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && !os.IsExist(err) {
		return err
	}

	filter := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: src.Attrs().Index,
			Parent:    netlink.MakeHandle(0xffff, 0),
			Protocol:  syscall.ETH_P_ALL,
		},
		Sel: &netlink.TcU32Sel{
			Keys: []netlink.TcU32Key{
				{
					Mask: 0x0,
					Val:  0,
				},
			},
			Flags: netlink.TC_U32_TERMINAL,
		},
		Actions: []netlink.Action{
			&netlink.MirredAction{
				ActionAttrs: netlink.ActionAttrs{
					Action: netlink.TC_ACT_STOLEN,
				},
				MirredAction: netlink.TCA_EGRESS_REDIR,
				Ifindex:      dst.Attrs().Index,
			},
		},
	}

	return netlink.FilterAdd(filter)
}

// DeleteVxlan deletes VxLAN tunnels matching a prefix.
func (s *Service) DeleteVxlan(ctx context.Context, prefix string) ([]string, error) {
	_, cancel := s.ensureTimeout(ctx)
	defer cancel()

	ls, err := clabutils.GetLinksByNamePrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to get links by prefix: %w", err)
	}

	var deleted []string
	for _, l := range ls {
		if l.Type() != "vxlan" {
			continue
		}

		name := l.Attrs().Name
		log.Info("Deleting VxLAN link", "name", name)

		err := netlink.LinkDel(l)
		if err != nil {
			log.Warn("Error deleting link", "name", name, "error", err)
			continue
		}
		deleted = append(deleted, name)
	}

	return deleted, nil
}

// --- Netem ---

// NetemSetOptions contains options for setting link impairments using netem.
type NetemSetOptions struct {
	ContainerName string
	Interface     string
	Delay         time.Duration
	Jitter        time.Duration
	Loss          float64
	Rate          uint64 // kbit/s
	Corruption    float64
}

// SetNetem applies netem impairments to a specific interface in a container's network namespace.
func (s *Service) SetNetem(ctx context.Context, opts NetemSetOptions) error {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Best-effort: ensure netem kernel module is loaded (helps on some distros).
	if err := exec.CommandContext(ctx, "modprobe", "sch_netem").Run(); err != nil {
		log.Warn("failed to load sch_netem kernel module", "err", err)
	}

	rt, err := s.getContainerRuntime()
	if err != nil {
		return err
	}

	nsPath, err := rt.GetNSPath(ctx, opts.ContainerName)
	if err != nil {
		return fmt.Errorf("failed to get namespace path for container %s: %w", opts.ContainerName, err)
	}

	nodeNS, err := ns.GetNS(nsPath)
	if err != nil {
		return fmt.Errorf("failed to open network namespace %s: %w", nsPath, err)
	}
	defer nodeNS.Close()

	tcnl, err := clabnetem.NewTC(int(nodeNS.Fd()))
	if err != nil {
		return fmt.Errorf("failed to open rtnetlink socket: %w", err)
	}
	defer func() {
		if closeErr := tcnl.Close(); closeErr != nil {
			log.Warn("failed to close rtnetlink socket", "err", closeErr)
		}
	}()

	err = nodeNS.Do(func(_ ns.NetNS) error {
		netemIfLink, err := resolveNetemLink(opts.Interface)
		if err != nil {
			var lnf netlink.LinkNotFoundError
			if errors.As(err, &lnf) {
				return fmt.Errorf("%w: %s", ErrNetemInterfaceNotFound, opts.Interface)
			}
			return err
		}

		netemIfName := netemIfLink.Attrs().Name
		iface, err := net.InterfaceByName(netemIfName)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrNetemInterfaceNotFound, netemIfName)
		}

		_, err = clabnetem.SetImpairments(
			tcnl,
			opts.ContainerName,
			iface,
			opts.Delay,
			opts.Jitter,
			opts.Loss,
			opts.Rate,
			opts.Corruption,
		)
		return err
	})
	if err != nil {
		return err
	}

	log.Info("netem impairments set",
		"container", opts.ContainerName,
		"interface", opts.Interface,
		"delay", opts.Delay.String(),
		"jitter", opts.Jitter.String(),
		"loss", opts.Loss,
		"rate_kbit", opts.Rate,
		"corruption", opts.Corruption,
	)

	return nil
}

func resolveNetemLink(iface string) (netlink.Link, error) {
	netemIfLink, err := netlink.LinkByName(clablinks.SanitizeInterfaceName(iface))
	if err == nil {
		return netemIfLink, nil
	}

	var lnf netlink.LinkNotFoundError
	if !errors.As(err, &lnf) {
		return nil, err
	}

	links, listErr := netlink.LinkList()
	if listErr != nil {
		return nil, listErr
	}
	for _, link := range links {
		if link.Attrs().Alias == iface {
			return link, nil
		}
	}

	return nil, err
}

// ResetNetem removes netem impairments from a specific interface in a container's network namespace.
func (s *Service) ResetNetem(ctx context.Context, containerName, iface string) error {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	rt, err := s.getContainerRuntime()
	if err != nil {
		return err
	}

	nsPath, err := rt.GetNSPath(ctx, containerName)
	if err != nil {
		return fmt.Errorf("failed to get namespace path for container %s: %w", containerName, err)
	}

	nodeNS, err := ns.GetNS(nsPath)
	if err != nil {
		return fmt.Errorf("failed to open network namespace %s: %w", nsPath, err)
	}
	defer nodeNS.Close()

	tcnl, err := clabnetem.NewTC(int(nodeNS.Fd()))
	if err != nil {
		return fmt.Errorf("failed to open rtnetlink socket: %w", err)
	}
	defer func() {
		if closeErr := tcnl.Close(); closeErr != nil {
			log.Warn("failed to close rtnetlink socket", "err", closeErr)
		}
	}()

	return nodeNS.Do(func(_ ns.NetNS) error {
		netemIfLink, err := resolveNetemLink(iface)
		if err != nil {
			var lnf netlink.LinkNotFoundError
			if errors.As(err, &lnf) {
				return fmt.Errorf("%w: %s", ErrNetemInterfaceNotFound, iface)
			}
			return err
		}

		netemIfIface, err := net.InterfaceByName(netemIfLink.Attrs().Name)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrNetemInterfaceNotFound, netemIfLink.Attrs().Name)
		}

		qdiscs, qdiscErr := clabnetem.Impairments(tcnl)
		if qdiscErr == nil && !hasNetemQdisc(qdiscs, netemIfIface.Index) {
			log.Debug("netem reset skipped because interface has no netem qdisc",
				"container", containerName,
				"interface", iface,
			)
			return nil
		}
		if qdiscErr != nil {
			log.Debug("failed to pre-check netem qdiscs before reset",
				"container", containerName,
				"interface", iface,
				"err", qdiscErr,
			)
		}

		if err := clabnetem.DeleteImpairments(tcnl, netemIfIface); err != nil {
			if isNetemAlreadyClearError(err) {
				log.Debug("netem reset delete raced with already-cleared qdisc",
					"container", containerName,
					"interface", iface,
					"err", err,
				)
				return nil
			}
			return err
		}

		return nil
	})
}

func hasNetemQdisc(qdiscs []gotc.Object, ifaceIndex int) bool {
	for idx := range qdiscs {
		if int(qdiscs[idx].Ifindex) == ifaceIndex && qdiscs[idx].Attribute.Kind == "netem" {
			return true
		}
	}
	return false
}

func isNetemAlreadyClearError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "invalid argument") ||
		strings.Contains(message, "no such file") ||
		strings.Contains(message, "not found") ||
		strings.Contains(message, "could not find qdisc") ||
		strings.Contains(message, "cannot find qdisc")
}

// ShowNetem returns the current netem impairments for interfaces that have netem qdisc set.
func (s *Service) ShowNetem(ctx context.Context, containerName string) ([]clabtypes.ImpairmentData, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	rt, err := s.getContainerRuntime()
	if err != nil {
		return nil, err
	}

	nsPath, err := rt.GetNSPath(ctx, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace path for container %s: %w", containerName, err)
	}

	nodeNS, err := ns.GetNS(nsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open network namespace %s: %w", nsPath, err)
	}
	defer nodeNS.Close()

	tcnl, err := clabnetem.NewTC(int(nodeNS.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to open rtnetlink socket: %w", err)
	}
	defer func() {
		if closeErr := tcnl.Close(); closeErr != nil {
			log.Warn("failed to close rtnetlink socket", "err", closeErr)
		}
	}()

	var impairments []clabtypes.ImpairmentData
	err = nodeNS.Do(func(_ ns.NetNS) error {
		qdiscs, err := clabnetem.Impairments(tcnl)
		if err != nil {
			return err
		}

		for idx := range qdiscs {
			if qdiscs[idx].Attribute.Kind != "netem" {
				continue // skip clsact or other qdisc types
			}
			impairments = append(impairments, qdiscToImpairmentData(&qdiscs[idx]))
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return impairments, nil
}

func (s *Service) getContainerRuntime() (clabruntime.ContainerRuntime, error) {
	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithRuntime(config.AppConfig.ClabRuntime, &clabruntime.RuntimeConfig{Timeout: defaultTimeout}),
	}

	clab, err := newContainerLab(clabOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	// Prefer explicitly configured runtime if present.
	if rt, ok := clab.Runtimes[config.AppConfig.ClabRuntime]; ok && rt != nil {
		return rt, nil
	}

	// Fall back to first configured runtime.
	for _, rt := range clab.Runtimes {
		if rt != nil {
			return rt, nil
		}
	}

	return nil, fmt.Errorf("no container runtime configured")
}

const msPerSec = 1000

func qdiscToImpairmentData(qdisc *gotc.Object) clabtypes.ImpairmentData {
	var ifDisplayName string

	link, err := netlink.LinkByIndex(int(qdisc.Ifindex))
	if err != nil || link == nil {
		ifDisplayName = fmt.Sprintf("ifindex:%d", qdisc.Ifindex)
	} else {
		ifDisplayName = link.Attrs().Name
		if link.Attrs().Alias != "" {
			ifDisplayName += fmt.Sprintf(" (%s)", link.Attrs().Alias)
		}
	}

	// Return empty values when netem is not set.
	if qdisc.Netem == nil {
		return clabtypes.ImpairmentData{
			Interface: ifDisplayName,
		}
	}

	data := clabtypes.ImpairmentData{
		Interface: ifDisplayName,
	}

	if qdisc.Netem.Latency64 != nil && *qdisc.Netem.Latency64 != 0 {
		data.Delay = (time.Duration(*qdisc.Netem.Latency64) * time.Nanosecond).String()
	}

	if qdisc.Netem.Jitter64 != nil && *qdisc.Netem.Jitter64 != 0 {
		data.Jitter = (time.Duration(*qdisc.Netem.Jitter64) * time.Nanosecond).String()
	}

	if qdisc.Netem.Rate != nil && int(qdisc.Netem.Rate.Rate) != 0 {
		data.Rate = int(uint64(qdisc.Netem.Rate.Rate) * 8 / msPerSec)
	}

	if qdisc.Netem.Corrupt != nil && qdisc.Netem.Corrupt.Probability != 0 {
		// round to 2 decimal places
		data.Corruption = math.Round((float64(qdisc.Netem.Corrupt.Probability)/
			float64(math.MaxUint32)*100)*100) / 100 //nolint: mnd
	}

	if qdisc.Netem.Qopt.Loss != 0 {
		// round to 2 decimal places
		data.PacketLoss = math.Round(
			(float64(qdisc.Netem.Qopt.Loss)/float64(math.MaxUint32)*100)*100) / 100 //nolint: mnd
	}

	return data
}

// GenerateTopologyOptions contains options for generating a topology.
type GenerateTopologyOptions struct {
	Name              string
	Tiers             []TierDefinition
	DefaultKind       string
	Images            map[string]string
	Licenses          map[string]string
	NodePrefix        string
	GroupPrefix       string
	ManagementNetwork string
	IPv4Subnet        string
	IPv6Subnet        string
}

// TierDefinition defines a tier in the topology.
type TierDefinition struct {
	Count int
	Kind  string
	Type  string
}

// GenerateTopology generates a topology YAML.
func (s *Service) GenerateTopology(ctx context.Context, opts GenerateTopologyOptions) ([]byte, error) {
	_, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Build nodes definitions
	nodeDefs := make([]nodesDef, len(opts.Tiers))
	for i, tier := range opts.Tiers {
		kind := tier.Kind
		if kind == "" {
			kind = opts.DefaultKind
			if kind == "" {
				kind = "srl"
			}
		}
		nodeDefs[i] = nodesDef{
			numNodes: uint(tier.Count),
			kind:     kind,
			typ:      tier.Type,
		}
	}

	// Get node registry
	clab := &clabcore.CLab{}
	clab.Reg = clabnodes.NewNodeRegistry()
	clab.RegisterNodes()

	// Set default prefixes
	nodePrefix := opts.NodePrefix
	if nodePrefix == "" {
		nodePrefix = "node"
	}
	groupPrefix := opts.GroupPrefix
	if groupPrefix == "" {
		groupPrefix = "tier"
	}

	log.Info("Generating topology",
		"name", opts.Name,
		"tiers", len(opts.Tiers),
	)

	// Generate the topology configuration
	b, err := s.generateTopologyConfig(
		opts.Name,
		opts.ManagementNetwork,
		opts.IPv4Subnet,
		opts.IPv6Subnet,
		opts.Images,
		opts.Licenses,
		clab.Reg,
		nodePrefix,
		groupPrefix,
		nodeDefs...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate topology: %w", err)
	}

	return b, nil
}

// nodesDef is used internally for topology generation.
type nodesDef struct {
	numNodes uint
	kind     string
	typ      string
}

// generateTopologyConfig generates the topology YAML configuration.
func (s *Service) generateTopologyConfig(
	name, network, ipv4range, ipv6range string,
	images, licenses map[string]string,
	reg *clabnodes.NodeRegistry,
	nodePrefix, groupPrefix string,
	nodes ...nodesDef,
) ([]byte, error) {
	numStages := len(nodes)
	config := &clabcore.Config{
		Name: name,
		Mgmt: new(clabtypes.MgmtNet),
		Topology: &clabtypes.Topology{
			Kinds: make(map[string]*clabtypes.NodeDefinition),
			Nodes: make(map[string]*clabtypes.NodeDefinition),
		},
	}

	config.Mgmt.Network = network

	if ipv4range != "" && ipv4range != "<nil>" {
		config.Mgmt.IPv4Subnet = ipv4range
	}

	if ipv6range != "" && ipv6range != "<nil>" {
		config.Mgmt.IPv6Subnet = ipv6range
	}

	for k, img := range images {
		config.Topology.Kinds[k] = &clabtypes.NodeDefinition{Image: img}
	}

	for k, lic := range licenses {
		if knd, ok := config.Topology.Kinds[k]; ok {
			knd.License = lic
			config.Topology.Kinds[k] = knd
			continue
		}
		config.Topology.Kinds[k] = &clabtypes.NodeDefinition{License: lic}
	}

	if numStages == 1 {
		for j := range nodes[0].numNodes {
			node1 := fmt.Sprintf("%s1-%d", nodePrefix, j+1)
			if _, ok := config.Topology.Nodes[node1]; !ok {
				config.Topology.Nodes[node1] = &clabtypes.NodeDefinition{
					Group: fmt.Sprintf("%s-1", groupPrefix),
					Kind:  nodes[0].kind,
					Type:  nodes[0].typ,
				}
			}
		}
	}

	generateNodesAttributes := reg.GetGenerateNodeAttributes()

	for i := range numStages - 1 {
		interfaceOffset := uint(0)
		if i > 0 {
			interfaceOffset = nodes[i-1].numNodes
		}

		for j := range nodes[i].numNodes {
			node1 := fmt.Sprintf("%s%d-%d", nodePrefix, i+1, j+1)
			if _, ok := config.Topology.Nodes[node1]; !ok {
				config.Topology.Nodes[node1] = &clabtypes.NodeDefinition{
					Group: fmt.Sprintf("%s-%d", groupPrefix, i+1),
					Kind:  nodes[i].kind,
					Type:  nodes[i].typ,
				}
			}

			for k := range nodes[i+1].numNodes {
				node2 := fmt.Sprintf("%s%d-%d", nodePrefix, i+2, k+1)
				if _, ok := config.Topology.Nodes[node2]; !ok {
					config.Topology.Nodes[node2] = &clabtypes.NodeDefinition{
						Group: fmt.Sprintf("%s-%d", groupPrefix, i+2),
						Kind:  nodes[i+1].kind,
						Type:  nodes[i+1].typ,
					}
				}

				// Create a raw veth link
				l := &clablinks.LinkVEthRaw{
					Endpoints: []*clablinks.EndpointRaw{
						clablinks.NewEndpointRaw(node1, fmt.Sprintf(
							generateNodesAttributes[nodes[i].kind].GetInterfaceFormat(),
							k+1+interfaceOffset,
						), ""),
						clablinks.NewEndpointRaw(node2, fmt.Sprintf(
							generateNodesAttributes[nodes[i+1].kind].GetInterfaceFormat(),
							j+1,
						), ""),
					},
				}

				ld := &clablinks.LinkDefinition{
					Link: l.ToLinkBriefRaw(),
				}

				config.Topology.Links = append(config.Topology.Links, ld)
			}
		}
	}

	return yaml.Marshal(config)
}

// prepareWorkDir prepares the working directory for a user.
func (s *Service) prepareWorkDir(username string) (string, error) {
	storage, err := workspacestore.ResolveUserStorage(username)
	if err != nil {
		return "", fmt.Errorf("failed to resolve user workspace: %w", err)
	}

	if err := workspacestore.EnsureUserStorage(storage); err != nil {
		return "", fmt.Errorf("failed to prepare containerlab workspace: %w", err)
	}

	return storage.BaseDir, nil
}

// ensureTimeout ensures the context has a timeout.
func (s *Service) ensureTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		return context.WithTimeout(ctx, defaultTimeout)
	}
	return ctx, func() {}
}

// processGitTopoFile handles GitHub/GitLab URLs by cloning the repo and returning
// the local path to the topology file. This mirrors the CLI behavior.
func (s *Service) processGitTopoFile(topo, workDir string) (string, error) {
	// For short github urls, prepend https://github.com
	if clabgit.IsGitHubShortURL(topo) {
		topo = "https://github.com/" + topo
	}

	repo, err := clabgit.NewRepo(topo)
	if err != nil {
		return "", fmt.Errorf("failed to parse git URL: %w", err)
	}

	// Instantiate the git implementation
	gitImpl := clabgit.NewGoGit(repo)

	// Clone the repo
	log.Debug("Cloning git repository", "url", topo, "workDir", workDir)
	if err := withContainerlabProcessState(workDir, "", func() error {
		if cloneErr := gitImpl.Clone(); cloneErr != nil {
			return cloneErr
		}

		// SetUIDAndGID currently accepts a relative path and therefore belongs in
		// the same protected working-directory section as Clone.
		if ownershipErr := clabutils.SetUIDAndGID(repo.GetName()); ownershipErr != nil {
			log.Warn("Error adjusting repository permissions, continuing anyways", "error", ownershipErr)
		}
		return nil
	}); err != nil {
		return "", fmt.Errorf("failed to clone git repository: %w", err)
	}

	// Find the topology file in the cloned repo
	repoPath := filepath.Join(workDir, repo.GetName())

	// If a specific path was provided in the URL, use it
	if len(repo.GetPath()) > 0 {
		repoPath = filepath.Join(repoPath, filepath.Join(repo.GetPath()...))
	}

	// If a specific filename was provided, use it
	if repo.GetFilename() != "" {
		topoFile := filepath.Join(repoPath, repo.GetFilename())
		if _, err := os.Stat(topoFile); err != nil {
			return "", fmt.Errorf("specified topology file not found: %s", topoFile)
		}
		return topoFile, nil
	}

	// Otherwise, find a .clab.yml file in the repo
	topoFile, err := clabcore.FindTopoFileByPath(repoPath)
	if err != nil {
		return "", fmt.Errorf("failed to find topology file in cloned repo: %w", err)
	}

	return topoFile, nil
}

func (s *Service) runCommand(ctx context.Context, name string, args []string) (string, error) {
	var output []byte
	err := withContainerlabProcessState("", "", func() error {
		cmd := exec.CommandContext(ctx, name, args...)
		var commandErr error
		output, commandErr = cmd.CombinedOutput()
		return commandErr
	})
	trimmed := strings.TrimSpace(string(output))
	if err != nil {
		if trimmed == "" {
			return "", fmt.Errorf("command %s %s failed: %w", name, strings.Join(args, " "), err)
		}
		return trimmed, fmt.Errorf(
			"command %s %s failed: %w: %s",
			name,
			strings.Join(args, " "),
			err,
			trimmed,
		)
	}

	return trimmed, nil
}

func drawioOutputPathFromTopo(topoPath string) string {
	lowerPath := strings.ToLower(topoPath)
	switch {
	case strings.HasSuffix(lowerPath, ".yaml"):
		return topoPath[:len(topoPath)-len(".yaml")] + ".drawio"
	case strings.HasSuffix(lowerPath, ".yml"):
		return topoPath[:len(topoPath)-len(".yml")] + ".drawio"
	default:
		return topoPath + ".drawio"
	}
}

// isGitURL checks if the given path is a GitHub or GitLab URL that needs to be cloned.
func (s *Service) isGitURL(path string) bool {
	return clabgit.IsGitHubOrGitLabURL(path) || clabgit.IsGitHubShortURL(path)
}

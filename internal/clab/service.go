// internal/clab/service.go
package clab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
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
)

const (
	defaultTimeout         = 5 * time.Minute
	gracefulDestroyTimeout = 2 * time.Minute
	imagePullTimeout       = 30 * time.Minute
)

var ErrNetemInterfaceNotFound = errors.New("netem interface not found")

// ErrNetemNodeNotFound is returned when a netem target node is not part of the lab topology.
var ErrNetemNodeNotFound = errors.New("netem node not found")

// ErrMgmtOverrideUnsupported is returned when management network overrides are
// requested for a topology that defines several management networks.
var ErrMgmtOverrideUnsupported = errors.New("management network overrides cannot be used with multiple management networks")

// Service provides an interface to containerlab operations using the library directly.
type Service struct {
	// scoper places lab runtime calls in namespaces and identities; nil uses the
	// server's own credentials.
	scoper LabScoper
}

// NewService creates a new containerlab service.
func NewService() *Service {
	return &Service{}
}

// containerlabMu protects containerlab's process-wide owner environment, working
// directory and special link nodes. Stateful operations hold it from construction
// through completion; constructors used by read-only requests take the same lock.
var containerlabMu sync.Mutex

// lockContainerlabOperation gives one operation exclusive use of the host and
// mgmt-net pseudo nodes. Clear stale endpoints before link resolution and release
// references afterwards, including when an operation fails. This only forgets
// endpoint objects; it does not remove interfaces belonging to running labs.
func lockContainerlabOperation() func() {
	containerlabMu.Lock()
	drainSpecialLinkNodes()
	return func() {
		drainSpecialLinkNodes()
		containerlabMu.Unlock()
	}
}

// drainSpecialLinkNodes restores the state a fresh containerlab CLI process sees.
// Callers must hold containerlabMu while draining and using these shared nodes.
func drainSpecialLinkNodes() {
	for _, n := range []clablinks.Node{clablinks.GetHostLinkNode(), clablinks.GetMgmtBrLinkNode()} {
		if n == nil {
			continue
		}
		// Copy first: ReleaseEndpoint changes the slice we would be ranging over.
		for _, ep := range append([]clablinks.Endpoint(nil), n.GetEndpoints()...) {
			_ = n.ReleaseEndpoint(ep)
		}
	}
	// Containerlab renames this singleton to the management bridge. Leaving that
	// name behind can shadow a topology's bridge node during the next resolution.
	_ = clablinks.SetMgmtNetUnderlyingBridge("mgmt-net")
}

func newContainerLab(opts ...clabcore.ClabOption) (*clabcore.CLab, error) {
	containerlabMu.Lock()
	defer containerlabMu.Unlock()

	return clabcore.NewContainerLab(opts...)
}

func newContainerLabForOwner(owner string, opts ...clabcore.ClabOption) (*clabcore.CLab, error) {
	containerlabMu.Lock()
	defer containerlabMu.Unlock()

	restoreOwnerEnv := setProcessOwnerEnv(owner)
	defer restoreOwnerEnv()

	return clabcore.NewContainerLab(opts...)
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

func (n *rootLinkNode) AdoptEndpoint(e clablinks.Endpoint) error {
	if e == nil {
		return fmt.Errorf("node %q cannot adopt a nil endpoint", n.shortName)
	}

	owner := e.GetNode()
	if owner == nil {
		return fmt.Errorf(
			"node %q cannot adopt endpoint %q without an owner",
			n.shortName,
			e.GetIfaceName(),
		)
	}
	if owner.GetShortName() != n.shortName {
		return fmt.Errorf(
			"node %q cannot adopt endpoint %q owned by %q",
			n.shortName,
			e.GetIfaceName(),
			owner.GetShortName(),
		)
	}

	for _, owned := range n.endpoints {
		if owned == e {
			return nil
		}
		if owned.GetIfaceName() == e.GetIfaceName() {
			return fmt.Errorf(
				"node %q already tracks interface %q",
				n.shortName,
				e.GetIfaceName(),
			)
		}
	}

	n.endpoints = append(n.endpoints, e)
	return nil
}

func (n *rootLinkNode) ReleaseEndpoint(e clablinks.Endpoint) error {
	for i, owned := range n.endpoints {
		if owned != e {
			continue
		}

		n.endpoints = append(n.endpoints[:i], n.endpoints[i+1:]...)
		return nil
	}

	return fmt.Errorf("node %q does not own endpoint %q", n.shortName, e.GetIfaceName())
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
	TopoPath string
	// LabName is the API-authorized lab name. It is required and overrides the
	// name from the topology so deployment cannot switch to an unchecked lab.
	LabName  string
	Username string
	// Actor is the user who asked for the deploy, when it is not Username (the lab
	// owner), e.g. a member redeploying a shared lab. Lab runtime calls act as the actor.
	Actor          string
	Reconfigure    bool
	MaxWorkers     uint
	ExportTemplate string
	NodeFilter     []string
	SkipPostDeploy bool
	SkipLabDirACLs bool
	// MgmtNetwork, MgmtIPv4Subnet and MgmtIPv6Subnet override the topology's
	// management network like the --network, --ipv4-subnet and --ipv6-subnet flags.
	MgmtNetwork    string
	MgmtIPv4Subnet string
	MgmtIPv6Subnet string
	// VarsFiles are template variable files like --vars. When empty, containerlab
	// discovers <topology>_vars.{yaml,yml,json} next to the topology.
	VarsFiles []string
	// RestoreNodeSnapshots lists "node=/absolute/snapshot.tar" entries like the
	// --restore deploy flag. Paths must come from StageRestoreSnapshots so the
	// mounted files live in the server-owned staging directory.
	RestoreNodeSnapshots []string
}

// ApplyOptions contains options for applying topology changes to a lab.
type ApplyOptions struct {
	TopoPath string
	// LabName is the API-authorized lab name.
	LabName  string
	Username string
	// Actor is the user who asked for the apply, when it is not Username (the lab owner).
	Actor          string
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
	// VarsFiles are template variable files like --vars, used to render the
	// topology the lab was deployed from.
	VarsFiles []string
}

// ListOptions contains options for listing labs/containers.
type ListOptions struct {
	// Username is the user the listing is for. Lab runtimes list only the labs this user
	// can access, and act as this user.
	Username      string
	LabName       string
	ContainerName string
	NodeName      string
	// IncludeInternal also returns helper containers containerlab creates for a
	// node (e.g. the SR-SIM netns holder), which `clab inspect` hides by default.
	IncludeInternal bool
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
	TopoPath string
	// LabName is the API-authorized lab name.
	LabName    string
	Username   string
	NodeFilter []string
	// CopyOut, when set, copies saved configs like `containerlab save --copy`.
	CopyOut *OutputDir
}

type nodeConfigSaver interface {
	GetShortName() string
	SaveConfig(context.Context) (*clabnodes.SaveConfigResult, error)
}

// InspectOptions contains options for inspecting labs.
type InspectOptions struct {
	LabName  string
	Username string
	// Details returns the raw runtime container objects, like `containerlab inspect --details`.
	Details bool
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
	TopologyPath string
	CommandArgs  []string
}

type CloneTopologySourceOptions struct {
	SourceURL string
	Username  string
	// WorkDir is the clone's parent directory. Empty uses the user's lab directory.
	// Callers supplying a temporary directory are responsible for its cleanup.
	WorkDir string
}

type CloneTopologySourceResult struct {
	RepoDir      string
	RepoName     string
	TopologyPath string
}

type ResolveTopologySourceOptions struct {
	SourcePath string
	Username   string
}

type ResolveTopologySourceResult struct {
	TopologyPath string
	LabName      string
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

	workDir := opts.WorkDir
	if workDir == "" {
		var err error
		workDir, err = s.prepareWorkDir(opts.Username)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare working directory: %w", err)
		}
	}
	workDir, err := filepath.Abs(workDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve working directory: %w", err)
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

	repoDir := filepath.Join(workDir, repo.GetName())

	// The clone runs as root, so hand it over or the user cannot edit or remove it.
	if uid, gid, idErr := lookupUserIDs(opts.Username); idErr != nil {
		log.Warn("Failed to resolve user for cloned topology ownership",
			"user", opts.Username,
			"error", idErr,
		)
	} else if chownErr := chownTree(repoDir, uid, gid); chownErr != nil {
		log.Warn("Failed to set ownership on cloned topology",
			"dir", repoDir,
			"user", opts.Username,
			"error", chownErr,
		)
	}

	return &CloneTopologySourceResult{
		RepoDir:      repoDir,
		RepoName:     repo.GetName(),
		TopologyPath: topoPath,
	}, nil
}

// ResolveTopologySource materializes a topology source and returns its effective lab name after
// template, environment, and git-variable expansion.
func (s *Service) ResolveTopologySource(
	opts ResolveTopologySourceOptions,
) (*ResolveTopologySourceResult, error) {
	sourcePath := strings.TrimSpace(opts.SourcePath)
	if sourcePath == "" {
		return nil, fmt.Errorf("topology source is required")
	}
	if strings.TrimSpace(opts.Username) == "" {
		return nil, fmt.Errorf("username is required")
	}

	topologyPath := sourcePath
	if s.isGitURL(sourcePath) {
		cloned, err := s.CloneTopologySource(CloneTopologySourceOptions{
			SourceURL: sourcePath,
			Username:  opts.Username,
		})
		if err != nil {
			return nil, err
		}
		topologyPath = cloned.TopologyPath
	}

	clab, err := newContainerLabForOwner(
		opts.Username,
		runtimeOption(defaultTimeout),
		clabcore.WithTopoPath(topologyPath, nil),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load topology: %w", err)
	}

	labName := strings.TrimSpace(clab.Config.Name)
	if labName == "" {
		return nil, fmt.Errorf("topology name is required")
	}

	return &ResolveTopologySourceResult{
		TopologyPath: clab.TopoPaths.TopologyFilenameAbsPath(),
		LabName:      labName,
	}, nil
}

func deployClabOptions(topoPath, labName string, opts DeployOptions, scope *LabScope) []clabcore.ClabOption {
	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithTopoPath(topoPath, opts.VarsFiles),
		clabcore.WithTopologyName(labName),
	}
	clabOpts = append(clabOpts, runtimeOptions(scope, defaultTimeout)...)
	if scope != nil && scope.Owner != "" {
		clabOpts = append(clabOpts, clabcore.WithLabOwner(scope.Owner))
	}

	if len(opts.NodeFilter) > 0 {
		clabOpts = append(clabOpts, clabcore.WithNodeFilter(opts.NodeFilter))
	}

	return append(clabOpts, mgmtOverrideOptions(opts)...)
}

// mgmtOverrideOptions mirrors the --network, --ipv4-subnet and --ipv6-subnet deploy flags.
func mgmtOverrideOptions(opts DeployOptions) []clabcore.ClabOption {
	var clabOpts []clabcore.ClabOption
	if opts.MgmtNetwork != "" {
		clabOpts = append(clabOpts, clabcore.WithManagementNetworkName(opts.MgmtNetwork))
	}
	if opts.MgmtIPv4Subnet != "" {
		clabOpts = append(clabOpts, clabcore.WithManagementIpv4Subnet(opts.MgmtIPv4Subnet))
	}
	if opts.MgmtIPv6Subnet != "" {
		clabOpts = append(clabOpts, clabcore.WithManagementIpv6Subnet(opts.MgmtIPv6Subnet))
	}
	return clabOpts
}

// wrapMgmtOverrideError maps containerlab's rejection of management network
// overrides to ErrMgmtOverrideUnsupported so handlers can report a client error.
func wrapMgmtOverrideError(err error) error {
	if err != nil && strings.Contains(err.Error(), "management network flags cannot be used") {
		return fmt.Errorf("%w: %v", ErrMgmtOverrideUnsupported, err)
	}
	return err
}

// openDeployLab prepares the process state a deploy runs in (owner env, work
// directory, containerlab lock) and loads the topology with the deploy options.
// The returned release function must be called once the instance is no longer used.
func (s *Service) openDeployLab(opts DeployOptions, scope *LabScope) (*clabcore.CLab, func(), error) {
	labName := strings.TrimSpace(opts.LabName)
	if labName == "" {
		return nil, nil, fmt.Errorf("authorized lab name is required")
	}

	// Prepare clab working directory
	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare working directory: %w", err)
	}

	// Handle GitHub/GitLab URLs by cloning the repo first
	topoPath := opts.TopoPath
	if s.isGitURL(topoPath) {
		log.Debug("Detected git URL, cloning repository", "url", topoPath)
		var gitErr error
		topoPath, gitErr = s.processGitTopoFile(topoPath, workDir)
		if gitErr != nil {
			return nil, nil, fmt.Errorf("failed to process git URL: %w", gitErr)
		}
		log.Debug("Using cloned topology file", "path", topoPath)
	}

	// Change to the work directory for relative path resolution
	unlock := lockContainerlabOperation()
	restoreOwnerEnv := setProcessOwnerEnv(opts.Username)

	originalDir, _ := os.Getwd()
	if chErr := os.Chdir(workDir); chErr != nil {
		restoreOwnerEnv()
		unlock()
		return nil, nil, fmt.Errorf("failed to change to work directory: %w", chErr)
	}
	release := func() {
		if restoreErr := os.Chdir(originalDir); restoreErr != nil {
			log.Warn("Failed to restore working directory", "error", restoreErr)
		}
		restoreOwnerEnv()
		unlock()
	}

	log.Debug("Creating containerlab instance",
		"topoPath", opts.TopoPath,
		"username", opts.Username,
		"runtime", config.AppConfig.ClabRuntime,
	)

	clab, err := clabcore.NewContainerLab(deployClabOptions(topoPath, labName, opts, scope)...)
	if err != nil {
		release()
		return nil, nil, fmt.Errorf("failed to create containerlab instance: %w", wrapMgmtOverrideError(err))
	}

	return clab, release, nil
}

// ValidateDeploy loads the topology with the given deploy options without
// changing any lab state, so callers can reject invalid options before a
// destructive step such as the destroy phase of a redeploy.
func (s *Service) ValidateDeploy(opts DeployOptions) error {
	if IsLabRuntime() {
		if err := validateLabRuntimeDeployOptions(opts); err != nil {
			return err
		}
	}
	_, release, err := s.openDeployLab(opts, nil)
	if err != nil {
		return err
	}
	release()
	return nil
}

// Deploy deploys a lab using the containerlab library.
func (s *Service) Deploy(ctx context.Context, opts DeployOptions) ([]clabruntime.GenericContainer, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	var scope *LabScope
	if IsLabRuntime() {
		if err := validateLabRuntimeDeployOptions(opts); err != nil {
			return nil, err
		}
		prepared, err := s.labScoper().PrepareDeploy(ctx, actorOf(opts.Actor, opts.Username), strings.TrimSpace(opts.LabName), opts.TopoPath)
		if err != nil {
			return nil, err
		}
		scope = &prepared
	}

	clab, release, err := s.openDeployLab(opts, scope)
	if err != nil {
		return nil, err
	}
	defer release()

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
	if len(opts.RestoreNodeSnapshots) > 0 {
		deployOpts.SetRestoreNodeSnapshots(opts.RestoreNodeSnapshots)
	}
	labRuntimeDeployOptions(deployOpts)

	log.Info("Deploying lab",
		"username", opts.Username,
		"topoPath", opts.TopoPath,
		"reconfigure", opts.Reconfigure,
	)

	deployResult, err := clab.Deploy(ctx, deployOpts)
	var containers []clabruntime.GenericContainer
	if deployResult != nil {
		containers = withoutInternalContainers(deployResult.Containers)
	}
	if err != nil {
		return nil, fmt.Errorf("deployment failed: %w", err)
	}
	if clab.LabRuntime == nil {
		if err := syncLabHostsFiles(ctx, clab); err != nil {
			return nil, fmt.Errorf("deployment completed but host name resolution setup failed: %w", err)
		}
	}

	log.Info("Lab deployed successfully",
		"username", opts.Username,
		"containerCount", len(containers),
	)

	return containers, nil
}

// Apply applies topology changes to a lab using the containerlab library.
func (s *Service) Apply(ctx context.Context, opts ApplyOptions) (*ApplyOutcome, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	if strings.TrimSpace(opts.TopoPath) == "" {
		return nil, fmt.Errorf("topology path is required")
	}
	if IsLabRuntime() {
		return s.applyWithLabRuntime(ctx, opts)
	}

	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare working directory: %w", err)
	}

	unlock := lockContainerlabOperation()
	defer unlock()

	restoreOwnerEnv := setProcessOwnerEnv(opts.Username)
	defer restoreOwnerEnv()

	originalDir, _ := os.Getwd()
	if chErr := os.Chdir(workDir); chErr != nil {
		return nil, fmt.Errorf("failed to change to work directory: %w", chErr)
	}
	defer func() {
		if restoreErr := os.Chdir(originalDir); restoreErr != nil {
			log.Warn("Failed to restore working directory", "error", restoreErr)
		}
	}()

	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithTopoPath(opts.TopoPath, nil),
	}
	clabOpts = append(clabOpts, runtimeOptions(nil, defaultTimeout)...)

	log.Debug("Creating containerlab instance for apply",
		"topoPath", opts.TopoPath,
		"username", opts.Username,
		"runtime", config.AppConfig.ClabRuntime,
	)

	clab, err := clabcore.NewContainerLab(clabOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create containerlab instance: %w", err)
	}

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

	result, err := clab.Apply(ctx, applyOpts)
	if err != nil {
		return nil, fmt.Errorf("apply failed: %w", err)
	}
	if result != nil && strings.TrimSpace(result.LabName) == "" {
		result.LabName = clab.Config.Name
	}
	if !opts.DryRun {
		if err := syncLabHostsFiles(ctx, clab); err != nil {
			return nil, fmt.Errorf("apply completed but host name resolution setup failed: %w", err)
		}
	}

	return &ApplyOutcome{ApplyResult: result}, nil
}

// ErrInvalidTopology marks a topology that containerlab rejected during validation.
var ErrInvalidTopology = errors.New("invalid topology")

// ValidateOptions contains options for validating a topology file.
type ValidateOptions struct {
	TopoPath string
	Username string
}

// ValidateResult describes a topology that passed validation.
type ValidateResult struct {
	LabName string
	Nodes   int
	Links   int
}

// Validate parses and validates a topology the same way `containerlab validate`
// does, without touching runtime state. Topology errors are wrapped in
// ErrInvalidTopology.
func (s *Service) Validate(ctx context.Context, opts ValidateOptions) (*ValidateResult, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	if strings.TrimSpace(opts.TopoPath) == "" {
		return nil, fmt.Errorf("topology path is required")
	}

	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare working directory: %w", err)
	}

	unlock := lockContainerlabOperation()
	defer unlock()

	restoreOwnerEnv := setProcessOwnerEnv(opts.Username)
	defer restoreOwnerEnv()

	originalDir, _ := os.Getwd()
	if chErr := os.Chdir(workDir); chErr != nil {
		return nil, fmt.Errorf("failed to change to work directory: %w", chErr)
	}
	defer func() {
		if restoreErr := os.Chdir(originalDir); restoreErr != nil {
			log.Warn("Failed to restore working directory", "error", restoreErr)
		}
	}()

	clab, err := clabcore.NewContainerLab(append([]clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithTopoPath(opts.TopoPath, nil),
	}, runtimeOptions(nil, defaultTimeout)...)...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTopology, err)
	}

	result := &ValidateResult{LabName: clab.Config.Name}

	// Lab runtimes do not instantiate native nodes; their own compiler validates the topology.
	if clab.LabRuntime != nil && clab.Config.Name != "" {
		if err := clab.ValidateLabRuntimeTopology(ctx); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidTopology, err)
		}
		result.Nodes = len(clab.Config.Topology.Nodes)
		result.Links = len(clab.Config.Topology.Links)
		return result, nil
	}

	if clab.Config.Name == "" || len(clab.Nodes) == 0 {
		return nil, fmt.Errorf("%w: topology file %q defines no name or nodes", ErrInvalidTopology,
			clab.TopoPaths.TopologyFilenameBase())
	}

	if err := clab.ResolveLinks(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTopology, err)
	}

	result.Nodes = len(clab.Nodes)
	result.Links = len(clab.Links)
	return result, nil
}

// Destroy destroys a lab using the containerlab library.
func (s *Service) Destroy(ctx context.Context, opts DestroyOptions) error {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	if IsLabRuntime() {
		return s.destroyWithLabRuntime(ctx, opts)
	}

	// Prepare clab working directory
	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return fmt.Errorf("failed to prepare working directory: %w", err)
	}

	unlock := lockContainerlabOperation()
	defer unlock()

	originalDir, _ := os.Getwd()
	if chErr := os.Chdir(workDir); chErr != nil {
		return fmt.Errorf("failed to change to work directory: %w", chErr)
	}
	defer func() {
		if restoreErr := os.Chdir(originalDir); restoreErr != nil {
			log.Warn("Failed to restore working directory", "error", restoreErr)
		}
	}()

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
		clabOpts = append(clabOpts, clabcore.WithTopoPath(opts.TopoPath, opts.VarsFiles))
	} else if opts.LabName != "" {
		clabOpts = append(clabOpts, clabcore.WithTopologyFromLab(opts.LabName, opts.VarsFiles))
	} else {
		return fmt.Errorf("either lab name or topology path is required")
	}

	clabOpts = append(clabOpts, runtimeOptions(nil, clabTimeout)...)

	if opts.KeepMgmtNet {
		clabOpts = append(clabOpts, clabcore.WithKeepMgmtNet())
	}

	log.Debug("Creating containerlab instance for destroy",
		"labName", opts.LabName,
		"topoPath", opts.TopoPath,
		"username", opts.Username,
	)

	clab, err := clabcore.NewContainerLab(clabOpts...)
	if err != nil {
		return fmt.Errorf("failed to create containerlab instance: %w", err)
	}

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

	if len(opts.VarsFiles) > 0 {
		destroyOpts = append(destroyOpts, clabcore.WithDestroyVarsFiles(opts.VarsFiles))
	}

	log.Info("Destroying lab",
		"username", opts.Username,
		"labName", opts.LabName,
		"graceful", opts.Graceful,
		"gracefulTimeout", opts.GracefulTimeout,
		"cleanup", opts.Cleanup,
	)

	// Destroy the lab
	if err := clab.Destroy(ctx, destroyOpts...); err != nil {
		return fmt.Errorf("destroy failed: %w", err)
	}
	stagedLabName := opts.LabName
	if stagedLabName == "" {
		stagedLabName = clab.Config.Name
	}
	removeStagedRestoreSnapshots(stagedLabName, opts.NodeFilter)
	if err := removeLabHostsFiles(clab.Config.Name); err != nil {
		return fmt.Errorf("lab destroyed but host name resolution cleanup failed: %w", err)
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

	if IsLabRuntime() {
		return s.listLabRuntimeContainers(ctx, opts)
	}

	// Create a minimal clab instance for listing (no topology needed)
	clabOpts := append([]clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
	}, runtimeOptions(nil, defaultTimeout)...)

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
	if !opts.IncludeInternal {
		containers = withoutInternalContainers(containers)
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
		if err := RequireContainerRuntime("pausing nodes"); err != nil {
			return err
		}
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
	if IsLabRuntime() {
		return s.labRuntimeNodeLifecycle(ctx, opts)
	}

	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return fmt.Errorf("failed to prepare working directory: %w", err)
	}

	unlock := lockContainerlabOperation()
	defer unlock()

	originalDir, _ := os.Getwd()
	if chErr := os.Chdir(workDir); chErr != nil {
		return fmt.Errorf("failed to change to work directory: %w", chErr)
	}
	defer func() {
		if restoreErr := os.Chdir(originalDir); restoreErr != nil {
			log.Warn("Failed to restore working directory", "error", restoreErr)
		}
	}()

	clabOpts := append([]clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
	}, runtimeOptions(nil, defaultTimeout)...)

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

	clab, err := clabcore.NewContainerLab(clabOpts...)
	if err != nil {
		return fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	nodeNames := cleanNodeNames(opts.NodeNames)
	log.Info("Running topology lifecycle action",
		"username", opts.Username,
		"labName", opts.LabName,
		"topoPath", opts.TopoPath,
		"action", opts.Action,
		"nodes", nodeNames,
	)

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
	if err := RequireContainerRuntime("containerlab tools"); err != nil {
		return "", err
	}
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
	if err := RequireContainerRuntime("image management"); err != nil {
		return nil, err
	}
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
	if err := RequireContainerRuntime("image management"); err != nil {
		return "", err
	}
	baseCtx := ctx
	if _, hasDeadline := baseCtx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		baseCtx, cancel = context.WithTimeout(baseCtx, imagePullTimeout)
		defer cancel()
	}
	return s.runCommand(baseCtx, configuredRuntimeName(), []string{"pull", image})
}

func (s *Service) RemoveRuntimeImage(ctx context.Context, reference string, force bool) (string, error) {
	if err := RequireContainerRuntime("image management"); err != nil {
		return "", err
	}
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
	if err := RequireContainerRuntime("fcli"); err != nil {
		return "", err
	}
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

	networkArgs, err := s.fcliNetworkArgs(ctx, topologyPath)
	if err != nil {
		return "", err
	}

	args := []string{
		"run",
		"--pull", "always",
		"--rm",
	}
	args = append(args, networkArgs...)
	args = append(args,
		"-v", "/etc/hosts:/etc/hosts:ro",
		"-v", fmt.Sprintf("%s:/topo.yml", topologyPath),
		"ghcr.io/srl-labs/nornir-srl:latest",
		"-t", "/topo.yml",
	)
	args = append(args, opts.CommandArgs...)

	return s.runCommand(ctx, runtimeName, args)
}

// fcliNetworkArgs attaches the fcli container to the lab's default management
// network. Unless the network uses runtime IPAM, containerlab allocates the
// container address, as it does for its own tool containers, so the address
// cannot clash with addresses containerlab assigns to lab nodes.
func (s *Service) fcliNetworkArgs(ctx context.Context, topologyPath string) ([]string, error) {
	lab, err := newContainerLab(
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithTopoPath(topologyPath, nil),
		runtimeOption(defaultTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load topology: %w", err)
	}

	network := lab.Config.Mgmt.Network
	cfg := &clabtypes.NodeConfig{ShortName: "fcli", LongName: "fcli", MgmtNet: network}
	if err := lab.AllocateToolManagementIPs(ctx, cfg); err != nil {
		return nil, fmt.Errorf("failed to allocate fcli management address: %w", err)
	}

	args := []string{"--network", network}
	if cfg.MgmtIPv4Address != "" {
		args = append(args, "--ip", cfg.MgmtIPv4Address)
	}
	if cfg.MgmtIPv6Address != "" {
		args = append(args, "--ip6", cfg.MgmtIPv6Address)
	}
	return args, nil
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

// Text graph formats produced by GenerateGraphExport.
const (
	GraphFormatMermaid = "mermaid"
	GraphFormatDot     = "dot"
)

// GraphExportOptions contains options for exporting a topology as a text graph.
type GraphExportOptions struct {
	TopoPath string
	Username string
	// Format is GraphFormatMermaid or GraphFormatDot.
	Format string
	// Direction is the mermaid flowchart direction (mermaid only).
	Direction string
}

// GraphExportResult describes a generated text graph file.
type GraphExportResult struct {
	Path    string
	Content string
}

// GenerateGraphExport writes a mermaid or dot graph of a topology the same way
// `containerlab graph --mermaid|--dot` does and returns the generated file.
// Topology errors are wrapped in ErrInvalidTopology.
func (s *Service) GenerateGraphExport(ctx context.Context, opts GraphExportOptions) (*GraphExportResult, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	if strings.TrimSpace(opts.TopoPath) == "" {
		return nil, fmt.Errorf("topology path is required")
	}

	var ext string
	switch opts.Format {
	case GraphFormatMermaid:
		ext = ".mermaid"
	case GraphFormatDot:
		ext = ".dot"
	default:
		return nil, fmt.Errorf("unsupported graph format: %q", opts.Format)
	}

	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare working directory: %w", err)
	}

	unlock := lockContainerlabOperation()
	defer unlock()

	restoreOwnerEnv := setProcessOwnerEnv(opts.Username)
	defer restoreOwnerEnv()

	originalDir, _ := os.Getwd()
	if chErr := os.Chdir(workDir); chErr != nil {
		return nil, fmt.Errorf("failed to change to work directory: %w", chErr)
	}
	defer func() {
		if restoreErr := os.Chdir(originalDir); restoreErr != nil {
			log.Warn("Failed to restore working directory", "error", restoreErr)
		}
	}()

	clab, err := clabcore.NewContainerLab(
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithTopoPath(opts.TopoPath, nil),
		runtimeOption(defaultTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTopology, err)
	}

	// Lab runtimes do not build the topology's nodes; graphs render from the topology file.
	if clab.LabRuntime != nil {
		if err := clab.LoadTopologyNodes(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidTopology, err)
		}
	}

	if err := clab.ResolveLinks(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTopology, err)
	}

	// Containerlab creates the lab and graph directories as the server user;
	// hand any directory it creates here over to the lab owner afterwards.
	labDir := clab.TopoPaths.TopologyLabDir()
	_, labDirErr := os.Stat(labDir)
	labDirExisted := labDirErr == nil
	defer chownGraphOutput(opts.Username, labDir, labDirExisted, clab.TopoPaths.GraphDir())

	switch opts.Format {
	case GraphFormatMermaid:
		direction := opts.Direction
		if direction == "" {
			direction = "TD"
		}
		err = clab.GenerateMermaidGraph(direction)
	default:
		err = clab.GenerateDotGraph(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s graph: %w", opts.Format, err)
	}

	graphPath := clab.TopoPaths.GraphFilename(ext)
	content, err := os.ReadFile(graphPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read generated %s graph: %w", opts.Format, err)
	}

	return &GraphExportResult{
		Path:    graphPath,
		Content: string(content),
	}, nil
}

// chownGraphOutput transfers the graph directory, and the lab directory when
// the export created it, to the lab owner.
func chownGraphOutput(owner, labDir string, labDirExisted bool, graphDir string) {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return
	}
	uid, gid, err := lookupUserIDs(owner)
	if err != nil {
		log.Warn("Failed to resolve graph output owner", "user", owner, "error", err)
		return
	}

	target := graphDir
	if !labDirExisted {
		target = labDir
	}
	if _, statErr := os.Stat(target); statErr != nil {
		return
	}
	if chownErr := chownTree(target, uid, gid); chownErr != nil {
		log.Warn("Failed to set ownership on graph output",
			"path", target,
			"user", owner,
			"error", chownErr,
		)
	}
}

// ListContainerInterfaces lists interfaces for a specific container.
func (s *Service) ListContainerInterfaces(ctx context.Context, container *clabruntime.GenericContainer) (*clabtypes.ContainerInterfaces, error) {
	if err := RequireContainerRuntime("interface inspection"); err != nil {
		return nil, err
	}
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		runtimeOption(defaultTimeout),
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
	if err := RequireContainerRuntime("interface inspection"); err != nil {
		return nil, err
	}
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		runtimeOption(defaultTimeout),
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

	if IsLabRuntime() {
		return s.execWithLabRuntime(ctx, opts)
	}

	// Prepare clab working directory
	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare working directory: %w", err)
	}

	unlock := lockContainerlabOperation()
	defer unlock()

	originalDir, _ := os.Getwd()
	if chErr := os.Chdir(workDir); chErr != nil {
		return nil, fmt.Errorf("failed to change to work directory: %w", chErr)
	}
	defer func() {
		if restoreErr := os.Chdir(originalDir); restoreErr != nil {
			log.Warn("Failed to restore working directory", "error", restoreErr)
		}
	}()

	// Build clab options
	var clabOpts []clabcore.ClabOption
	clabOpts = append(clabOpts, clabcore.WithTimeout(defaultTimeout))
	if opts.TopoPath != "" {
		clabOpts = append(clabOpts, clabcore.WithTopoPath(opts.TopoPath, nil))
	}
	clabOpts = append(clabOpts, runtimeOptions(nil, defaultTimeout)...)

	clab, err := clabcore.NewContainerLab(clabOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create containerlab instance: %w", err)
	}

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

	result, err := clab.Exec(ctx, opts.Commands, listOpts...)
	if err != nil {
		return nil, fmt.Errorf("exec failed: %w", err)
	}

	return result, nil
}

// SaveConfig saves the configuration of lab nodes.
func (s *Service) SaveConfig(ctx context.Context, opts SaveOptions) (*SaveResult, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	if IsLabRuntime() {
		return s.saveWithLabRuntime(ctx, opts)
	}

	// Prepare clab working directory
	workDir, err := s.prepareWorkDir(opts.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare working directory: %w", err)
	}

	unlock := lockContainerlabOperation()
	defer unlock()

	originalDir, _ := os.Getwd()
	if chErr := os.Chdir(workDir); chErr != nil {
		return nil, fmt.Errorf("failed to change to work directory: %w", chErr)
	}
	defer func() {
		if restoreErr := os.Chdir(originalDir); restoreErr != nil {
			log.Warn("Failed to restore working directory", "error", restoreErr)
		}
	}()

	clabOpts := append([]clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		clabcore.WithTopoPath(opts.TopoPath, nil),
	}, runtimeOptions(nil, defaultTimeout)...)

	clab, err := clabcore.NewContainerLab(clabOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	log.Info("Saving lab configuration",
		"username", opts.Username,
		"topoPath", opts.TopoPath,
	)

	savers, err := selectNodeConfigSavers(clab.Nodes, opts.NodeFilter)
	if err != nil {
		return nil, err
	}
	// Refresh the whole lab's entries even when only selected nodes are saved.
	if err := syncLabHostsFiles(ctx, clab); err != nil {
		return nil, fmt.Errorf("failed to prepare host name resolution: %w", err)
	}

	if clab.Config.Mgmt != nil {
		if err := clablinks.SetMgmtNetUnderlyingBridge(clab.Config.Mgmt.Bridge); err != nil {
			return nil, fmt.Errorf("failed to configure management bridge: %w", err)
		}
	}

	result := &SaveResult{}
	var afterSave func(nodeConfigSaver, *clabnodes.SaveConfigResult) error
	if opts.CopyOut != nil {
		labDir := clab.TopoPaths.TopologyLabDir()
		labDirName, nameErr := copyLabDirName(labDir, clab.Config.Name)
		if nameErr != nil {
			return nil, nameErr
		}
		copier, copyErr := newSaveCopier(*opts.CopyOut, labDir, labDirName)
		if copyErr != nil {
			return nil, fmt.Errorf("failed to prepare save copy destination: %w", copyErr)
		}
		defer func() { _ = copier.Close() }()
		result.CopyDir = copier.dir()
		afterSave = func(node nodeConfigSaver, saved *clabnodes.SaveConfigResult) error {
			if err := copier.copy(node.GetShortName(), saved); err != nil {
				return fmt.Errorf("copy failed: %w", err)
			}
			return nil
		}
	}

	if err := saveNodeConfigsThen(ctx, savers, afterSave); err != nil {
		return result, fmt.Errorf("save failed: %w", err)
	}

	log.Info("Lab configuration saved successfully",
		"username", opts.Username,
		"copyDir", result.CopyDir,
	)

	return result, nil
}

func selectNodeConfigSavers(nodes map[string]clabnodes.Node, nodeFilter []string) ([]nodeConfigSaver, error) {
	for _, name := range nodeFilter {
		if _, ok := nodes[name]; !ok {
			return nil, fmt.Errorf("node %q is not present in the topology", name)
		}
	}
	var savers []nodeConfigSaver
	for name, node := range nodes {
		if len(nodeFilter) == 0 || slices.Contains(nodeFilter, name) {
			savers = append(savers, node)
		}
	}
	return savers, nil
}

func saveNodeConfigs(ctx context.Context, nodes []nodeConfigSaver) error {
	return saveNodeConfigsThen(ctx, nodes, nil)
}

// saveNodeConfigsThen saves nodes concurrently and runs afterSave for every
// node whose save succeeded.
func saveNodeConfigsThen(
	ctx context.Context,
	nodes []nodeConfigSaver,
	afterSave func(nodeConfigSaver, *clabnodes.SaveConfigResult) error,
) error {
	var wg sync.WaitGroup
	errorsCh := make(chan error, len(nodes))

	for _, node := range nodes {
		wg.Add(1)
		go func(node nodeConfigSaver) {
			defer wg.Done()
			result, err := node.SaveConfig(ctx)
			if err != nil {
				errorsCh <- fmt.Errorf("node %q: %w", node.GetShortName(), err)
				return
			}
			if afterSave != nil {
				if err := afterSave(node, result); err != nil {
					errorsCh <- fmt.Errorf("node %q: %w", node.GetShortName(), err)
				}
			}
		}(node)
	}

	wg.Wait()
	close(errorsCh)

	var saveErrors []error
	for err := range errorsCh {
		saveErrors = append(saveErrors, err)
	}

	return errors.Join(saveErrors...)
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
	if err := RequireContainerRuntime("disabling TX offload"); err != nil {
		return err
	}
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	clabOpts := []clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
		runtimeOption(defaultTimeout),
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
	if err := RequireContainerRuntime("veth tools"); err != nil {
		return err
	}
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
		runtimeOption(defaultTimeout),
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
	if err := RequireContainerRuntime("VxLAN tools"); err != nil {
		return err
	}
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
	if err := RequireContainerRuntime("VxLAN tools"); err != nil {
		return nil, err
	}
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

// NetemTarget selects the node netem operates on: either a runtime container,
// or a topology node of a running lab (`clab tools netem -n <node> --name <lab>`).
type NetemTarget struct {
	ContainerName string
	LabName       string
	NodeName      string
	// Username owns the working directory used to load the lab topology.
	Username string
}

// NetemSetOptions contains options for setting link impairments using netem.
type NetemSetOptions struct {
	Target     NetemTarget
	Interface  string
	Delay      time.Duration
	Jitter     time.Duration
	Loss       float64
	Rate       uint64 // kbit/s
	Corruption float64
}

// resolveNetemNode returns the netns and topology identity netem works with.
// A topology node resolves through its kind, so a multi-container node (e.g. a
// distributed SR-SIM) targets the namespace its interfaces live in.
func (s *Service) resolveNetemNode(ctx context.Context, target NetemTarget) (*clabcore.NetemNode, error) {
	if target.ContainerName != "" {
		node, err := clabcore.ResolveNetemNode(ctx, config.AppConfig.ClabRuntime, defaultTimeout, target.ContainerName)
		if err != nil {
			return nil, fmt.Errorf("failed to get namespace path for container %s: %w", target.ContainerName, err)
		}
		return node, nil
	}

	var node *clabcore.NetemNode
	err := s.withRunningLab(target.LabName, target.Username, func(lab *clabcore.CLab) error {
		labNode, ok := lab.Nodes[target.NodeName]
		if !ok || isInternalNodeConfig(labNode.Config()) {
			return fmt.Errorf("%w: node %q in lab %q", ErrNetemNodeNotFound, target.NodeName, target.LabName)
		}
		nsPath, err := labNode.GetNSPath(ctx)
		if err != nil {
			return fmt.Errorf("failed to get namespace path for node %s: %w", target.NodeName, err)
		}
		node = clabcore.NewNetemNode(nsPath, target.NodeName, lab.Config.Name, target.NodeName)
		return nil
	})
	return node, err
}

// hostNetNS is the server's own network namespace, opened while the package
// initializes and no thread has switched namespaces yet.
var hostNetNS, hostNetNSErr = ns.GetCurrentNS()

// resolveNetemTarget returns where impairments of iface must be applied.
func (s *Service) resolveNetemTarget(ctx context.Context, nodeTarget NetemTarget, iface string) (*clabcore.NetemTarget, error) {
	node, err := s.resolveNetemNode(ctx, nodeTarget)
	if err != nil {
		return nil, err
	}
	target, err := node.TargetFor(iface)
	if err != nil {
		return nil, err
	}
	// TargetFor names the host namespace by the calling thread's netns path,
	// which may meanwhile belong to a thread another request moved into a node
	// namespace. Pin host-side targets to the namespace opened at startup.
	if target.NSPath != node.NSPath {
		if hostNetNSErr != nil {
			return nil, fmt.Errorf("failed to open host network namespace: %w", hostNetNSErr)
		}
		target.NSPath = fmt.Sprintf("/proc/self/fd/%d", hostNetNS.Fd())
	}
	return target, nil
}

// withRunningLab loads the topology of a running lab the way commands invoked
// with --name do, and runs fn while holding the containerlab operation lock.
func (s *Service) withRunningLab(labName, username string, fn func(*clabcore.CLab) error) error {
	workDir, err := s.prepareWorkDir(username)
	if err != nil {
		return fmt.Errorf("failed to prepare working directory: %w", err)
	}

	unlock := lockContainerlabOperation()
	defer unlock()

	originalDir, _ := os.Getwd()
	if chErr := os.Chdir(workDir); chErr != nil {
		return fmt.Errorf("failed to change to work directory: %w", chErr)
	}
	defer func() {
		if restoreErr := os.Chdir(originalDir); restoreErr != nil {
			log.Warn("Failed to restore working directory", "error", restoreErr)
		}
	}()

	// WithTopologyFromLab looks the lab up through the runtime, so it must come after WithRuntime.
	lab, err := clabcore.NewContainerLab(
		clabcore.WithTimeout(defaultTimeout),
		runtimeOption(defaultTimeout),
		clabcore.WithTopologyFromLab(labName, nil),
	)
	if err != nil {
		return fmt.Errorf("failed to load topology of lab %q: %w", labName, err)
	}

	return fn(lab)
}

// withNetemInterface opens the namespace holding the target interface and runs
// fn inside it with an rtnetlink socket bound to that namespace.
func withNetemInterface(target *clabcore.NetemTarget, fn func(tcnl *gotc.Tc, iface *net.Interface) error) error {
	nodeNS, err := ns.GetNS(target.NSPath)
	if err != nil {
		return fmt.Errorf("failed to open network namespace %s: %w", target.NSPath, err)
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
		link, err := resolveNetemLink(target.Iface)
		if err != nil {
			var lnf netlink.LinkNotFoundError
			if errors.As(err, &lnf) {
				return fmt.Errorf("%w: %s", ErrNetemInterfaceNotFound, target.Iface)
			}
			return err
		}

		iface, err := net.InterfaceByName(link.Attrs().Name)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrNetemInterfaceNotFound, link.Attrs().Name)
		}

		return fn(tcnl, iface)
	})
}

// SetNetem applies netem impairments to an interface of a node. Interfaces of
// stitched links are impaired on their host-side tools interface, like the CLI does.
func (s *Service) SetNetem(ctx context.Context, opts NetemSetOptions) error {
	if err := RequireContainerRuntime("link impairment (netem)"); err != nil {
		return err
	}
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	// Best-effort: ensure netem kernel module is loaded (helps on some distros).
	if err := exec.CommandContext(ctx, "modprobe", "sch_netem").Run(); err != nil {
		log.Warn("failed to load sch_netem kernel module", "err", err)
	}

	target, err := s.resolveNetemTarget(ctx, opts.Target, opts.Interface)
	if err != nil {
		return err
	}

	err = withNetemInterface(target, func(tcnl *gotc.Tc, iface *net.Interface) error {
		_, err := clabnetem.SetImpairments(
			tcnl,
			target.DisplayName,
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
		"node", target.DisplayName,
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
	netemIfLink, err := netlink.LinkByName(clabutils.SanitizeInterfaceName(iface))
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

// ResetNetem removes netem impairments from an interface of a node.
func (s *Service) ResetNetem(ctx context.Context, nodeTarget NetemTarget, ifaceName string) error {
	if err := RequireContainerRuntime("link impairment (netem)"); err != nil {
		return err
	}
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	target, err := s.resolveNetemTarget(ctx, nodeTarget, ifaceName)
	if err != nil {
		return err
	}

	return withNetemInterface(target, func(tcnl *gotc.Tc, iface *net.Interface) error {
		qdiscs, qdiscErr := clabnetem.Impairments(tcnl)
		if qdiscErr == nil && !hasNetemQdisc(qdiscs, iface.Index) {
			log.Debug("netem reset skipped because interface has no netem qdisc",
				"node", target.DisplayName,
				"interface", ifaceName,
			)
			return nil
		}
		if qdiscErr != nil {
			log.Debug("failed to pre-check netem qdiscs before reset",
				"node", target.DisplayName,
				"interface", ifaceName,
				"err", qdiscErr,
			)
		}

		if err := clabnetem.DeleteImpairments(tcnl, iface); err != nil {
			if isNetemAlreadyClearError(err) {
				log.Debug("netem reset delete raced with already-cleared qdisc",
					"node", target.DisplayName,
					"interface", ifaceName,
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

// ShowNetem returns the netem impairments of a node.
func (s *Service) ShowNetem(ctx context.Context, target NetemTarget) ([]clabtypes.ImpairmentData, error) {
	if err := RequireContainerRuntime("link impairment (netem)"); err != nil {
		return nil, err
	}
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	node, err := s.resolveNetemNode(ctx, target)
	if err != nil {
		return nil, err
	}

	return netemNodeImpairments(node)
}

// ShowLabNetem returns the netem impairments of every deployed node of a lab,
// keyed by topology node name (`clab tools netem show --name <lab>`).
func (s *Service) ShowLabNetem(ctx context.Context, labName, username string) (map[string][]clabtypes.ImpairmentData, error) {
	if err := RequireContainerRuntime("link impairment (netem)"); err != nil {
		return nil, err
	}
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	nodes := map[string]*clabcore.NetemNode{}
	err := s.withRunningLab(labName, username, func(lab *clabcore.CLab) error {
		for name, labNode := range lab.Nodes {
			if isInternalNodeConfig(labNode.Config()) {
				continue
			}
			nsPath, err := labNode.GetNSPath(ctx)
			if err != nil {
				log.Warn("skipping netem show for node without a namespace", "lab", labName, "node", name, "err", err)
				continue
			}
			nodes[name] = clabcore.NewNetemNode(nsPath, name, lab.Config.Name, name)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	result := make(map[string][]clabtypes.ImpairmentData, len(nodes))
	for name, node := range nodes {
		impairments, err := netemNodeImpairments(node)
		if err != nil {
			log.Warn("failed to read netem impairments", "lab", labName, "node", name, "err", err)
			continue
		}
		result[name] = impairments
	}

	return result, nil
}

// netemNodeImpairments lists the netem qdiscs in a node's namespace plus those on
// host-side tools interfaces of its stitched links.
func netemNodeImpairments(node *clabcore.NetemNode) ([]clabtypes.ImpairmentData, error) {
	nodeNS, err := ns.GetNS(node.NSPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open network namespace %s: %w", node.NSPath, err)
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

	impairments := []clabtypes.ImpairmentData{}
	var ifaceNames []string
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

		// Tools interfaces are published under the topology-facing name, which
		// is the alias when a kind remaps interface names.
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, link := range links {
			name := link.Attrs().Alias
			if name == "" {
				name = link.Attrs().Name
			}
			ifaceNames = append(ifaceNames, name)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	hostImpairments, err := toolsInterfaceImpairments(node, ifaceNames)
	if err != nil {
		return nil, err
	}

	return append(impairments, hostImpairments...), nil
}

// toolsInterfaceImpairments returns the impairments set on the host-namespace
// tools interfaces that stitched links publish for the given node interfaces.
func toolsInterfaceImpairments(node *clabcore.NetemNode, ifaces []string) ([]clabtypes.ImpairmentData, error) {
	toolsIfaces := map[uint32]string{} // host ifindex -> display name
	for _, iface := range ifaces {
		toolsIface := node.ToolsIfaceFor(iface)
		if toolsIface == "" {
			continue
		}
		link, err := netlink.LinkByName(toolsIface)
		if err != nil {
			continue
		}
		toolsIfaces[uint32(link.Attrs().Index)] = iface + " (host)"
	}
	if len(toolsIfaces) == 0 {
		return nil, nil
	}

	if hostNetNSErr != nil {
		return nil, fmt.Errorf("failed to open host network namespace: %w", hostNetNSErr)
	}

	tcnl, err := clabnetem.NewTC(int(hostNetNS.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to open rtnetlink socket: %w", err)
	}
	defer func() {
		if closeErr := tcnl.Close(); closeErr != nil {
			log.Warn("failed to close rtnetlink socket", "err", closeErr)
		}
	}()

	qdiscs, err := clabnetem.Impairments(tcnl)
	if err != nil {
		return nil, err
	}

	var impairments []clabtypes.ImpairmentData
	for idx := range qdiscs {
		display, ok := toolsIfaces[qdiscs[idx].Ifindex]
		if !ok || qdiscs[idx].Kind != "netem" {
			continue
		}
		data := qdiscToImpairmentData(&qdiscs[idx])
		data.Interface = display
		impairments = append(impairments, data)
	}

	return impairments, nil
}

func (s *Service) getContainerRuntime() (clabruntime.ContainerRuntime, error) {
	if err := RequireContainerRuntime("this operation"); err != nil {
		return nil, err
	}
	clabOpts := append([]clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
	}, runtimeOptions(nil, defaultTimeout)...)

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

	if err := checkGenerateableKinds(clab.Reg, nodeDefs); err != nil {
		return nil, err
	}

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

// GenerateKindError reports a tier kind that containerlab cannot generate.
type GenerateKindError struct {
	Kind string
}

func (e *GenerateKindError) Error() string {
	return fmt.Sprintf("kind '%s' cannot be used to generate a topology", e.Kind)
}

// checkGenerateableKinds rejects kinds that are not registered or not
// generateable; their interface naming is unknown.
func checkGenerateableKinds(reg *clabnodes.NodeRegistry, nodes []nodesDef) error {
	attributes := reg.GetGenerateNodeAttributes()
	for _, node := range nodes {
		if !attributes[node.kind].IsGenerateable() {
			return &GenerateKindError{Kind: node.kind}
		}
	}
	return nil
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

	// Config.Mgmt is not serialized since containerlab 0.80; the mgmt block is
	// rendered from MgmtNetworks.
	config.MgmtNetworks = clabtypes.MgmtNetworks{config.Mgmt}
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

// lookupUserIDs resolves a username to its numeric uid/gid.
func lookupUserIDs(username string) (uid, gid int, err error) {
	usr, err := user.Lookup(username)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to lookup user: %w", err)
	}
	if uid, err = strconv.Atoi(usr.Uid); err != nil {
		return 0, 0, fmt.Errorf("failed to parse uid for %q: %w", username, err)
	}
	if gid, err = strconv.Atoi(usr.Gid); err != nil {
		return 0, 0, fmt.Errorf("failed to parse gid for %q: %w", username, err)
	}
	return uid, gid, nil
}

// chownTree transfers ownership of path and everything below it to uid:gid.
// Symlinks are changed rather than followed, so a link cannot retarget the chown.
func chownTree(path string, uid, gid int) error {
	return filepath.WalkDir(path, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
}

// prepareWorkDir prepares the working directory for a user.
func (s *Service) prepareWorkDir(username string) (string, error) {
	usr, err := user.Lookup(username)
	if err != nil {
		return "", fmt.Errorf("failed to lookup user: %w", err)
	}

	clabDir := filepath.Join(usr.HomeDir, ".clab")
	if err := os.MkdirAll(clabDir, 0750); err != nil {
		return "", fmt.Errorf("failed to create .clab directory: %w", err)
	}

	// Try to set ownership of the .clab directory to the actual user
	uid, gid, idErr := lookupUserIDs(username)
	if idErr == nil {
		if chownErr := os.Chown(clabDir, uid, gid); chownErr != nil {
			log.Warn("Failed to set ownership on .clab directory",
				"dir", clabDir,
				"user", username,
				"error", chownErr,
			)
		}
	}

	return clabDir, nil
}

// ensureTimeout ensures the context has a timeout.
func (s *Service) ensureTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		return context.WithTimeout(ctx, defaultTimeout)
	}
	return ctx, func() {}
}

// gitRepoInDirectory supplies an explicit clone destination to containerlab's Git helper.
type gitRepoInDirectory struct {
	clabgit.GitRepo
	dir string
}

func (r gitRepoInDirectory) GetName() string { return r.dir }

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

	repoDir, err := filepath.Abs(filepath.Join(workDir, repo.GetName()))
	if err != nil {
		return "", fmt.Errorf("failed to resolve clone directory: %w", err)
	}

	// Use an absolute destination so concurrent clones do not change each other's cwd.
	gitImpl := clabgit.NewGoGit(gitRepoInDirectory{GitRepo: repo, dir: repoDir})

	// Clone the repo
	log.Debug("Cloning git repository", "url", topo, "workDir", workDir)
	if err := gitImpl.Clone(); err != nil {
		return "", fmt.Errorf("failed to clone git repository: %w", err)
	}

	// Adjust permissions for the checked out repo
	if err := clabutils.SetUIDAndGID(repoDir); err != nil {
		log.Warn("Error adjusting repository permissions, continuing anyways", "error", err)
	}

	// Find the topology file in the cloned repo
	repoPath := repoDir

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
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
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

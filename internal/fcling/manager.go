// Package fcling runs fcling for the server's labs: its one-shot reports, and one engine
// (`fcling serve`) per lab, a container next to the lab's nodes.
//
// The manager keeps no state of its own. Whether an engine runs, where it listens and its
// token are read back from the container each time, so engines outlive a server restart.
package fcling

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
)

const (
	// DefaultImage is the image of the reports and the engine (FCLING_DOCKER_IMAGE).
	DefaultImage = "ghcr.io/srl-labs/fcling:latest"
	// DefaultPullPolicy is when that image is pulled (FCLING_PULL_POLICY).
	DefaultPullPolicy = "always"

	// LabLabel names an engine's lab. It is not containerlab's own label on purpose:
	// `containerlab inspect` would list the engine as a node of the lab.
	LabLabel = "clab-fcling-lab"

	engineAPIPort   = "8765"
	engineTokenEnv  = "FCLI_API_TOKEN"
	engineLogLines  = "20"
	stopGraceSecs   = "5"
	probeTimeout    = 2 * time.Second
	sweepInterval   = 5 * time.Minute
	sweepTimeout    = time.Minute
	containerPrefix = "clab-"
	containerSuffix = "-fcling"
)

// The state of a lab's engine.
const (
	StateStopped  = "stopped"
	StateStarting = "starting"
	StateReady    = "ready"
	StateFailed   = "failed"
)

// ErrEngineNotRunning says a lab has no engine to talk to.
var ErrEngineNotRunning = errors.New("fcling engine is not running")

// Config is how the server runs fcling. Empty values get the defaults.
type Config struct {
	// Runtime is the configured lab runtime: docker or podman.
	Runtime    string
	Image      string
	PullPolicy string
}

func (c Config) normalized() Config {
	c.Image = strings.TrimSpace(c.Image)
	if c.Image == "" {
		c.Image = DefaultImage
	}
	switch policy := strings.ToLower(strings.TrimSpace(c.PullPolicy)); policy {
	case "always", "missing", "never":
		c.PullPolicy = policy
	default:
		c.PullPolicy = DefaultPullPolicy
	}
	return c
}

func (c Config) runtimeBinary() string {
	if strings.EqualFold(strings.TrimSpace(c.Runtime), "podman") {
		return "podman"
	}
	return "docker"
}

// ReportArgs is the runtime command line of a one-shot report. Without a terminal fcling
// squeezes its tables into 80 columns, which leaves them unreadable, so it gets a width.
func ReportArgs(cfg Config, networkArgs []string, topologyPath string, commandArgs []string) []string {
	cfg = cfg.normalized()
	args := []string{"run", "--pull", cfg.PullPolicy, "--rm", "-e", "COLUMNS=400"}
	args = append(args, networkArgs...)
	args = append(args,
		"-v", "/etc/hosts:/etc/hosts:ro",
		"-v", topologyPath+":/topo.yml",
		cfg.Image,
		"-t", "/topo.yml",
	)
	return append(args, commandArgs...)
}

// ContainerName is the name of a lab's engine, and of the volume holding its history.
func ContainerName(labName string) string {
	return containerPrefix + labName + containerSuffix
}

func labOfContainer(name string) (string, bool) {
	name = strings.TrimPrefix(strings.TrimSpace(name), "/")
	if !strings.HasPrefix(name, containerPrefix) || !strings.HasSuffix(name, containerSuffix) {
		return "", false
	}
	lab := strings.TrimSuffix(strings.TrimPrefix(name, containerPrefix), containerSuffix)
	return lab, lab != ""
}

// Status is how a lab's engine is doing.
type Status struct {
	State         string
	Image         string
	ContainerName string
	StartedAt     string
	// Error is the end of the engine's log, when it failed.
	Error string
}

// StartOptions says what a new engine watches.
type StartOptions struct {
	LabName      string
	TopologyPath string
	// NetworkArgs attaches the engine to the lab's management network. It is called only
	// when an engine is really started, since it can reserve an address.
	NetworkArgs func(ctx context.Context) ([]string, error)
}

type commandRunner interface {
	Run(ctx context.Context, name string, args []string, env []string) (string, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args []string, env []string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	out, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(out))
	if err != nil {
		if trimmed == "" {
			return "", err
		}
		return trimmed, fmt.Errorf("%w: %s", err, trimmed)
	}
	return trimmed, nil
}

// Manager starts, finds and removes the engines of the server's labs.
type Manager struct {
	cfg    Config
	runner commandRunner
	client *http.Client

	locksMu sync.Mutex
	locks   map[string]*sync.Mutex

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewManager returns a manager that removes engines left without a lab until Shutdown.
func NewManager(cfg Config) *Manager {
	m := newManager(cfg, execRunner{})
	go m.sweeper()
	return m
}

func newManager(cfg Config, runner commandRunner) *Manager {
	return &Manager{
		cfg:    cfg.normalized(),
		runner: runner,
		client: &http.Client{Timeout: probeTimeout},
		locks:  make(map[string]*sync.Mutex),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

// Shutdown stops the sweeper. The engines keep running and collecting history: the next
// server finds them.
func (m *Manager) Shutdown(ctx context.Context) {
	m.stopOnce.Do(func() { close(m.stopCh) })
	select {
	case <-m.doneCh:
	case <-ctx.Done():
	}
}

// labLock serializes what changes one lab's engine, so two starts cannot race for its name.
func (m *Manager) labLock(labName string) func() {
	m.locksMu.Lock()
	lock, ok := m.locks[labName]
	if !ok {
		lock = &sync.Mutex{}
		m.locks[labName] = lock
	}
	m.locksMu.Unlock()
	lock.Lock()
	return lock.Unlock
}

func (m *Manager) run(ctx context.Context, args ...string) (string, error) {
	return m.runner.Run(ctx, m.cfg.runtimeBinary(), args, nil)
}

// Status tells how a lab's engine is doing: stopped without a container, starting until it
// answers with its token, ready then, failed once its container has exited.
func (m *Manager) Status(ctx context.Context, labName string) (Status, error) {
	container, err := m.inspect(ctx, labName)
	if err != nil {
		return Status{}, err
	}
	if container == nil {
		return Status{State: StateStopped}, nil
	}

	status := Status{
		Image:         container.Config.Image,
		ContainerName: ContainerName(labName),
		StartedAt:     container.startedAt(),
	}
	switch {
	case container.State.Running:
		status.State = StateStarting
		if m.engineAnswers(ctx, container) {
			status.State = StateReady
		}
	case container.isBeingStarted():
		status.State = StateStarting
	default:
		status.State = StateFailed
		status.Error = m.logTail(ctx, labName)
	}
	return status, nil
}

// Start starts a lab's engine and returns its status. An engine that runs is left alone, so
// it keeps its history; one that has exited is replaced.
func (m *Manager) Start(ctx context.Context, opts StartOptions) (Status, error) {
	defer m.labLock(opts.LabName)()

	container, err := m.inspect(ctx, opts.LabName)
	if err != nil {
		return Status{}, err
	}
	if container != nil {
		if container.State.Running || container.isBeingStarted() {
			return m.Status(ctx, opts.LabName)
		}
		if err := m.removeContainer(ctx, opts.LabName); err != nil {
			return Status{}, err
		}
	}

	var networkArgs []string
	if opts.NetworkArgs != nil {
		if networkArgs, err = opts.NetworkArgs(ctx); err != nil {
			return Status{}, err
		}
	}
	token, err := newToken()
	if err != nil {
		return Status{}, err
	}
	// The token goes through the runtime CLI's environment, which other users on the host
	// cannot read in a process listing.
	env := []string{engineTokenEnv + "=" + token}
	args := engineRunArgs(m.cfg, opts, networkArgs)
	if _, err := m.runner.Run(ctx, m.cfg.runtimeBinary(), args, env); err != nil {
		// A run that fails at the network or the port leaves its container created.
		if cleanupErr := m.removeContainer(ctx, opts.LabName); cleanupErr != nil {
			log.Warnf("fcling: failed removing the engine of lab '%s' after a failed start: %v", opts.LabName, cleanupErr)
		}
		return Status{}, fmt.Errorf("failed starting the fcling engine: %w", err)
	}
	return m.Status(ctx, opts.LabName)
}

func engineRunArgs(cfg Config, opts StartOptions, networkArgs []string) []string {
	name := ContainerName(opts.LabName)
	args := []string{
		"run", "-d",
		"--pull", cfg.PullPolicy,
		"--name", name,
		"--label", LabLabel + "=" + opts.LabName,
	}
	args = append(args, networkArgs...)
	return append(args,
		// The runtime picks the port; the server reads it back. Reachable from this host only.
		"-p", "127.0.0.1::"+engineAPIPort,
		"-v", opts.TopologyPath+":/topo.yml:ro",
		"-v", name+":/state",
		"-e", engineTokenEnv,
		cfg.Image,
		"-t", "/topo.yml",
		"serve", "--host", "0.0.0.0", "--no-tls", "--persist-acks",
	)
}

// Stop stops a lab's engine and keeps its history for the next one.
func (m *Manager) Stop(ctx context.Context, labName string) error {
	defer m.labLock(labName)()

	// A clean stop first, for the history to close; fcling stops within a second.
	if _, err := m.run(ctx, "stop", "-t", stopGraceSecs, ContainerName(labName)); err != nil && !isNotFound(err) {
		log.Debugf("fcling: stopping the engine of lab '%s': %v", labName, err)
	}
	return m.removeContainer(ctx, labName)
}

// Remove removes a lab's engine and its history.
func (m *Manager) Remove(ctx context.Context, labName string) error {
	defer m.labLock(labName)()

	if err := m.removeContainer(ctx, labName); err != nil {
		return err
	}
	if _, err := m.run(ctx, "volume", "rm", "-f", ContainerName(labName)); err != nil && !isNotFound(err) {
		return fmt.Errorf("failed removing the fcling history of lab '%s': %w", labName, err)
	}
	return nil
}

func (m *Manager) removeContainer(ctx context.Context, labName string) error {
	if _, err := m.run(ctx, "rm", "-f", ContainerName(labName)); err != nil && !isNotFound(err) {
		return fmt.Errorf("failed removing the fcling engine of lab '%s': %w", labName, err)
	}
	return nil
}

func isNotFound(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "no such") ||
		strings.Contains(message, "not found") ||
		strings.Contains(message, "no volume")
}

func (m *Manager) logTail(ctx context.Context, labName string) string {
	out, err := m.run(ctx, "logs", "--tail", engineLogLines, ContainerName(labName))
	if err != nil && out == "" {
		return err.Error()
	}
	return strings.TrimSpace(out)
}

// containerInspect is the part of `container inspect` the manager reads.
type containerInspect struct {
	State struct {
		Status    string `json:"Status"`
		Running   bool   `json:"Running"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
	Config struct {
		Image string   `json:"Image"`
		Env   []string `json:"Env"`
	} `json:"Config"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

func (c *containerInspect) isBeingStarted() bool {
	switch strings.ToLower(c.State.Status) {
	case "created", "configured", "restarting", "initialized":
		return true
	}
	return false
}

func (c *containerInspect) startedAt() string {
	started := strings.TrimSpace(c.State.StartedAt)
	if strings.HasPrefix(started, "0001-01-01") {
		return ""
	}
	return started
}

func (c *containerInspect) token() string {
	for _, entry := range c.Config.Env {
		if value, ok := strings.CutPrefix(entry, engineTokenEnv+"="); ok {
			return value
		}
	}
	return ""
}

func (c *containerInspect) hostPort() string {
	for _, binding := range c.NetworkSettings.Ports[engineAPIPort+"/tcp"] {
		if binding.HostPort != "" {
			return binding.HostPort
		}
	}
	return ""
}

func (m *Manager) inspect(ctx context.Context, labName string) (*containerInspect, error) {
	out, err := m.run(ctx, "container", "inspect", ContainerName(labName))
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed inspecting the fcling engine of lab '%s': %w", labName, err)
	}
	var containers []containerInspect
	if err := json.Unmarshal([]byte(out), &containers); err != nil {
		return nil, fmt.Errorf("failed reading the fcling engine of lab '%s': %w", labName, err)
	}
	if len(containers) == 0 {
		return nil, nil
	}
	return &containers[0], nil
}

// Target is where a running engine answers, and the token it wants.
type Target struct {
	Host  string
	Token string
}

// Target finds a lab's running engine, or ErrEngineNotRunning.
func (m *Manager) Target(ctx context.Context, labName string) (Target, error) {
	container, err := m.inspect(ctx, labName)
	if err != nil {
		return Target{}, err
	}
	if container == nil || !container.State.Running {
		return Target{}, ErrEngineNotRunning
	}
	return targetOf(container)
}

func targetOf(container *containerInspect) (Target, error) {
	port, token := container.hostPort(), container.token()
	if port == "" || token == "" {
		return Target{}, ErrEngineNotRunning
	}
	return Target{Host: net.JoinHostPort("127.0.0.1", port), Token: token}, nil
}

func (m *Manager) engineAnswers(ctx context.Context, container *containerInspect) bool {
	target, err := targetOf(container)
	if err != nil {
		return false
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+target.Host+"/api/status", nil)
	if err != nil {
		return false
	}
	request.Header.Set("Authorization", "Bearer "+target.Token)
	response, err := m.client.Do(request)
	if err != nil {
		return false
	}
	defer func() { _ = response.Body.Close() }()
	return response.StatusCode == http.StatusOK
}

func newToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("failed generating an fcling token: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

func (m *Manager) sweeper() {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	defer close(m.doneCh)

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), sweepTimeout)
			m.sweep(ctx)
			cancel()
		}
	}
}

// sweep removes the engines whose lab is gone: `containerlab destroy` run outside this
// server does not know them. A lab that is only stopped still has its containers.
func (m *Manager) sweep(ctx context.Context) {
	out, err := m.run(ctx, "ps", "-a", "--filter", "label="+LabLabel, "--format", "{{.Names}}")
	if err != nil {
		log.Warnf("fcling sweeper: failed listing engines: %v", err)
		return
	}
	for _, line := range strings.Split(out, "\n") {
		labName, ok := labOfContainer(line)
		if !ok {
			continue
		}
		nodes, err := m.run(ctx, "ps", "-a", "-q", "--filter", "label=containerlab="+labName)
		if err != nil {
			log.Warnf("fcling sweeper: failed listing the nodes of lab '%s': %v", labName, err)
			continue
		}
		if strings.TrimSpace(nodes) != "" {
			continue
		}
		log.Infof("fcling sweeper: lab '%s' is gone, removing its engine", labName)
		if err := m.Remove(ctx, labName); err != nil {
			log.Warnf("fcling sweeper: %v", err)
		}
	}
}

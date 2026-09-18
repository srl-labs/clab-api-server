package capture

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"go.yaml.in/yaml/v3"
)

const (
	defaultSessionSweepInterval = time.Minute
	defaultEdgesharkComposeURL  = "https://github.com/siemens/edgeshark/raw/main/deployments/wget/docker-compose.yaml"
	packetflixProbeTimeout      = 500 * time.Millisecond
)

var sanitizeContainerNameRx = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

var edgesharkComposeURL = defaultEdgesharkComposeURL

var (
	ErrEdgeSharkNotRunning = errors.New("edgeshark is not running")
	ErrSessionNotFound     = errors.New("capture session not found")
	ErrSessionForbidden    = errors.New("capture session not owned by user")
)

type pullPolicy string

const (
	pullPolicyAlways  pullPolicy = "always"
	pullPolicyMissing pullPolicy = "missing"
	pullPolicyNever   pullPolicy = "never"
)

type ManagerConfig struct {
	Runtime               string
	PacketflixPort        int
	RemoteHostname        string
	WiresharkDockerImage  string
	WiresharkPullPolicy   string
	WiresharkSessionTTL   time.Duration
	EdgesharkExtraEnvVars string
}

type ContainerCaptureSpec struct {
	ContainerName        string
	InterfaceNames       []string
	LabDirectory         string
	HostNetworkNamespace bool
}

type PacketflixURI struct {
	ContainerName  string
	InterfaceNames []string
	URI            string
}

type WiresharkSessionInfo struct {
	SessionID      string
	LabName        string
	ContainerName  string
	InterfaceNames []string
	VncPath        string
	ShowVolumeTip  bool
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

type EdgeSharkStatus struct {
	Running bool
	Version string
}

type CreateWiresharkSessionsOptions struct {
	Username string
	LabName  string
	Theme    string
	Specs    []ContainerCaptureSpec
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

type wiresharkSession struct {
	id             string
	username       string
	labName        string
	containerName  string
	interfaceNames []string
	containerID    string
	port           int
	showVolumeTip  bool
	createdAt      time.Time
	expiresAt      time.Time
	lastAccess     time.Time
}

type Manager struct {
	cfg    ManagerConfig
	runner commandRunner
	client *http.Client

	mu       sync.RWMutex
	sessions map[string]*wiresharkSession

	stopCh chan struct{}
	doneCh chan struct{}
}

func NewManager(cfg ManagerConfig) *Manager {
	normalized := cfg
	if normalized.PacketflixPort <= 0 {
		normalized.PacketflixPort = 5001
	}
	if normalized.WiresharkDockerImage == "" {
		normalized.WiresharkDockerImage = "ghcr.io/srl-labs/wireshark-vnc-docker:latest"
	}
	if normalized.WiresharkSessionTTL <= 0 {
		normalized.WiresharkSessionTTL = 2 * time.Hour
	}
	switch pullPolicy(strings.ToLower(strings.TrimSpace(normalized.WiresharkPullPolicy))) {
	case pullPolicyAlways, pullPolicyMissing, pullPolicyNever:
	default:
		normalized.WiresharkPullPolicy = string(pullPolicyAlways)
	}

	m := &Manager{
		cfg:      normalized,
		runner:   execRunner{},
		client:   &http.Client{Timeout: 2 * time.Second},
		sessions: make(map[string]*wiresharkSession),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
	go m.sessionSweeper()
	return m
}

func (m *Manager) Shutdown(ctx context.Context) {
	close(m.stopCh)
	select {
	case <-m.doneCh:
	case <-ctx.Done():
	}

	m.mu.Lock()
	pending := make([]*wiresharkSession, 0, len(m.sessions))
	for _, session := range m.sessions {
		pending = append(pending, session)
	}
	m.sessions = make(map[string]*wiresharkSession)
	m.mu.Unlock()

	for _, session := range pending {
		if err := m.stopWiresharkContainer(ctx, session.containerID); err != nil {
			log.Warnf("capture shutdown: failed stopping session '%s': %v", session.id, err)
		}
	}
}

func (m *Manager) Runtime() string {
	return m.runtimeBinary()
}

func (m *Manager) PacketflixPort() int {
	return m.cfg.PacketflixPort
}

func (m *Manager) Status(ctx context.Context) (EdgeSharkStatus, error) {
	if status, ok, err := m.probePacketflixVersion(ctx); ok || err != nil {
		return status, err
	}
	if m.packetflixPortReachable(ctx) && m.edgeSharkContainerRunning(ctx) {
		return EdgeSharkStatus{Running: true}, nil
	}
	return EdgeSharkStatus{Running: false}, nil
}

func (m *Manager) probePacketflixVersion(ctx context.Context) (EdgeSharkStatus, bool, error) {
	versionURL := fmt.Sprintf("http://127.0.0.1:%d/version", m.cfg.PacketflixPort)
	probeCtx, cancel := context.WithTimeout(ctx, packetflixProbeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, versionURL, nil)
	if err != nil {
		return EdgeSharkStatus{}, false, err
	}

	res, err := m.client.Do(req)
	if err != nil {
		return EdgeSharkStatus{}, false, nil
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return EdgeSharkStatus{}, false, nil
	}
	body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	return EdgeSharkStatus{
		Running: true,
		Version: strings.TrimSpace(string(body)),
	}, true, nil
}

func (m *Manager) packetflixPortReachable(ctx context.Context) bool {
	probeCtx, cancel := context.WithTimeout(ctx, packetflixProbeTimeout)
	defer cancel()

	conn, err := (&net.Dialer{Timeout: packetflixProbeTimeout}).DialContext(
		probeCtx,
		"tcp",
		fmt.Sprintf("127.0.0.1:%d", m.cfg.PacketflixPort),
	)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func edgeSharkStatusPsArgs() []string {
	return []string{"ps", "--filter", "name=edgeshark", "--format", "{{.Names}} {{.Image}}"}
}

func (m *Manager) edgeSharkContainerRunning(ctx context.Context) bool {
	out, err := m.runner.Run(ctx, m.runtimeBinary(), edgeSharkStatusPsArgs(), nil)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		if isEdgeSharkPacketflixContainerLine(line) {
			return true
		}
	}
	return false
}

func isEdgeSharkPacketflixContainerLine(line string) bool {
	normalized := strings.ToLower(strings.TrimSpace(line))
	return strings.Contains(normalized, "packetflix") ||
		strings.Contains(normalized, "edgeshark-edgeshark") ||
		strings.Contains(normalized, "edgeshark_edgeshark")
}

func (m *Manager) InstallEdgeShark(ctx context.Context) error {
	composePath, cleanup, err := m.prepareEdgesharkComposeFile(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	runtime := m.runtimeBinary()
	_, err = m.runner.Run(
		ctx,
		runtime,
		[]string{"compose", "-f", composePath, "up", "-d"},
		[]string{"DOCKER_DEFAULT_PLATFORM="},
	)
	if err != nil {
		return fmt.Errorf("failed to install edgeshark: %w", err)
	}
	return nil
}

func (m *Manager) UninstallEdgeShark(ctx context.Context) error {
	composePath, cleanup, err := m.prepareEdgesharkComposeFile(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	runtime := m.runtimeBinary()
	_, err = m.runner.Run(
		ctx,
		runtime,
		[]string{"compose", "-f", composePath, "down"},
		[]string{"DOCKER_DEFAULT_PLATFORM="},
	)
	if err != nil {
		return fmt.Errorf("failed to uninstall edgeshark: %w", err)
	}
	return nil
}

func (m *Manager) BuildPacketflixURIs(
	ctx context.Context,
	specs []ContainerCaptureSpec,
	remoteHostname string,
) ([]PacketflixURI, error) {
	if len(specs) == 0 {
		return nil, errors.New("at least one capture target is required")
	}

	status, err := m.Status(ctx)
	if err != nil {
		return nil, err
	}
	if !status.Running {
		return nil, ErrEdgeSharkNotRunning
	}

	resolvedHostname := m.resolveRemoteHostname(remoteHostname)
	bracketed := bracketHostname(resolvedHostname)

	out := make([]PacketflixURI, 0, len(specs))
	for _, spec := range specs {
		if len(spec.InterfaceNames) == 0 {
			continue
		}
		uri, err := buildPacketflixURIForSpec(bracketed, m.cfg.PacketflixPort, spec)
		if err != nil {
			return nil, err
		}
		out = append(out, PacketflixURI{
			ContainerName:  spec.ContainerName,
			InterfaceNames: append([]string(nil), spec.InterfaceNames...),
			URI:            uri,
		})
	}

	if len(out) == 0 {
		return nil, errors.New("no valid capture targets were provided")
	}
	return out, nil
}

func (m *Manager) CreateWiresharkSessions(
	ctx context.Context,
	options CreateWiresharkSessionsOptions,
) ([]WiresharkSessionInfo, error) {
	if len(options.Specs) == 0 {
		return nil, errors.New("at least one capture target is required")
	}

	status, err := m.Status(ctx)
	if err != nil {
		return nil, err
	}
	if !status.Running {
		return nil, ErrEdgeSharkNotRunning
	}

	if err := m.ensureImageAvailable(ctx); err != nil {
		return nil, err
	}

	edgesharkNetwork, err := m.findEdgeSharkNetwork(ctx)
	if err != nil {
		return nil, err
	}

	created := make([]*wiresharkSession, 0, len(options.Specs))
	infos := make([]WiresharkSessionInfo, 0, len(options.Specs))
	packetflixHost := wiresharkPacketflixHost(m.runtimeBinary(), edgesharkNetwork != "")

	for _, spec := range options.Specs {
		if len(spec.InterfaceNames) == 0 {
			continue
		}

		port, err := reserveLocalPort()
		if err != nil {
			m.cleanupCreatedSessions(ctx, created)
			return nil, err
		}

		packetflix, err := buildPacketflixURIForSpec(
			packetflixHost,
			m.cfg.PacketflixPort,
			spec,
		)
		if err != nil {
			m.cleanupCreatedSessions(ctx, created)
			return nil, err
		}

		sessionID := randomSessionID()
		containerName := buildWiresharkContainerName(
			options.Username,
			spec.ContainerName,
			spec.InterfaceNames,
		)

		containerID, err := m.startWiresharkContainer(ctx, startWiresharkOptions{
			containerName:  containerName,
			packetflixURI:  packetflix,
			darkMode:       strings.EqualFold(strings.TrimSpace(options.Theme), "dark"),
			localPort:      port,
			labDir:         strings.TrimSpace(spec.LabDirectory),
			edgesharkNet:   edgesharkNetwork,
			wiresharkImage: m.cfg.WiresharkDockerImage,
		})
		if err != nil {
			m.cleanupCreatedSessions(ctx, created)
			return nil, err
		}

		now := time.Now().UTC()
		session := &wiresharkSession{
			id:             sessionID,
			username:       options.Username,
			labName:        options.LabName,
			containerName:  spec.ContainerName,
			interfaceNames: append([]string(nil), spec.InterfaceNames...),
			containerID:    containerID,
			port:           port,
			showVolumeTip:  strings.TrimSpace(spec.LabDirectory) != "",
			createdAt:      now,
			expiresAt:      now.Add(m.cfg.WiresharkSessionTTL),
			lastAccess:     now,
		}

		m.mu.Lock()
		m.sessions[session.id] = session
		m.mu.Unlock()

		created = append(created, session)
		infos = append(infos, session.toInfo())
	}

	if len(infos) == 0 {
		return nil, errors.New("no wireshark sessions were created")
	}
	return infos, nil
}

func (m *Manager) CloseSession(
	ctx context.Context,
	sessionID string,
	username string,
	isSuperuser bool,
) error {
	m.mu.Lock()
	session, ok := m.sessions[sessionID]
	if !ok {
		m.mu.Unlock()
		return ErrSessionNotFound
	}
	if !isSuperuser && session.username != username {
		m.mu.Unlock()
		return ErrSessionForbidden
	}
	delete(m.sessions, sessionID)
	m.mu.Unlock()

	return m.stopWiresharkContainer(ctx, session.containerID)
}

func (m *Manager) CloseAllSessions(
	ctx context.Context,
	username string,
	isSuperuser bool,
) (int, error) {
	if !isSuperuser && strings.TrimSpace(username) == "" {
		return 0, errors.New("username is required")
	}

	m.mu.Lock()
	pending := make([]*wiresharkSession, 0, len(m.sessions))
	for sessionID, session := range m.sessions {
		if !isSuperuser && session.username != username {
			continue
		}
		pending = append(pending, session)
		delete(m.sessions, sessionID)
	}
	m.mu.Unlock()

	if len(pending) == 0 {
		return 0, nil
	}

	errs := make([]string, 0)
	for _, session := range pending {
		if err := m.stopWiresharkContainer(ctx, session.containerID); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", session.id, err))
		}
	}

	if len(errs) > 0 {
		return len(pending), fmt.Errorf("failed stopping some sessions: %s", strings.Join(errs, "; "))
	}

	return len(pending), nil
}

func (m *Manager) SessionReady(
	ctx context.Context,
	sessionID string,
	username string,
	isSuperuser bool,
) (bool, string, error) {
	session, err := m.lookupSession(sessionID, username, isSuperuser)
	if err != nil {
		return false, "", err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("http://127.0.0.1:%d", session.port),
		nil,
	)
	if err != nil {
		return false, "", err
	}

	res, err := m.client.Do(req)
	if err == nil {
		_ = res.Body.Close()
	}
	ready := err == nil && res.StatusCode >= 200 && res.StatusCode < 500
	return ready, session.toInfo().VncPath, nil
}

func (m *Manager) ResolveProxyTarget(
	sessionID string,
	username string,
	isSuperuser bool,
) (string, error) {
	session, err := m.lookupSession(sessionID, username, isSuperuser)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("http://127.0.0.1:%d", session.port), nil
}

func (m *Manager) lookupSession(sessionID, username string, isSuperuser bool) (*wiresharkSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	if !isSuperuser && session.username != username {
		return nil, ErrSessionForbidden
	}
	session.lastAccess = time.Now().UTC()
	return session, nil
}

func (m *Manager) cleanupCreatedSessions(ctx context.Context, sessions []*wiresharkSession) {
	for _, session := range sessions {
		if session == nil {
			continue
		}
		m.mu.Lock()
		delete(m.sessions, session.id)
		m.mu.Unlock()
		if err := m.stopWiresharkContainer(ctx, session.containerID); err != nil {
			log.Warnf("capture cleanup: failed stopping session '%s': %v", session.id, err)
		}
	}
}

func (m *Manager) ensureImageAvailable(ctx context.Context) error {
	policy := pullPolicy(strings.ToLower(strings.TrimSpace(m.cfg.WiresharkPullPolicy)))
	image := strings.TrimSpace(m.cfg.WiresharkDockerImage)
	if image == "" {
		return errors.New("wireshark docker image is not configured")
	}

	runtime := m.runtimeBinary()
	switch policy {
	case pullPolicyAlways:
		_, err := m.runner.Run(ctx, runtime, []string{"pull", image}, nil)
		if err != nil {
			return fmt.Errorf("failed pulling wireshark image: %w", err)
		}
	case pullPolicyMissing:
		_, err := m.runner.Run(ctx, runtime, []string{"image", "inspect", image}, nil)
		if err == nil {
			return nil
		}
		_, err = m.runner.Run(ctx, runtime, []string{"pull", image}, nil)
		if err != nil {
			return fmt.Errorf("failed pulling wireshark image: %w", err)
		}
	case pullPolicyNever:
		// no-op
	default:
		return fmt.Errorf("unsupported wireshark pull policy: %s", m.cfg.WiresharkPullPolicy)
	}

	return nil
}

type startWiresharkOptions struct {
	containerName  string
	packetflixURI  string
	darkMode       bool
	localPort      int
	labDir         string
	edgesharkNet   string
	wiresharkImage string
}

func (m *Manager) startWiresharkContainer(
	ctx context.Context,
	options startWiresharkOptions,
) (string, error) {
	runtime := m.runtimeBinary()
	args := []string{
		"run",
		"-d",
		"--rm",
		"--name", options.containerName,
		"-p", fmt.Sprintf("127.0.0.1:%d:5800", options.localPort),
	}
	if strings.TrimSpace(options.edgesharkNet) == "" {
		args = append(args, wiresharkHostGatewayRunArgs(runtime)...)
	}
	if strings.TrimSpace(options.labDir) != "" {
		args = append(args, "-v", fmt.Sprintf("%s:/pcaps", options.labDir))
	}
	args = append(args, "-e", fmt.Sprintf("PACKETFLIX_LINK=%s", options.packetflixURI))
	if options.darkMode {
		args = append(args, "-e", "DARK_MODE=1")
	}
	args = append(args, options.wiresharkImage)

	out, err := m.runner.Run(ctx, runtime, args, nil)
	if err != nil {
		return "", fmt.Errorf("failed starting wireshark container: %w", err)
	}

	containerID := strings.TrimSpace(firstLine(out))
	if containerID == "" {
		return "", errors.New("runtime did not return a container id")
	}
	if err := m.connectWiresharkContainerNetwork(ctx, containerID, options.edgesharkNet); err != nil {
		_ = m.stopWiresharkContainer(ctx, containerID)
		return "", err
	}
	return containerID, nil
}

func (m *Manager) connectWiresharkContainerNetwork(ctx context.Context, containerID, networkName string) error {
	containerID = strings.TrimSpace(containerID)
	networkName = strings.TrimSpace(networkName)
	if containerID == "" || networkName == "" {
		return nil
	}
	runtime := m.runtimeBinary()
	_, err := m.runner.Run(ctx, runtime, []string{"network", "connect", networkName, containerID}, nil)
	if err != nil {
		return fmt.Errorf("failed connecting wireshark container to edgeshark network: %w", err)
	}
	return nil
}

func (m *Manager) stopWiresharkContainer(ctx context.Context, containerID string) error {
	containerID = strings.TrimSpace(containerID)
	if containerID == "" {
		return nil
	}
	runtime := m.runtimeBinary()
	_, err := m.runner.Run(ctx, runtime, []string{"rm", "-f", containerID}, nil)
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "no such container") || strings.Contains(lower, "not found") {
			return nil
		}
		return err
	}
	return nil
}

func (m *Manager) findEdgeSharkNetwork(ctx context.Context) (string, error) {
	runtime := m.runtimeBinary()
	out, err := m.runner.Run(
		ctx,
		runtime,
		[]string{"ps", "--filter", "name=edgeshark", "--format", "{{.ID}}"},
		nil,
	)
	if err != nil {
		return "", nil
	}

	containerID := strings.TrimSpace(firstLine(out))
	if containerID == "" {
		return "", nil
	}

	inspectOut, err := m.runner.Run(ctx, runtime, []string{"inspect", containerID}, nil)
	if err != nil {
		return "", nil
	}

	var payload []map[string]any
	if err := json.Unmarshal([]byte(inspectOut), &payload); err != nil || len(payload) == 0 {
		return "", nil
	}

	networks := extractNetworkNames(payload[0])
	if len(networks) == 0 {
		return "", nil
	}
	sort.Strings(networks)
	for _, networkName := range networks {
		if strings.Contains(strings.ToLower(networkName), "edgeshark") {
			return networkName, nil
		}
	}
	for _, networkName := range networks {
		if !isDefaultRuntimeNetworkName(networkName) {
			return networkName, nil
		}
	}
	return "", nil
}

func isDefaultRuntimeNetworkName(networkName string) bool {
	switch strings.ToLower(strings.TrimSpace(networkName)) {
	case "", "bridge", "host", "none", "podman":
		return true
	default:
		return false
	}
}

func extractNetworkNames(inspectObject map[string]any) []string {
	networkSettingsRaw, ok := inspectObject["NetworkSettings"]
	if !ok {
		return nil
	}
	networkSettings, ok := networkSettingsRaw.(map[string]any)
	if !ok {
		return nil
	}
	networksRaw, ok := networkSettings["Networks"]
	if !ok {
		return nil
	}
	networksMap, ok := networksRaw.(map[string]any)
	if !ok {
		return nil
	}

	names := make([]string, 0, len(networksMap))
	for key := range networksMap {
		if strings.TrimSpace(key) != "" {
			names = append(names, key)
		}
	}
	return names
}

func (m *Manager) prepareEdgesharkComposeFile(
	ctx context.Context,
) (string, func(), error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, edgesharkComposeURL, nil)
	if err != nil {
		return "", func() {}, err
	}
	downloadClient := &http.Client{Timeout: 30 * time.Second}
	res, err := downloadClient.Do(req)
	if err != nil {
		return "", func() {}, fmt.Errorf("failed to download edgeshark compose file: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", func() {}, fmt.Errorf("failed to download edgeshark compose file: status %d", res.StatusCode)
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return "", func() {}, fmt.Errorf("failed to read edgeshark compose file: %w", err)
	}

	extraEnv := parseExtraEnvVars(m.cfg.EdgesharkExtraEnvVars)
	if len(extraEnv) > 0 {
		data, err = injectComposeEnvironment(data, extraEnv)
		if err != nil {
			return "", func() {}, err
		}
	}

	tmpFile, err := os.CreateTemp("", "edgeshark-compose-*.yaml")
	if err != nil {
		return "", func() {}, fmt.Errorf("failed creating temporary compose file: %w", err)
	}

	cleanup := func() {
		_ = os.Remove(tmpFile.Name())
	}

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("failed writing temporary compose file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("failed closing temporary compose file: %w", err)
	}

	return tmpFile.Name(), cleanup, nil
}

func parseExtraEnvVars(raw string) map[string]string {
	result := make(map[string]string)
	for _, piece := range strings.Split(raw, ",") {
		entry := strings.TrimSpace(piece)
		if entry == "" {
			continue
		}

		parts := strings.SplitN(entry, "=", 2)
		key := strings.TrimSpace(parts[0])
		if key == "" {
			continue
		}
		value := ""
		if len(parts) == 2 {
			value = strings.TrimSpace(parts[1])
		}
		result[key] = value
	}
	return result
}

func injectComposeEnvironment(composeYAML []byte, extraEnv map[string]string) ([]byte, error) {
	if len(extraEnv) == 0 {
		return composeYAML, nil
	}

	var payload map[string]any
	if err := yaml.Unmarshal(composeYAML, &payload); err != nil {
		return nil, fmt.Errorf("failed parsing edgeshark compose yaml: %w", err)
	}

	servicesRaw, ok := payload["services"]
	if !ok {
		return nil, errors.New("edgeshark compose yaml does not define services")
	}
	services, ok := servicesRaw.(map[string]any)
	if !ok {
		return nil, errors.New("edgeshark compose yaml has unsupported services shape")
	}

	for _, serviceName := range []string{"gostwire", "edgeshark"} {
		serviceRaw, ok := services[serviceName]
		if !ok {
			continue
		}
		service, ok := serviceRaw.(map[string]any)
		if !ok {
			continue
		}
		service["environment"] = mergeEnvironmentValue(service["environment"], extraEnv)
		services[serviceName] = service
	}
	payload["services"] = services

	out, err := yaml.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed serializing edgeshark compose yaml: %w", err)
	}
	return out, nil
}

func mergeEnvironmentValue(current any, extra map[string]string) []string {
	merged := make(map[string]string)

	switch value := current.(type) {
	case []any:
		for _, entryRaw := range value {
			entry, ok := entryRaw.(string)
			if !ok {
				continue
			}
			pair := strings.SplitN(entry, "=", 2)
			key := strings.TrimSpace(pair[0])
			if key == "" {
				continue
			}
			val := ""
			if len(pair) == 2 {
				val = pair[1]
			}
			merged[key] = val
		}
	case map[string]any:
		for key, valRaw := range value {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			merged[key] = fmt.Sprint(valRaw)
		}
	case map[string]string:
		for key, val := range value {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			merged[key] = val
		}
	}

	for key, value := range extra {
		merged[key] = value
	}

	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, fmt.Sprintf("%s=%s", key, merged[key]))
	}
	return result
}

func (m *Manager) sessionSweeper() {
	ticker := time.NewTicker(defaultSessionSweepInterval)
	defer ticker.Stop()
	defer close(m.doneCh)

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.sweepExpiredSessions()
		}
	}
}

func (m *Manager) sweepExpiredSessions() {
	now := time.Now().UTC()
	expired := make([]*wiresharkSession, 0)

	m.mu.Lock()
	for id, session := range m.sessions {
		if now.After(session.expiresAt) {
			expired = append(expired, session)
			delete(m.sessions, id)
		}
	}
	m.mu.Unlock()

	if len(expired) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, session := range expired {
		if err := m.stopWiresharkContainer(ctx, session.containerID); err != nil {
			log.Warnf("capture sweeper: failed stopping expired session '%s': %v", session.id, err)
		}
	}
}

func (m *Manager) runtimeBinary() string {
	switch strings.ToLower(strings.TrimSpace(m.cfg.Runtime)) {
	case "docker":
		return "docker"
	case "podman":
		return "podman"
	default:
		return "docker"
	}
}

func (m *Manager) resolveRemoteHostname(explicit string) string {
	if trimmed := strings.TrimSpace(explicit); trimmed != "" {
		return trimmed
	}
	if trimmed := strings.TrimSpace(m.cfg.RemoteHostname); trimmed != "" {
		return trimmed
	}
	return "localhost"
}

func reserveLocalPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("failed reserving localhost port: %w", err)
	}
	defer listener.Close()

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || addr.Port <= 0 {
		return 0, errors.New("failed determining reserved localhost port")
	}
	return addr.Port, nil
}

func bracketHostname(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return "localhost"
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

func buildPacketflixURI(
	host string,
	packetflixPort int,
	containerName string,
	interfaceNames []string,
	netnsID uint64,
) string {
	containerPayload := map[string]any{
		"network-interfaces": interfaceNames,
	}
	if netnsID != 0 {
		containerPayload["netns"] = netnsID
	} else {
		containerPayload["name"] = containerName
		containerPayload["type"] = "docker"
	}
	containerJSON, _ := json.Marshal(containerPayload)
	containerQuery := urlEncode(string(containerJSON))
	nif := urlEncode(strings.Join(interfaceNames, "/"))
	return fmt.Sprintf(
		"packetflix:ws://%s:%d/capture?container=%s&nif=%s",
		host,
		packetflixPort,
		containerQuery,
		nif,
	)
}

func buildPacketflixURIForSpec(
	host string,
	packetflixPort int,
	spec ContainerCaptureSpec,
) (string, error) {
	var netnsID uint64
	if spec.HostNetworkNamespace {
		var err error
		netnsID, err = currentNetworkNamespaceID()
		if err != nil {
			return "", fmt.Errorf("failed resolving host network namespace: %w", err)
		}
	}

	return buildPacketflixURI(
		host,
		packetflixPort,
		spec.ContainerName,
		spec.InterfaceNames,
		netnsID,
	), nil
}

func currentNetworkNamespaceID() (uint64, error) {
	target, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return 0, err
	}

	const prefix = "net:["
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, "]") {
		return 0, fmt.Errorf("unexpected network namespace link %q", target)
	}

	return strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, prefix), "]"), 10, 64)
}

func wiresharkPacketflixHost(runtime string, hasEdgeSharkNetwork bool) string {
	if hasEdgeSharkNetwork {
		return "edgeshark-edgeshark-1"
	}
	switch strings.ToLower(strings.TrimSpace(runtime)) {
	case "podman":
		return "host.containers.internal"
	default:
		return "host.docker.internal"
	}
}

func wiresharkHostGatewayRunArgs(runtime string) []string {
	if strings.ToLower(strings.TrimSpace(runtime)) != "docker" {
		return nil
	}
	return []string{"--add-host", "host.docker.internal:host-gateway"}
}

func buildWiresharkContainerName(username, containerName string, interfaceNames []string) string {
	joinedInterfaces := strings.Join(interfaceNames, "_")
	raw := fmt.Sprintf(
		"clab_ws_vnc_%s_%s_%s_%d",
		username,
		containerName,
		joinedInterfaces,
		time.Now().UnixMilli(),
	)
	sanitized := sanitizeContainerNameRx.ReplaceAllString(raw, "-")
	if len(sanitized) > 128 {
		return sanitized[:128]
	}
	return sanitized
}

func randomSessionID() string {
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err == nil {
		return fmt.Sprintf("%x", buffer)
	}
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func firstLine(value string) string {
	if value == "" {
		return ""
	}
	parts := strings.Split(value, "\n")
	return strings.TrimSpace(parts[0])
}

func urlEncode(value string) string {
	return url.QueryEscape(value)
}

func (s *wiresharkSession) toInfo() WiresharkSessionInfo {
	return WiresharkSessionInfo{
		SessionID:      s.id,
		LabName:        s.labName,
		ContainerName:  s.containerName,
		InterfaceNames: append([]string(nil), s.interfaceNames...),
		VncPath:        fmt.Sprintf("/api/v1/capture/wireshark-vnc-sessions/%s/vnc/", s.id),
		ShowVolumeTip:  s.showVolumeTip,
		CreatedAt:      s.createdAt,
		ExpiresAt:      s.expiresAt,
	}
}

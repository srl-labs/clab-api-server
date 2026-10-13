package terminal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/creack/pty"
	clabcore "github.com/srl-labs/containerlab/core"
	clabnodes "github.com/srl-labs/containerlab/nodes"

	"github.com/srl-labs/clab-api-server/internal/models"
)

const (
	DefaultCleanupTick        = time.Minute
	DefaultSessionTTL         = time.Hour
	DefaultIdleTimeout        = 15 * time.Minute
	DefaultMaxSessionsPerUser = 128
	DefaultTerminalCols       = 120
	DefaultTerminalRows       = 36
	DefaultTelnetPort         = 5000
)

var (
	ErrSessionNotFound   = errors.New("terminal session not found")
	ErrSessionForbidden  = errors.New("terminal session not owned by user")
	ErrSessionAttached   = errors.New("terminal session already has an active client")
	ErrTooManySessions   = errors.New("too many terminal sessions for user")
	ErrSessionExited     = errors.New("terminal session has already exited")
	validSSHUsernameExpr = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$`)
)

var defaultShellCommandsByKind = map[string][]string{
	"nokia_srlinux": {"sr_cli"},
	"cisco_xrd":     {"/pkg/bin/xr_cli.sh"},
	"frr":           {"vtysh"},
	"frrouting":     {"vtysh"},
}

// kindRegistry holds containerlab's node kinds, whose default credentials are
// the users images ship for SSH logins.
var kindRegistry = sync.OnceValue(func() *clabnodes.NodeRegistry {
	lab := &clabcore.CLab{Reg: clabnodes.NewNodeRegistry()}
	lab.RegisterNodes()
	return lab.Reg
})

// defaultSSHUsername returns the default login user of a node kind.
func defaultSSHUsername(kind string) string {
	entry := kindRegistry().Kind(strings.TrimSpace(kind))
	if entry == nil {
		return ""
	}
	credentials := entry.GetCredentials()
	if credentials == nil {
		return ""
	}
	return credentials.GetUsername()
}

type CreateSessionOptions struct {
	Username      string
	LabName       string
	NodeName      string
	ContainerID   string
	ContainerIP   string
	ContainerKind string
	Runtime       string
	Protocol      models.TerminalProtocol
	Cols          int
	Rows          int
	SSHUsername   string
	TelnetPort    int
}

type Manager struct {
	mu          sync.RWMutex
	sessions    map[string]*Session
	pending     map[string]int
	cleanupTick time.Duration
	sessionTTL  time.Duration
	idleTimeout time.Duration
	maxPerUser  int
	stopCh      chan struct{}
	stoppedCh   chan struct{}
}

type Session struct {
	manager *Manager

	mu           sync.RWMutex
	id           string
	username     string
	labName      string
	nodeName     string
	protocol     models.TerminalProtocol
	createdAt    time.Time
	expiresAt    time.Time
	lastActivity time.Time
	state        string
	lastError    string
	exitCode     *int
	attached     bool

	cmd     *exec.Cmd
	ptyFile *os.File
	doneCh  chan struct{}
}

func NewManager(cleanupTick, sessionTTL, idleTimeout time.Duration, maxPerUser int) *Manager {
	if cleanupTick <= 0 {
		cleanupTick = DefaultCleanupTick
	}
	if sessionTTL <= 0 {
		sessionTTL = DefaultSessionTTL
	}
	if idleTimeout <= 0 {
		idleTimeout = DefaultIdleTimeout
	}
	if maxPerUser <= 0 {
		maxPerUser = DefaultMaxSessionsPerUser
	}

	m := &Manager{
		sessions:    make(map[string]*Session),
		pending:     make(map[string]int),
		cleanupTick: cleanupTick,
		sessionTTL:  sessionTTL,
		idleTimeout: idleTimeout,
		maxPerUser:  maxPerUser,
		stopCh:      make(chan struct{}),
		stoppedCh:   make(chan struct{}),
	}

	go m.runCleanup()
	return m
}

func (m *Manager) Shutdown() {
	close(m.stopCh)
	<-m.stoppedCh

	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.mu.Unlock()

	for _, session := range sessions {
		session.Terminate("server shutdown")
		_ = session.WaitForExit(2 * time.Second)
	}
}

func (m *Manager) CreateSession(opts CreateSessionOptions) (*models.TerminalSessionInfo, error) {
	protocol, err := normalizeProtocol(opts.Protocol)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(opts.Username) == "" {
		return nil, fmt.Errorf("username is required")
	}
	if strings.TrimSpace(opts.LabName) == "" {
		return nil, fmt.Errorf("lab name is required")
	}
	if strings.TrimSpace(opts.NodeName) == "" {
		return nil, fmt.Errorf("node name is required")
	}
	if strings.TrimSpace(opts.ContainerID) == "" {
		return nil, fmt.Errorf("container ID is required")
	}
	if protocol == models.TerminalProtocolSSH && strings.TrimSpace(opts.ContainerIP) == "" {
		return nil, fmt.Errorf("container management IP is required for SSH")
	}

	cols, rows := sanitizeTerminalSize(opts.Cols, opts.Rows)
	command, err := resolveLaunchCommand(protocol, opts)
	if err != nil {
		return nil, err
	}

	username := strings.TrimSpace(opts.Username)
	if err := m.reserveUserSessionCapacity(username); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	session := &Session{
		manager:      m,
		id:           newSessionID(),
		username:     username,
		labName:      strings.TrimSpace(opts.LabName),
		nodeName:     strings.TrimSpace(opts.NodeName),
		protocol:     protocol,
		createdAt:    now,
		expiresAt:    now.Add(m.sessionTTL),
		lastActivity: now,
		state:        "ready",
		doneCh:       make(chan struct{}),
	}

	cmd := exec.CommandContext(context.Background(), command[0], command[1:]...)
	cmd.Env = minimalCommandEnv()
	cmd.Dir = "/"

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Cols: uint16(cols),
		Rows: uint16(rows),
	})
	if err != nil {
		m.releaseUserSessionCapacity(username)
		return nil, fmt.Errorf("failed to start terminal session: %w", err)
	}

	session.cmd = cmd
	session.ptyFile = ptmx

	m.mu.Lock()
	m.releaseUserSessionCapacityLocked(session.username)
	m.sessions[session.id] = session
	m.mu.Unlock()

	go session.waitForProcess()

	log.Infof(
		"terminal session created: user=%s lab=%s node=%s protocol=%s session=%s",
		session.username,
		session.labName,
		session.nodeName,
		session.protocol,
		session.id,
	)

	info := session.Snapshot()
	return &info, nil
}

func (m *Manager) reserveUserSessionCapacity(username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.countSessionsForUserLocked(username)+m.pending[username] >= m.maxPerUser {
		return ErrTooManySessions
	}
	m.pending[username]++
	return nil
}

func (m *Manager) releaseUserSessionCapacity(username string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releaseUserSessionCapacityLocked(username)
}

func (m *Manager) releaseUserSessionCapacityLocked(username string) {
	if m.pending[username] <= 1 {
		delete(m.pending, username)
		return
	}
	m.pending[username]--
}

func (m *Manager) GetSessionInfo(sessionID, username string, allowAll bool) (*models.TerminalSessionInfo, error) {
	session, err := m.lookupSession(sessionID, username, allowAll)
	if err != nil {
		return nil, err
	}
	info := session.Snapshot()
	return &info, nil
}

func (m *Manager) TerminateSession(sessionID, username string, allowAll bool) error {
	session, err := m.lookupSession(sessionID, username, allowAll)
	if err != nil {
		return err
	}
	session.Terminate("session terminated")
	return nil
}

func (m *Manager) BeginStream(sessionID, username string, allowAll bool) (*Session, error) {
	session, err := m.lookupSession(sessionID, username, allowAll)
	if err != nil {
		return nil, err
	}
	if err := session.beginStream(); err != nil {
		return nil, err
	}
	return session, nil
}

func (m *Manager) lookupSession(sessionID, username string, allowAll bool) (*Session, error) {
	m.mu.RLock()
	session := m.sessions[sessionID]
	m.mu.RUnlock()
	if session == nil {
		return nil, ErrSessionNotFound
	}

	session.mu.RLock()
	owner := session.username
	session.mu.RUnlock()
	if !allowAll && owner != username {
		return nil, ErrSessionForbidden
	}
	return session, nil
}

func (m *Manager) countSessionsForUserLocked(username string) int {
	count := 0
	for _, session := range m.sessions {
		session.mu.RLock()
		owner := session.username
		state := session.state
		session.mu.RUnlock()
		if owner == username && state != "closed" {
			count++
		}
	}
	return count
}

func (m *Manager) runCleanup() {
	ticker := time.NewTicker(m.cleanupTick)
	defer func() {
		ticker.Stop()
		close(m.stoppedCh)
	}()

	for {
		select {
		case <-ticker.C:
			m.cleanupExpiredSessions()
		case <-m.stopCh:
			return
		}
	}
}

func (m *Manager) cleanupExpiredSessions() {
	now := time.Now().UTC()

	m.mu.RLock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.mu.RUnlock()

	for _, session := range sessions {
		session.mu.RLock()
		state := session.state
		attached := session.attached
		expiresAt := session.expiresAt
		lastActivity := session.lastActivity
		session.mu.RUnlock()

		if now.After(expiresAt) {
			session.Terminate("session TTL expired")
			continue
		}
		if !attached && state == "ready" && now.Sub(lastActivity) > m.idleTimeout {
			session.Terminate("session idle timeout")
			continue
		}
		if state == "closed" && now.Sub(lastActivity) > m.cleanupTick {
			m.mu.Lock()
			if current := m.sessions[session.id]; current == session {
				delete(m.sessions, session.id)
			}
			m.mu.Unlock()
		}
	}
}

func (s *Session) beginStream() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == "closed" {
		return ErrSessionExited
	}
	if s.attached {
		return ErrSessionAttached
	}

	s.attached = true
	s.lastActivity = time.Now().UTC()
	return nil
}

func (s *Session) EndStream() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attached = false
	s.lastActivity = time.Now().UTC()
}

func (s *Session) Read(p []byte) (int, error) {
	s.mu.RLock()
	file := s.ptyFile
	s.mu.RUnlock()
	if file == nil {
		return 0, io.EOF
	}
	n, err := file.Read(p)
	if n > 0 {
		s.markActivity()
	}
	return n, err
}

func (s *Session) WriteInput(input string) error {
	s.mu.RLock()
	file := s.ptyFile
	s.mu.RUnlock()
	if file == nil {
		return io.EOF
	}
	s.markActivity()
	_, err := file.WriteString(input)
	return err
}

func (s *Session) Resize(cols, rows int) error {
	s.mu.RLock()
	file := s.ptyFile
	s.mu.RUnlock()
	if file == nil {
		return io.EOF
	}
	s.markActivity()
	sanitizedCols, sanitizedRows := sanitizeTerminalSize(cols, rows)
	return pty.Setsize(file, &pty.Winsize{
		Cols: uint16(sanitizedCols),
		Rows: uint16(sanitizedRows),
	})
}

func (s *Session) markActivity() {
	s.mu.Lock()
	s.lastActivity = time.Now().UTC()
	s.mu.Unlock()
}

func (s *Session) Snapshot() models.TerminalSessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return models.TerminalSessionInfo{
		SessionID:    s.id,
		Username:     s.username,
		LabName:      s.labName,
		NodeName:     s.nodeName,
		Protocol:     s.protocol,
		State:        s.state,
		CreatedAt:    s.createdAt,
		ExpiresAt:    s.expiresAt,
		LastActivity: s.lastActivity,
		ExitCode:     s.exitCode,
		Error:        s.lastError,
	}
}

func (s *Session) waitForProcess() {
	defer close(s.doneCh)

	err := s.cmd.Wait()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	} else if s.cmd.ProcessState != nil {
		exitCode = s.cmd.ProcessState.ExitCode()
	}

	s.mu.Lock()
	if s.exitCode == nil {
		s.exitCode = &exitCode
	}
	if err != nil && !errors.Is(err, os.ErrClosed) {
		s.lastError = err.Error()
	}
	s.state = "closed"
	s.attached = false
	s.lastActivity = time.Now().UTC()
	file := s.ptyFile
	s.ptyFile = nil
	s.mu.Unlock()

	if file != nil {
		_ = file.Close()
	}

	log.Infof(
		"terminal session closed: user=%s lab=%s node=%s protocol=%s session=%s exitCode=%d",
		s.username,
		s.labName,
		s.nodeName,
		s.protocol,
		s.id,
		exitCode,
	)
}

func (s *Session) WaitForExit(timeout time.Duration) error {
	select {
	case <-s.doneCh:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("timed out waiting for terminal session to exit")
	}
}

func (s *Session) Terminate(reason string) {
	s.mu.Lock()
	if s.state == "closed" {
		s.mu.Unlock()
		return
	}
	s.state = "closing"
	s.lastError = reason
	s.lastActivity = time.Now().UTC()
	file := s.ptyFile
	proc := s.cmd.Process
	s.mu.Unlock()

	if file != nil {
		_ = file.Close()
	}
	if proc != nil {
		_ = proc.Signal(syscall.SIGHUP)
		time.AfterFunc(750*time.Millisecond, func() {
			_ = proc.Kill()
		})
	}
}

func sanitizeTerminalSize(cols, rows int) (int, int) {
	if cols < 40 || cols > 400 {
		cols = DefaultTerminalCols
	}
	if rows < 12 || rows > 200 {
		rows = DefaultTerminalRows
	}
	return cols, rows
}

func normalizeProtocol(protocol models.TerminalProtocol) (models.TerminalProtocol, error) {
	switch models.TerminalProtocol(strings.ToLower(strings.TrimSpace(string(protocol)))) {
	case models.TerminalProtocolSSH:
		return models.TerminalProtocolSSH, nil
	case models.TerminalProtocolShell:
		return models.TerminalProtocolShell, nil
	case models.TerminalProtocolTelnet:
		return models.TerminalProtocolTelnet, nil
	default:
		return "", fmt.Errorf("unsupported terminal protocol %q", protocol)
	}
}

func resolveLaunchCommand(protocol models.TerminalProtocol, opts CreateSessionOptions) ([]string, error) {
	switch protocol {
	case models.TerminalProtocolSSH:
		ip := stripCIDRSuffix(opts.ContainerIP)
		if ip == "" {
			return nil, fmt.Errorf("container management IP is required for SSH")
		}
		username := resolveSSHUsername(opts.ContainerKind, opts.SSHUsername)
		return []string{
			"ssh",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "GlobalKnownHostsFile=/dev/null",
			"-o", "LogLevel=ERROR",
			"-o", "ServerAliveInterval=30",
			"-o", "ServerAliveCountMax=3",
			fmt.Sprintf("%s@%s", username, ip),
		}, nil
	case models.TerminalProtocolShell:
		command := resolveShellCommand(opts.ContainerKind)
		return append([]string{resolveRuntime(opts.Runtime), "exec", "-it", opts.ContainerID}, command...), nil
	case models.TerminalProtocolTelnet:
		port := opts.TelnetPort
		if port <= 0 || port > 65535 {
			port = DefaultTelnetPort
		}
		return []string{
			resolveRuntime(opts.Runtime),
			"exec",
			"-it",
			opts.ContainerID,
			"telnet",
			"127.0.0.1",
			fmt.Sprintf("%d", port),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported terminal protocol %q", protocol)
	}
}

func resolveShellCommand(kind string) []string {
	if command, ok := defaultShellCommandsByKind[strings.TrimSpace(kind)]; ok && len(command) > 0 {
		return append([]string(nil), command...)
	}
	return []string{"sh"}
}

func resolveSSHUsername(kind, requested string) string {
	if trimmed := strings.TrimSpace(requested); validSSHUsernameExpr.MatchString(trimmed) {
		return trimmed
	}
	if username := defaultSSHUsername(kind); username != "" {
		return username
	}
	return "admin"
}

func resolveRuntime(runtime string) string {
	if trimmed := strings.TrimSpace(runtime); trimmed != "" {
		return trimmed
	}
	return "docker"
}

func stripCIDRSuffix(ip string) string {
	trimmed := strings.TrimSpace(ip)
	if trimmed == "" {
		return ""
	}
	if slash := strings.IndexByte(trimmed, '/'); slash >= 0 {
		return trimmed[:slash]
	}
	return trimmed
}

func minimalCommandEnv() []string {
	return []string{
		"HOME=/tmp",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TERM=xterm-256color",
	}
}

func newSessionID() string {
	var buffer [16]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		panic(fmt.Errorf("failed to generate terminal session ID: %w", err))
	}
	return hex.EncodeToString(buffer[:])
}

package terminal

import (
	"bytes"
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
	DefaultCleanupTick = time.Minute
	DefaultSessionTTL  = 12 * time.Hour
	// DefaultIdleTimeout ends a resumable session this long after its last client left.
	DefaultIdleTimeout        = 30 * time.Minute
	DefaultMaxSessionsPerUser = 128
	DefaultTerminalCols       = 120
	DefaultTerminalRows       = 36
	DefaultTelnetPort         = 5000
	// DefaultScrollbackBytes is the recent output a session replays to a client that attaches again.
	DefaultScrollbackBytes = 256 * 1024

	// attachmentBufferChunks is the output a client may fall behind by before it is detached.
	attachmentBufferChunks = 512
	// exitDrainTimeout is how long the final output may take to arrive after the process exited.
	exitDrainTimeout = time.Second
)

// Why an attachment ended.
const (
	DetachReasonClientLeft = "client left"
	DetachReasonTakenOver  = "attached elsewhere"
	DetachReasonSlowClient = "client too slow"
	DetachReasonExited     = "session ended"
)

var (
	ErrSessionNotFound   = errors.New("terminal session not found")
	ErrSessionForbidden  = errors.New("terminal session not owned by user")
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
	// Resumable keeps the session running after its client left. Other
	// sessions end with their client, which is what clients that never attach
	// again expect.
	Resumable bool
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

// Session is a terminal process on the server. A resumable session keeps
// running while no client is attached, and remembers its recent output for the
// next client.
type Session struct {
	manager *Manager

	mu           sync.RWMutex
	id           string
	username     string
	labName      string
	nodeName     string
	protocol     models.TerminalProtocol
	resumable    bool
	createdAt    time.Time
	expiresAt    time.Time
	lastActivity time.Time
	// detachedAt is when the last client left, or the creation time.
	detachedAt time.Time
	state      string
	lastError  string
	exitCode   *int
	attachment *Attachment
	scrollback scrollback

	cmd      *exec.Cmd
	ptyFile  *os.File
	pumpDone chan struct{}
	doneCh   chan struct{}
}

// Attachment is one client's connection to a session. Its output channel
// closes when the attachment ends; Reason says why.
type Attachment struct {
	// Replay is the session's recent output, to show before Output.
	Replay []byte
	output chan []byte
	reason string
	ended  bool
}

// Output delivers the session's output after Replay.
func (a *Attachment) Output() <-chan []byte {
	return a.output
}

// Reason says why the attachment ended. Read it once Output is closed.
func (a *Attachment) Reason() string {
	return a.reason
}

// scrollback keeps the most recent terminal output, up to limit bytes.
type scrollback struct {
	data  []byte
	limit int
}

func (b *scrollback) write(p []byte) {
	b.data = append(b.data, p...)
	// Compact only at twice the limit, so a write costs O(1) on average.
	if len(b.data) > 2*b.limit {
		b.data = append([]byte(nil), b.data[len(b.data)-b.limit:]...)
	}
}

// bytes returns the kept output, from the start of a line where the oldest output was cut.
func (b *scrollback) bytes() []byte {
	data := b.data
	if over := len(data) - b.limit; over > 0 {
		data = data[over:]
		if i := bytes.IndexByte(data[:min(len(data), 4096)], '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	return append([]byte(nil), data...)
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

	command, err := resolveLaunchCommand(protocol, opts)
	if err != nil {
		return nil, err
	}
	opts.Protocol = protocol
	return m.startSession(opts, command)
}

// startSession runs command in a new terminal for the validated options.
func (m *Manager) startSession(opts CreateSessionOptions, command []string) (*models.TerminalSessionInfo, error) {
	cols, rows := sanitizeTerminalSize(opts.Cols, opts.Rows)
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
		protocol:     opts.Protocol,
		resumable:    opts.Resumable,
		createdAt:    now,
		expiresAt:    now.Add(m.sessionTTL),
		lastActivity: now,
		detachedAt:   now,
		state:        "ready",
		scrollback:   scrollback{limit: DefaultScrollbackBytes},
		pumpDone:     make(chan struct{}),
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

	go session.pump(ptmx)
	go session.waitForProcess()

	log.Infof(
		"terminal session created: user=%s lab=%s node=%s protocol=%s session=%s resumable=%t",
		session.username,
		session.labName,
		session.nodeName,
		session.protocol,
		session.id,
		session.resumable,
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

// Attach connects a client to a session. A client that is still attached is
// detached, so a reloaded page or a reconnecting client takes the session over.
func (m *Manager) Attach(sessionID, username string, allowAll bool) (*Session, *Attachment, error) {
	session, err := m.lookupSession(sessionID, username, allowAll)
	if err != nil {
		return nil, nil, err
	}
	attachment, err := session.attach()
	if err != nil {
		return nil, nil, err
	}
	return session, attachment, nil
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
		attached := session.attachment != nil
		expiresAt := session.expiresAt
		lastActivity := session.lastActivity
		detachedAt := session.detachedAt
		session.mu.RUnlock()

		if now.After(expiresAt) {
			session.Terminate("session TTL expired")
			continue
		}
		if !attached && state == "ready" && now.Sub(detachedAt) > m.idleTimeout {
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

func (s *Session) attach() (*Attachment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != "ready" {
		return nil, ErrSessionExited
	}
	s.endAttachmentLocked(s.attachment, DetachReasonTakenOver)

	attachment := &Attachment{
		Replay: s.scrollback.bytes(),
		output: make(chan []byte, attachmentBufferChunks),
	}
	s.attachment = attachment
	s.lastActivity = time.Now().UTC()
	return attachment, nil
}

// Detach ends an attachment. A resumable session keeps running for the next
// client; any other session ends with its client.
func (s *Session) Detach(attachment *Attachment) {
	s.mu.Lock()
	orphaned := s.endAttachmentLocked(attachment, DetachReasonClientLeft)
	s.mu.Unlock()
	if orphaned {
		s.Terminate("client disconnected")
	}
}

// endAttachmentLocked reports whether the session lost its client and must
// end because it is not resumable.
func (s *Session) endAttachmentLocked(attachment *Attachment, reason string) bool {
	if attachment == nil || attachment.ended {
		return false
	}
	attachment.ended = true
	attachment.reason = reason
	close(attachment.output)
	if s.attachment != attachment {
		return false
	}
	s.attachment = nil
	s.detachedAt = time.Now().UTC()
	return !s.resumable && (reason == DetachReasonClientLeft || reason == DetachReasonSlowClient)
}

// pump reads the terminal for the whole session, also while no client is
// attached, so the process never blocks on a full terminal.
func (s *Session) pump(file *os.File) {
	defer close(s.pumpDone)
	buffer := make([]byte, 32*1024)
	for {
		n, err := file.Read(buffer)
		if n > 0 {
			chunk := append([]byte(nil), buffer[:n]...)
			orphaned := false
			s.mu.Lock()
			s.scrollback.write(chunk)
			s.lastActivity = time.Now().UTC()
			if attachment := s.attachment; attachment != nil {
				select {
				case attachment.output <- chunk:
				default:
					// A resumable session's client reconnects and gets the output from the scrollback.
					orphaned = s.endAttachmentLocked(attachment, DetachReasonSlowClient)
				}
			}
			s.mu.Unlock()
			if orphaned {
				s.Terminate("client too slow")
			}
		}
		if err != nil {
			return
		}
	}
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
		Resumable:    s.resumable,
		State:        s.state,
		CreatedAt:    s.createdAt,
		ExpiresAt:    s.expiresAt,
		LastActivity: s.lastActivity,
		Attached:     s.attachment != nil,
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

	// Let the pump read the last output. A child that still holds the terminal
	// keeps it open, so stop waiting after a moment.
	select {
	case <-s.pumpDone:
	case <-time.After(exitDrainTimeout):
	}

	s.mu.Lock()
	if s.exitCode == nil {
		s.exitCode = &exitCode
	}
	if err != nil && !errors.Is(err, os.ErrClosed) {
		s.lastError = err.Error()
	}
	s.state = "closed"
	s.lastActivity = time.Now().UTC()
	s.endAttachmentLocked(s.attachment, DetachReasonExited)
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
	// A closing session is already on its way out.
	if s.state != "ready" {
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

package terminal

import (
	"strings"
	"testing"
	"time"

	"github.com/srl-labs/clab-api-server/internal/models"
)

func newTestManager(t *testing.T, maxPerUser int) *Manager {
	t.Helper()
	m := NewManager(time.Hour, time.Hour, time.Hour, maxPerUser)
	t.Cleanup(func() {
		close(m.stopCh)
		<-m.stoppedCh
	})
	return m
}

func TestResolveLaunchCommandShellAllowlist(t *testing.T) {
	command, err := resolveLaunchCommand(models.TerminalProtocolShell, CreateSessionOptions{
		Runtime:       "docker",
		ContainerID:   "cid-123",
		ContainerKind: "nokia_srlinux",
	})
	if err != nil {
		t.Fatalf("resolveLaunchCommand returned unexpected error: %v", err)
	}

	expected := []string{"docker", "exec", "-it", "cid-123", "sr_cli"}
	if strings.Join(command, " ") != strings.Join(expected, " ") {
		t.Fatalf("unexpected shell command: got %v want %v", command, expected)
	}
}

func TestResolveLaunchCommandFallbackShell(t *testing.T) {
	command, err := resolveLaunchCommand(models.TerminalProtocolShell, CreateSessionOptions{
		Runtime:       "podman",
		ContainerID:   "cid-456",
		ContainerKind: "unknown-kind",
	})
	if err != nil {
		t.Fatalf("resolveLaunchCommand returned unexpected error: %v", err)
	}

	expected := []string{"podman", "exec", "-it", "cid-456", "sh"}
	if strings.Join(command, " ") != strings.Join(expected, " ") {
		t.Fatalf("unexpected fallback shell command: got %v want %v", command, expected)
	}
}

func TestResolveLaunchCommandSSHUsesDirectArgv(t *testing.T) {
	command, err := resolveLaunchCommand(models.TerminalProtocolSSH, CreateSessionOptions{
		ContainerIP:   "172.20.20.2/24",
		ContainerKind: "cisco_xrd",
	})
	if err != nil {
		t.Fatalf("resolveLaunchCommand returned unexpected error: %v", err)
	}

	if len(command) == 0 || command[0] != "ssh" {
		t.Fatalf("expected ssh binary, got %v", command)
	}
	for _, disallowed := range []string{"sh", "bash", "-lc", "-c"} {
		for _, part := range command {
			if part == disallowed {
				t.Fatalf("unexpected shell wrapper token %q in %v", disallowed, command)
			}
		}
	}
	if last := command[len(command)-1]; last != "clab@172.20.20.2" {
		t.Fatalf("unexpected ssh target %q", last)
	}
}

func TestResolveLaunchCommandTelnetUsesDirectArgv(t *testing.T) {
	command, err := resolveLaunchCommand(models.TerminalProtocolTelnet, CreateSessionOptions{
		Runtime:     "docker",
		ContainerID: "cid-789",
		TelnetPort:  7001,
	})
	if err != nil {
		t.Fatalf("resolveLaunchCommand returned unexpected error: %v", err)
	}

	expected := []string{"docker", "exec", "-it", "cid-789", "telnet", "127.0.0.1", "7001"}
	if strings.Join(command, " ") != strings.Join(expected, " ") {
		t.Fatalf("unexpected telnet command: got %v want %v", command, expected)
	}
	for _, disallowed := range []string{"ssh", "sh", "bash", "-lc", "-c"} {
		for _, part := range command {
			if part == disallowed {
				t.Fatalf("unexpected shell/ssh wrapper token %q in %v", disallowed, command)
			}
		}
	}
}

func TestResolveLaunchCommandTelnetDefaultsPort(t *testing.T) {
	command, err := resolveLaunchCommand(models.TerminalProtocolTelnet, CreateSessionOptions{
		Runtime:     "podman",
		ContainerID: "cid-999",
		TelnetPort:  0,
	})
	if err != nil {
		t.Fatalf("resolveLaunchCommand returned unexpected error: %v", err)
	}

	expected := []string{"podman", "exec", "-it", "cid-999", "telnet", "127.0.0.1", "5000"}
	if strings.Join(command, " ") != strings.Join(expected, " ") {
		t.Fatalf("unexpected default telnet command: got %v want %v", command, expected)
	}
}

func TestSanitizeTerminalSizeClampsInvalidValues(t *testing.T) {
	cols, rows := sanitizeTerminalSize(0, 500)
	if cols != DefaultTerminalCols {
		t.Fatalf("unexpected cols: got %d want %d", cols, DefaultTerminalCols)
	}
	if rows != DefaultTerminalRows {
		t.Fatalf("unexpected rows: got %d want %d", rows, DefaultTerminalRows)
	}
}

func TestNewManagerDefaultsMaxSessionsPerUser(t *testing.T) {
	m := newTestManager(t, 0)
	if m.maxPerUser != DefaultMaxSessionsPerUser {
		t.Fatalf("unexpected maxPerUser: got %d want %d", m.maxPerUser, DefaultMaxSessionsPerUser)
	}
	if m.maxPerUser != 128 {
		t.Fatalf("unexpected default session limit: got %d want 128", m.maxPerUser)
	}
}

func TestNewManagerUsesConfiguredMaxSessionsPerUser(t *testing.T) {
	m := newTestManager(t, 150)
	if m.maxPerUser != 150 {
		t.Fatalf("unexpected maxPerUser: got %d want 150", m.maxPerUser)
	}
}

func TestReserveUserSessionCapacityRejectsAtConfiguredLimit(t *testing.T) {
	m := newTestManager(t, 2)
	m.sessions["active"] = &Session{username: "alice", state: "ready"}

	if err := m.reserveUserSessionCapacity("alice"); err != nil {
		t.Fatalf("reserve below limit returned unexpected error: %v", err)
	}
	if err := m.reserveUserSessionCapacity("alice"); err != ErrTooManySessions {
		t.Fatalf("reserve at limit returned %v, want %v", err, ErrTooManySessions)
	}
}

func TestReserveUserSessionCapacityIgnoresClosedSessions(t *testing.T) {
	m := newTestManager(t, 1)
	m.sessions["closed"] = &Session{username: "alice", state: "closed"}

	if err := m.reserveUserSessionCapacity("alice"); err != nil {
		t.Fatalf("reserve with only closed sessions returned unexpected error: %v", err)
	}
}

func startTestSession(t *testing.T, m *Manager, script string, resumable bool) *Session {
	t.Helper()
	info, err := m.startSession(CreateSessionOptions{
		Username:  "alice",
		LabName:   "lab",
		NodeName:  "node1",
		Protocol:  models.TerminalProtocolShell,
		Resumable: resumable,
	}, []string{"sh", "-c", script})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}
	session, err := m.lookupSession(info.SessionID, "alice", false)
	if err != nil {
		t.Fatalf("lookupSession: %v", err)
	}
	t.Cleanup(func() {
		session.Terminate("test done")
		_ = session.WaitForExit(2 * time.Second)
	})
	return session
}

// readUntil collects attachment output until it contains want.
func readUntil(t *testing.T, attachment *Attachment, want string) string {
	t.Helper()
	got := string(attachment.Replay)
	deadline := time.After(5 * time.Second)
	for !strings.Contains(got, want) {
		select {
		case chunk, open := <-attachment.Output():
			if !open {
				t.Fatalf("attachment ended (%s) before %q; got %q", attachment.Reason(), want, got)
			}
			got += string(chunk)
		case <-deadline:
			t.Fatalf("timed out waiting for %q; got %q", want, got)
		}
	}
	return got
}

func TestSessionKeepsRunningAndReplaysOutputAfterDetach(t *testing.T) {
	m := newTestManager(t, 4)
	session := startTestSession(t, m, "echo first; read line; echo got-$line; sleep 30", true)
	if !session.Snapshot().Resumable {
		t.Fatalf("session info does not report resumable")
	}

	first, err := session.attach()
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	readUntil(t, first, "first")
	session.Detach(first)
	if session.Snapshot().Attached {
		t.Fatalf("session still attached after detach")
	}

	// Input and output while nobody is attached end up in the scrollback.
	if err := session.WriteInput("again\n"); err != nil {
		t.Fatalf("WriteInput: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	second, err := session.attach()
	if err != nil {
		t.Fatalf("attach again: %v", err)
	}
	replayed := string(second.Replay)
	if !strings.Contains(replayed, "first") || !strings.Contains(replayed, "got-again") {
		t.Fatalf("replay misses earlier output: %q", replayed)
	}
}

func TestAttachTakesOverTheCurrentClient(t *testing.T) {
	m := newTestManager(t, 4)
	// Taking over ends no session, resumable or not.
	session := startTestSession(t, m, "sleep 30", false)

	first, err := session.attach()
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	second, err := session.attach()
	if err != nil {
		t.Fatalf("second attach: %v", err)
	}
	if _, open := <-first.Output(); open {
		t.Fatalf("first attachment still open")
	}
	if first.Reason() != DetachReasonTakenOver {
		t.Fatalf("first attachment ended with %q, want %q", first.Reason(), DetachReasonTakenOver)
	}
	// Detaching the old client must not detach the new one.
	session.Detach(first)
	if snapshot := session.Snapshot(); !snapshot.Attached || snapshot.State != "ready" {
		t.Fatalf("detaching a replaced client detached or ended the session: %+v", snapshot)
	}
	session.Detach(second)
}

func TestSessionWithoutResumeEndsWhenItsClientLeaves(t *testing.T) {
	m := newTestManager(t, 4)
	session := startTestSession(t, m, "sleep 30", false)
	if session.Snapshot().Resumable {
		t.Fatalf("session reports resumable without asking for it")
	}

	attachment, err := session.attach()
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	session.Detach(attachment)
	if err := session.WaitForExit(3 * time.Second); err != nil {
		t.Fatalf("session kept running after its client left: %v", err)
	}
	if state := session.Snapshot().State; state != "closed" {
		t.Fatalf("session state = %q after its client left, want closed", state)
	}
}

func TestAttachmentEndsWhenTheProcessExits(t *testing.T) {
	m := newTestManager(t, 4)
	session := startTestSession(t, m, "read line; echo bye", false)
	attachment, err := session.attach()
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if err := session.WriteInput("x\n"); err != nil {
		t.Fatalf("WriteInput: %v", err)
	}
	readUntil(t, attachment, "bye")
	for range attachment.Output() {
	}
	if attachment.Reason() != DetachReasonExited {
		t.Fatalf("attachment ended with %q, want %q", attachment.Reason(), DetachReasonExited)
	}
	if _, err := session.attach(); err != ErrSessionExited {
		t.Fatalf("attach after exit returned %v, want %v", err, ErrSessionExited)
	}
}

func TestIdleTimeoutCountsFromTheLastDetach(t *testing.T) {
	m := newTestManager(t, 4)
	m.idleTimeout = time.Minute
	session := startTestSession(t, m, "sleep 30", true)

	attachment, err := session.attach()
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	session.mu.Lock()
	session.detachedAt = time.Now().Add(-2 * time.Minute)
	session.mu.Unlock()
	m.cleanupExpiredSessions()
	if session.Snapshot().State != "ready" {
		t.Fatalf("an attached session was ended for idleness")
	}

	session.Detach(attachment)
	session.mu.Lock()
	session.detachedAt = time.Now().Add(-2 * time.Minute)
	session.mu.Unlock()
	m.cleanupExpiredSessions()
	if err := session.WaitForExit(3 * time.Second); err != nil {
		t.Fatalf("idle session was not ended: %v", err)
	}
}

func TestScrollbackKeepsTheNewestOutputFromALineStart(t *testing.T) {
	b := scrollback{limit: 16}
	b.write([]byte("old line\n"))
	b.write([]byte("0123456789\nnewest\n"))
	if got := string(b.bytes()); got != "newest\n" {
		t.Fatalf("scrollback = %q, want %q", got, "newest\n")
	}
	for range 10 {
		b.write([]byte("abcdefgh\n"))
	}
	if len(b.data) > 2*b.limit {
		t.Fatalf("scrollback grew to %d bytes", len(b.data))
	}
}

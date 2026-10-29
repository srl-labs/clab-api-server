package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeWireshark is the reading end of a capture pipe: what the server wrote into it, and a
// way to close it as Wireshark does when its capture stops.
type fakeWireshark struct {
	mu     sync.Mutex
	data   bytes.Buffer
	closed chan struct{}
}

func (w *fakeWireshark) read() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.data.String()
}

// fakePipeStreamer plays the exec in the Wireshark container: it waits for Wireshark to open
// the pipe (a value on opens), reports "open", and copies stdin into the pipe until stdin
// ends or Wireshark closes the pipe (exit 0). With err set, the exec fails at once.
type fakePipeStreamer struct {
	mu    sync.Mutex
	args  [][]string
	err   error
	opens chan *fakeWireshark
}

func newFakePipeStreamer() *fakePipeStreamer {
	return &fakePipeStreamer{opens: make(chan *fakeWireshark)}
}

func (s *fakePipeStreamer) Stream(ctx context.Context, name string, args []string, stdin io.Reader, stdout io.Writer) error {
	s.mu.Lock()
	s.args = append(s.args, append([]string{name}, args...))
	err := s.err
	s.mu.Unlock()
	if err != nil {
		return err
	}
	var wireshark *fakeWireshark
	select {
	case wireshark = <-s.opens:
	case <-ctx.Done():
		return ctx.Err()
	}
	if _, err := stdout.Write([]byte("open\n")); err != nil {
		return err
	}
	stdinEnded := make(chan struct{})
	go func() {
		defer close(stdinEnded)
		buffer := make([]byte, 4096)
		for {
			n, err := stdin.Read(buffer)
			wireshark.mu.Lock()
			wireshark.data.Write(buffer[:n])
			wireshark.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	select {
	case <-stdinEnded:
		return nil
	case <-wireshark.closed:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// openAndRead opens the session's pipe and waits for the capture to write into it.
func (s *fakePipeStreamer) openAndRead(t *testing.T) *fakeWireshark {
	t.Helper()
	wireshark := s.open(t)
	require.Eventually(t, func() bool { return wireshark.read() != "" }, 5*time.Second, 10*time.Millisecond)
	return wireshark
}

// open opens the session's pipe as Wireshark does.
func (s *fakePipeStreamer) open(t *testing.T) *fakeWireshark {
	t.Helper()
	wireshark := &fakeWireshark{closed: make(chan struct{})}
	select {
	case s.opens <- wireshark:
	case <-time.After(5 * time.Second):
		t.Fatal("the server does not write into the capture pipe")
	}
	return wireshark
}

// fakeCapture writes "capture <n>" for its n-th run, then waits for its end, which it reports.
type fakeCapture struct {
	mu    sync.Mutex
	runs  int
	ended chan error
	fail  error
}

func (c *fakeCapture) run(ctx context.Context, w io.Writer) error {
	c.mu.Lock()
	c.runs++
	run, fail := c.runs, c.fail
	c.mu.Unlock()
	if _, err := fmt.Fprintf(w, "capture %d;", run); err != nil {
		return err
	}
	if fail != nil {
		return fail
	}
	<-ctx.Done()
	c.ended <- ctx.Err()
	return nil
}

func (c *fakeCapture) requireEnded(t *testing.T, why string) {
	t.Helper()
	select {
	case err := <-c.ended:
		require.ErrorIs(t, err, context.Canceled, why)
	case <-time.After(5 * time.Second):
		t.Fatalf("the capture did not end: %s", why)
	}
}

// newPipeTestManager returns a manager whose docker run starts container-<n> and whose
// execs are the fake streamer's.
func newPipeTestManager(t *testing.T) (*Manager, *fakeCommandRunner, *fakePipeStreamer) {
	t.Helper()
	previousDelay := pipeFeedRetryDelay
	pipeFeedRetryDelay = time.Millisecond
	t.Cleanup(func() { pipeFeedRetryDelay = previousDelay })
	runner := &fakeCommandRunner{t: t, responses: map[string]string{}, errors: map[string]error{}}
	started := 0
	runner.onRun = func(cmd recordedCommand) {
		if len(cmd.args) == 0 || cmd.args[0] != "run" {
			return
		}
		started++
		id := fmt.Sprintf("container-%d", started)
		runner.responses[commandKey(cmd.name, cmd.args)] = id + "\n"
		runner.responses[commandKey("docker", []string{"rm", "-f", id})] = ""
	}
	manager := newTestManager(t, ManagerConfig{
		Runtime:              "c9s",
		WiresharkDockerImage: "example/wireshark:test",
		WiresharkPullPolicy:  "never",
		WiresharkSessionTTL:  time.Hour,
	})
	streamer := newFakePipeStreamer()
	manager.runner = runner
	manager.streamer = streamer
	return manager, runner, streamer
}

func startPipeSession(t *testing.T, manager *Manager, containerName string, capture CaptureFunc) WiresharkSessionInfo {
	t.Helper()
	sessions, err := manager.CreatePipeWiresharkSessions(context.Background(), CreatePipeWiresharkSessionsOptions{
		Username: "alice",
		LabName:  "lab1",
		Theme:    "dark",
		Specs:    []WiresharkPipeSpec{{ContainerName: containerName, InterfaceNames: []string{"eth1", "eth2"}, Capture: capture}},
	})
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	return sessions[0]
}

func TestPipeSessionRunsWiresharkOnACapturePipe(t *testing.T) {
	manager, runner, streamer := newPipeTestManager(t)
	capture := &fakeCapture{ended: make(chan error, 1)}
	session := startPipeSession(t, manager, "lab1-n1", capture.run)
	require.Equal(t, "lab1-n1", session.ContainerName)
	require.Equal(t, []string{"eth1", "eth2"}, session.InterfaceNames)
	require.False(t, session.ShowVolumeTip)

	runArgs := strings.Join(runner.commandArgsContaining("run", "example/wireshark:test"), " ")
	require.Contains(t, runArgs, "-e CLABWIRE_CAPTURE_PIPE=/tmp/clabwire/lab1-n1 -e DARK_MODE=1 example/wireshark:test")
	require.Contains(t, runArgs, "-p 127.0.0.1:")
	require.NotContains(t, runArgs, "PACKETFLIX_LINK", "Wireshark reads the pipe only")
	require.NotContains(t, runArgs, "--add-host", "the container does not reach the server")
	require.Nil(t, runner.commandArgsContaining("network", "connect"), "no Edgeshark network")
	require.Nil(t, runner.commandArgsContaining("ps"), "no Edgeshark lookup")

	wireshark := streamer.open(t)
	require.Eventually(t, func() bool { return wireshark.read() == "capture 1;" }, 5*time.Second, 10*time.Millisecond)
	streamer.mu.Lock()
	require.Equal(t, []string{"docker", "exec", "-i", "container-1", "sh", "-c", capturePipeScript}, streamer.args[0])
	streamer.mu.Unlock()
	require.NoError(t, manager.CloseSession(context.Background(), session.SessionID, "alice", false))
}

// TestPipeSessionCaptureFollowsWiresharkAndTheSession stops and restarts the capture in the
// session's Wireshark, then closes the session: each opening of the pipe gets a capture of
// its own, which ends when Wireshark closes the pipe or the session ends.
func TestPipeSessionCaptureFollowsWiresharkAndTheSession(t *testing.T) {
	manager, runner, streamer := newPipeTestManager(t)
	capture := &fakeCapture{ended: make(chan error, 1)}
	session := startPipeSession(t, manager, "lab1-n1", capture.run)

	first := streamer.open(t)
	require.Eventually(t, func() bool { return first.read() == "capture 1;" }, 5*time.Second, 10*time.Millisecond)
	close(first.closed)
	capture.requireEnded(t, "Wireshark stopped its capture")

	second := streamer.open(t)
	require.Eventually(t, func() bool { return second.read() == "capture 2;" }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, "capture 1;", first.read(), "a restarted capture starts a new stream")

	require.NoError(t, manager.CloseSession(context.Background(), session.SessionID, "alice", false))
	capture.requireEnded(t, "closing the session ends its capture")
	require.NotNil(t, runner.commandArgsContaining("rm", "-f", "container-1"))
}

// TestPipeSessionCaptureEndsWithTheSession ends sessions in the other ways a session ends:
// closed with all sessions, expired, and shut down.
func TestPipeSessionCaptureEndsWithTheSession(t *testing.T) {
	manager, _, streamer := newPipeTestManager(t)
	capture := &fakeCapture{ended: make(chan error, 1)}

	startPipeSession(t, manager, "lab1-n1", capture.run)
	streamer.openAndRead(t)
	count, err := manager.CloseAllSessions(context.Background(), "alice", false)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	capture.requireEnded(t, "closing all sessions")

	expired := startPipeSession(t, manager, "lab1-n1", capture.run)
	streamer.openAndRead(t)
	manager.mu.Lock()
	manager.sessions[expired.SessionID].expiresAt = time.Now().Add(-time.Second)
	manager.mu.Unlock()
	manager.sweepExpiredSessions()
	capture.requireEnded(t, "the session expired")

	// A manager of its own: the test's cleanup shuts the first one down.
	shutdown := NewManager(manager.cfg)
	shutdown.runner, shutdown.streamer = manager.runner, manager.streamer
	startPipeSession(t, shutdown, "lab1-n1", capture.run)
	streamer.openAndRead(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdown.Shutdown(ctx)
	capture.requireEnded(t, "the server shut down")
}

func TestPipeSessionFailsWithItsCapture(t *testing.T) {
	manager, runner, streamer := newPipeTestManager(t)
	capture := &fakeCapture{ended: make(chan error, 1), fail: errors.New("pod n1 is gone")}
	session := startPipeSession(t, manager, "lab1-n1", capture.run)
	wireshark := streamer.open(t)

	var err error
	require.Eventually(t, func() bool {
		_, _, err = manager.SessionReady(context.Background(), session.SessionID, "alice", false)
		return err != nil
	}, 5*time.Second, 10*time.Millisecond)
	require.ErrorIs(t, err, ErrSessionCaptureFailed)
	require.ErrorContains(t, err, "pod n1 is gone")
	require.Equal(t, "capture 1;", wireshark.read(), "Wireshark got what the capture wrote")
	require.NotNil(t, runner.commandArgsContaining("rm", "-f", "container-1"), "the failed session's container is stopped")
	_, err = manager.ResolveProxyTarget(session.SessionID, "alice", false)
	require.ErrorIs(t, err, ErrSessionCaptureFailed)
	_, _, err = manager.SessionReady(context.Background(), session.SessionID, "bob", false)
	require.ErrorIs(t, err, ErrSessionForbidden, "only its user learns why")

	require.NoError(t, manager.CloseSession(context.Background(), session.SessionID, "alice", false))
	_, _, err = manager.SessionReady(context.Background(), session.SessionID, "alice", false)
	require.ErrorIs(t, err, ErrSessionNotFound)
}

func TestPipeSessionFailsWithoutACapturePipe(t *testing.T) {
	manager, _, streamer := newPipeTestManager(t)
	streamer.err = errors.New("exit status 3: Wireshark created no capture pipe /tmp/clabwire/lab1-n1")
	capture := &fakeCapture{ended: make(chan error, 1)}
	session := startPipeSession(t, manager, "lab1-n1", capture.run)

	var err error
	require.Eventually(t, func() bool {
		_, _, err = manager.SessionReady(context.Background(), session.SessionID, "alice", false)
		return err != nil
	}, 5*time.Second, 10*time.Millisecond)
	require.ErrorIs(t, err, ErrSessionCaptureFailed)
	require.ErrorContains(t, err, "created no capture pipe")
	capture.mu.Lock()
	require.Zero(t, capture.runs, "no capture without a reader")
	capture.mu.Unlock()
}

func TestPipeSessionsStopOnAStartFailure(t *testing.T) {
	manager, runner, _ := newPipeTestManager(t)
	failNext := false
	onRun := runner.onRun
	runner.onRun = func(cmd recordedCommand) {
		if len(cmd.args) > 0 && cmd.args[0] == "run" && failNext {
			runner.errors[commandKey(cmd.name, cmd.args)] = errors.New("docker run failed")
			return
		}
		onRun(cmd)
		failNext = true
	}
	capture := &fakeCapture{ended: make(chan error, 1)}
	_, err := manager.CreatePipeWiresharkSessions(context.Background(), CreatePipeWiresharkSessionsOptions{
		Username: "alice", LabName: "lab1",
		Specs: []WiresharkPipeSpec{
			{ContainerName: "lab1-n1", InterfaceNames: []string{"eth1"}, Capture: capture.run},
			{ContainerName: "lab1-n2", InterfaceNames: []string{"eth1"}, Capture: capture.run},
		},
	})
	require.ErrorContains(t, err, "docker run failed")
	require.NotNil(t, runner.commandArgsContaining("rm", "-f", "container-1"), "the started session is stopped")
	closed, err := manager.CloseAllSessions(context.Background(), "", true)
	require.NoError(t, err)
	require.Zero(t, closed)
}

func TestWiresharkCapturePipe(t *testing.T) {
	require.Equal(t, "/tmp/clabwire/lab1-srl1", wiresharkCapturePipe("lab1-srl1"))
	require.Equal(t, "/tmp/clabwire/a-b", wiresharkCapturePipe("../a b"))
	require.Equal(t, "/tmp/clabwire/capture", wiresharkCapturePipe(".."))
}

func TestContainerRuntimeAvailableIsCached(t *testing.T) {
	runner := &fakeCommandRunner{t: t, responses: map[string]string{}, errors: map[string]error{
		commandKey("docker", []string{"version", "--format", "{{.Server.Version}}"}): errors.New("cannot connect"),
	}}
	manager := newTestManager(t, ManagerConfig{Runtime: "c9s"})
	manager.runner = runner
	require.False(t, manager.ContainerRuntimeAvailable(context.Background()))
	require.False(t, manager.ContainerRuntimeAvailable(context.Background()))
	require.Len(t, runner.commands, 1, "probed once a minute")

	manager.runtimeProbedAt = time.Time{}
	runner.errors = nil
	runner.responses[commandKey("docker", []string{"version", "--format", "{{.Server.Version}}"})] = "29.0.0"
	require.True(t, manager.ContainerRuntimeAvailable(context.Background()))
}

package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
)

// Wireshark VNC sessions fed through a pipe: the Wireshark VNC image (wireshark-vnc-docker
// with its CLABWIRE_CAPTURE_PIPE mode) creates a named pipe and runs Wireshark on it, and the
// server writes a pcapng capture into the pipe through an exec in the container. The container
// needs neither Edgeshark nor a way to reach the server.

// capturePipeEnv names the pipe the Wireshark VNC image creates and reads.
const capturePipeEnv = "CLABWIRE_CAPTURE_PIPE"

// capturePipeDir holds the capture pipe in the Wireshark container.
const capturePipeDir = "/tmp/clabwire/"

// capturePipeScript runs in the Wireshark container for every capture the server writes into
// the pipe. It waits for the image to create the pipe (60 s, then exit 3), opens it for
// writing, which blocks until Wireshark opens it for reading, reports "open" on stdout and
// copies stdin into the pipe until stdin ends or Wireshark closes the pipe (exit 0).
const capturePipeScript = `p="$` + capturePipeEnv + `"
i=0
while [ ! -p "$p" ]; do
	i=$((i+1))
	if [ "$i" -gt 300 ]; then
		echo "Wireshark created no capture pipe $p; Wireshark VNC on this lab runtime needs a wireshark-vnc-docker image with ` + capturePipeEnv + `" >&2
		exit 3
	fi
	sleep 0.2
done
exec 3>"$p"
echo open
cat >&3
exit 0`

// pipeFeedRetryDelay keeps a capture pipe that Wireshark opens and closes at once from
// restarting the capture in a tight loop; tests shorten it.
var pipeFeedRetryDelay = time.Second

// CaptureFunc writes one pcapng capture to w until ctx ends or the capture fails.
type CaptureFunc func(ctx context.Context, w io.Writer) error

// WiresharkPipeSpec is a Wireshark VNC session whose Wireshark reads a capture the server
// writes into a pipe in its container, instead of capturing through Edgeshark.
type WiresharkPipeSpec struct {
	// ContainerName and InterfaceNames describe what the session captures.
	ContainerName  string
	InterfaceNames []string
	// Capture writes the session's capture. It runs each time the session's Wireshark opens
	// the pipe: when it starts, and when its capture is restarted. The session's end cancels
	// it. A capture that fails ends the session's container.
	Capture CaptureFunc
}

// CreatePipeWiresharkSessionsOptions selects Wireshark VNC sessions fed through a pipe.
type CreatePipeWiresharkSessionsOptions struct {
	Username string
	LabName  string
	Theme    string
	Specs    []WiresharkPipeSpec
}

// CreatePipeWiresharkSessions starts one Wireshark VNC container per spec and feeds the
// spec's capture into its pipe for as long as the session exists. It needs neither Edgeshark
// nor its network, only the container runtime on this host.
func (m *Manager) CreatePipeWiresharkSessions(
	ctx context.Context,
	options CreatePipeWiresharkSessionsOptions,
) ([]WiresharkSessionInfo, error) {
	if len(options.Specs) == 0 {
		return nil, errors.New("at least one capture target is required")
	}
	for _, spec := range options.Specs {
		if spec.Capture == nil {
			return nil, errors.New("a Wireshark session fed through a pipe needs a capture")
		}
	}
	if err := m.ensureImageAvailable(ctx); err != nil {
		return nil, err
	}
	launches := make([]sessionLaunch, 0, len(options.Specs))
	for _, spec := range options.Specs {
		launches = append(launches, sessionLaunch{
			containerName:  spec.ContainerName,
			interfaceNames: spec.InterfaceNames,
			capture:        spec.Capture,
		})
	}
	return m.startSessions(ctx, options.Username, options.LabName, options.Theme, launches)
}

// wiresharkCapturePipe is the pipe of a session's Wireshark; Wireshark shows it as the name
// of what it captures.
func wiresharkCapturePipe(containerName string) string {
	name := strings.Trim(sanitizeContainerNameRx.ReplaceAllString(containerName, "-"), ".-")
	if name == "" {
		name = "capture"
	}
	return capturePipeDir + name
}

// feedSession writes the session's capture into its Wireshark's pipe, once per opening of
// the pipe, until ctx ends with the session. When a capture fails, the session fails.
func (m *Manager) feedSession(ctx context.Context, session *wiresharkSession, capture CaptureFunc) {
	defer close(session.feedDone)
	for ctx.Err() == nil {
		started := time.Now()
		err := m.feedPipeOnce(ctx, session.containerID, capture)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			m.failSession(session, err)
			return
		}
		// Wireshark closed the pipe: its capture stopped, and may be restarted.
		if wait := pipeFeedRetryDelay - time.Since(started); wait > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
	}
}

// failSession ends the container of a session whose capture failed. The session stays until
// it is closed or expires, and reports the failure.
func (m *Manager) failSession(session *wiresharkSession, err error) {
	m.mu.Lock()
	_, registered := m.sessions[session.id]
	if registered {
		session.failure = err
	}
	m.mu.Unlock()
	if !registered {
		return
	}
	log.Warnf("capture: Wireshark VNC session '%s' of lab '%s' stopped, its capture failed: %v", session.id, session.labName, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if stopErr := m.stopWiresharkContainer(ctx, session.containerID); stopErr != nil {
		log.Warnf("capture: failed stopping session '%s' after its capture failed: %v", session.id, stopErr)
	}
}

// errCapturePipeClosed ends the writes of a capture whose pipe is gone.
var errCapturePipeClosed = errors.New("the Wireshark capture pipe is closed")

// feedPipeOnce writes one capture into the container's pipe: it waits until Wireshark opens
// the pipe, then runs capture into it until Wireshark closes the pipe (nil), the capture ends
// (its error), or ctx ends.
func (m *Manager) feedPipeOnce(ctx context.Context, containerID string, capture CaptureFunc) error {
	stdin, stdinWriter := io.Pipe()
	opened := &pipeOpenedWriter{opened: make(chan struct{})}
	execCtx, cancelExec := context.WithCancel(ctx)
	defer cancelExec()
	execDone := make(chan error, 1)
	go func() {
		err := m.streamer.Stream(execCtx, m.runtimeBinary(),
			[]string{"exec", "-i", containerID, "sh", "-c", capturePipeScript}, stdin, opened)
		// Report the end before the capture's writes fail, so they are not taken for a failure.
		execDone <- err
		_ = stdin.CloseWithError(errCapturePipeClosed)
	}()

	select {
	case <-opened.opened:
	case err := <-execDone:
		if err == nil {
			err = errors.New("the capture pipe closed before Wireshark opened it")
		}
		return fmt.Errorf("writing into the Wireshark capture pipe: %w", err)
	case <-ctx.Done():
		cancelExec()
		<-execDone
		return ctx.Err()
	}

	captureCtx, cancelCapture := context.WithCancel(ctx)
	defer cancelCapture()
	captureDone := make(chan error, 1)
	go func() { captureDone <- capture(captureCtx, stdinWriter) }()

	select {
	case err := <-execDone:
		// Wireshark closed the pipe (nil), or the exec failed: the capture stops.
		cancelCapture()
		<-captureDone
		if err != nil {
			return fmt.Errorf("writing into the Wireshark capture pipe: %w", err)
		}
		return nil
	case err := <-captureDone:
		select {
		case execErr := <-execDone:
			// The pipe went away first; the capture failed writing into it.
			if execErr != nil {
				return fmt.Errorf("writing into the Wireshark capture pipe: %w", execErr)
			}
			return nil
		default:
		}
		// The capture ended: Wireshark reads the end of the stream.
		_ = stdinWriter.Close()
		select {
		case <-execDone:
		case <-ctx.Done():
			cancelExec()
			<-execDone
		}
		return err
	}
}

// pipeOpenedWriter takes the exec's stdout and closes opened once the script reports that
// Wireshark opened the pipe.
type pipeOpenedWriter struct {
	opened chan struct{}
	once   sync.Once
	seen   []byte
}

func (w *pipeOpenedWriter) Write(p []byte) (int, error) {
	if len(w.seen) < 64 {
		w.seen = append(w.seen, p...)
		if bytes.Contains(w.seen, []byte("open\n")) {
			w.once.Do(func() { close(w.opened) })
		}
	}
	return len(p), nil
}

// streamRunner runs a command with a stream as its stdin; tests replace it.
type streamRunner interface {
	Stream(ctx context.Context, name string, args []string, stdin io.Reader, stdout io.Writer) error
}

// Stream runs the command until it exits, copying stdin to it and its stdout to stdout.
// Unlike exec.Cmd with a plain reader as Stdin, it returns when the command exits, without
// waiting for stdin to end; the caller closes stdin afterwards.
func (execRunner) Stream(ctx context.Context, name string, args []string, stdin io.Reader, stdout io.Writer) error {
	cmd := exec.CommandContext(ctx, name, args...)
	// A killed command's children may hold its stdout open; do not wait for them for long.
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdout = stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		_, _ = io.Copy(in, stdin)
		_ = in.Close()
	}()
	if err := cmd.Wait(); err != nil {
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return fmt.Errorf("%w: %s", err, message)
		}
		return err
	}
	return nil
}

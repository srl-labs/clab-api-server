package terminal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	"golang.org/x/crypto/ssh"
)

// sessionBackend is what a terminal session runs: a local process on a PTY, or a stream
// to a node through a lab runtime. The session machinery (scrollback, attach, resume,
// idle timeout) is the same for every backend.
type sessionBackend interface {
	// Read returns terminal output. It returns an error once the backend has ended.
	Read(p []byte) (int, error)
	// Write sends terminal input.
	Write(p []byte) (int, error)
	// Resize changes the terminal size.
	Resize(cols, rows int) error
	// Wait blocks until the backend ended and returns its exit code.
	Wait() (int, error)
	// Hangup asks the backend to end, and forces it shortly after.
	Hangup()
	// Close releases the backend's resources once it ended.
	Close() error
}

// backendStarter starts a backend with an initial terminal size.
type backendStarter func(cols, rows int) (sessionBackend, error)

// --- PTY child process ---

type ptyBackend struct {
	cmd  *exec.Cmd
	file *os.File
}

func startPTYBackend(command []string) backendStarter {
	return func(cols, rows int) (sessionBackend, error) {
		cmd := exec.CommandContext(context.Background(), command[0], command[1:]...)
		cmd.Env = minimalCommandEnv()
		cmd.Dir = "/"
		file, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
		if err != nil {
			return nil, err
		}
		return &ptyBackend{cmd: cmd, file: file}, nil
	}
}

func (b *ptyBackend) Read(p []byte) (int, error)  { return b.file.Read(p) }
func (b *ptyBackend) Write(p []byte) (int, error) { return b.file.Write(p) }

func (b *ptyBackend) Resize(cols, rows int) error {
	return pty.Setsize(b.file, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}

func (b *ptyBackend) Wait() (int, error) {
	err := b.cmd.Wait()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), err
		}
		return -1, err
	}
	if b.cmd.ProcessState != nil {
		return b.cmd.ProcessState.ExitCode(), nil
	}
	return 0, nil
}

func (b *ptyBackend) Hangup() {
	_ = b.file.Close()
	if proc := b.cmd.Process; proc != nil {
		_ = proc.Signal(syscall.SIGHUP)
		time.AfterFunc(750*time.Millisecond, func() {
			_ = proc.Kill()
		})
	}
}

func (b *ptyBackend) Close() error { return b.file.Close() }

// --- streams (lab runtime attach, SSH) ---

// streamBackend runs a session as a function that consumes terminal input and produces
// output, such as an exec in a Kubernetes Pod or an SSH session.
type streamBackend struct {
	inputReader  *io.PipeReader
	inputWriter  *io.PipeWriter
	outputReader *io.PipeReader
	outputWriter *io.PipeWriter
	resize       chan clablabruntime.TerminalSize
	cancel       context.CancelFunc
	done         chan struct{}

	mu       sync.Mutex
	exitCode int
	err      error
}

// runStream starts run with the session's streams. run returns once the remote command
// ended; its error decides the exit code.
func runStream(
	cols, rows int,
	run func(ctx context.Context, stdin io.Reader, stdout io.Writer, resize <-chan clablabruntime.TerminalSize) error,
) *streamBackend {
	ctx, cancel := context.WithCancel(context.Background())
	inputReader, inputWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	b := &streamBackend{
		inputReader:  inputReader,
		inputWriter:  inputWriter,
		outputReader: outputReader,
		outputWriter: outputWriter,
		resize:       make(chan clablabruntime.TerminalSize, 1),
		cancel:       cancel,
		done:         make(chan struct{}),
	}
	b.queueResize(cols, rows)
	go func() {
		err := run(ctx, inputReader, outputWriter, b.resize)
		code := exitCodeOf(err)
		if ctx.Err() != nil && code < 0 {
			// Ended by Hangup: the remote side was told to stop.
			err = nil
		}
		b.mu.Lock()
		b.exitCode, b.err = code, err
		b.mu.Unlock()
		_ = outputWriter.CloseWithError(io.EOF)
		_ = inputReader.CloseWithError(io.EOF)
		close(b.done)
	}()
	return b
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var commandExit *clablabruntime.CommandExitError
	if errors.As(err, &commandExit) {
		return commandExit.Code
	}
	var sshExit *ssh.ExitError
	if errors.As(err, &sshExit) {
		return sshExit.ExitStatus()
	}
	return -1
}

func (b *streamBackend) Read(p []byte) (int, error)  { return b.outputReader.Read(p) }
func (b *streamBackend) Write(p []byte) (int, error) { return b.inputWriter.Write(p) }

// queueResize keeps only the newest size, so a slow remote never blocks the client.
func (b *streamBackend) queueResize(cols, rows int) {
	size := clablabruntime.TerminalSize{Width: uint16(cols), Height: uint16(rows)}
	for {
		select {
		case b.resize <- size:
			return
		default:
		}
		select {
		case <-b.resize:
		default:
		}
	}
}

func (b *streamBackend) Resize(cols, rows int) error {
	select {
	case <-b.done:
		return io.EOF
	default:
	}
	b.queueResize(cols, rows)
	return nil
}

func (b *streamBackend) Wait() (int, error) {
	<-b.done
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exitCode, b.err
}

func (b *streamBackend) Hangup() {
	_ = b.inputWriter.Close()
	b.cancel()
}

func (b *streamBackend) Close() error {
	b.cancel()
	_ = b.inputWriter.Close()
	return b.outputReader.Close()
}

// AttachFunc runs an interactive command in a node's container through the lab runtime.
type AttachFunc func(ctx context.Context, command []string, tty bool, streams clablabruntime.AttachStreams) error

// DialFunc opens a TCP connection to a port of a node through the lab runtime.
type DialFunc func(ctx context.Context, port int) (net.Conn, error)

func startAttachBackend(attach AttachFunc, command []string) backendStarter {
	return func(cols, rows int) (sessionBackend, error) {
		return runStream(cols, rows, func(ctx context.Context, stdin io.Reader, stdout io.Writer, resize <-chan clablabruntime.TerminalSize) error {
			return attach(ctx, command, true, clablabruntime.AttachStreams{
				Stdin:  stdin,
				Stdout: stdout,
				Resize: resize,
			})
		}), nil
	}
}

// sshDialTimeout bounds connecting and authenticating to a node's SSH server.
const sshDialTimeout = 30 * time.Second

// sshPasswordAttempts is how often a user may type the password, like OpenSSH.
const sshPasswordAttempts = 3

// startSSHBackend logs in to a node's SSH server with Go's SSH client. The connection
// comes from dial (a port-forward to the node's port 22, or the node's LoadBalancer
// address). Like the ssh command it replaces, it asks for the password in the terminal.
func startSSHBackend(dial func(ctx context.Context) (net.Conn, error), address, username string) backendStarter {
	return func(cols, rows int) (sessionBackend, error) {
		return runStream(cols, rows, func(ctx context.Context, stdin io.Reader, stdout io.Writer, resize <-chan clablabruntime.TerminalSize) error {
			return runSSHSession(ctx, dial, address, username, stdin, stdout, resize)
		}), nil
	}
}

func runSSHSession(
	ctx context.Context,
	dial func(ctx context.Context) (net.Conn, error),
	address, username string,
	stdin io.Reader,
	stdout io.Writer,
	resize <-chan clablabruntime.TerminalSize,
) error {
	dialCtx, cancelDial := context.WithTimeout(ctx, sshDialTimeout)
	conn, err := dial(dialCtx)
	cancelDial()
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "ssh: connect to %s: %v\r\n", address, err)
		return err
	}
	defer func() { _ = conn.Close() }()
	// End the connection, and with it a pending password prompt, when the session ends.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	prompt := &terminalPrompt{in: stdin, out: stdout}
	password := func() (string, error) {
		return prompt.ask(fmt.Sprintf("%s@%s's password: ", username, address), false)
	}
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.RetryableAuthMethod(ssh.PasswordCallback(password), sshPasswordAttempts),
			ssh.RetryableAuthMethod(ssh.KeyboardInteractive(prompt.challenge), sshPasswordAttempts),
		},
		// Lab nodes get new host keys on every deploy; the ssh command ran with
		// StrictHostKeyChecking=no for the same reason.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // lab nodes regenerate host keys
		Timeout:         sshDialTimeout,
	}
	clientConn, channels, requests, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "\r\nssh: %v\r\n", err)
		return err
	}
	client := ssh.NewClient(clientConn, channels, requests)
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "ssh: %v\r\n", err)
		return err
	}
	defer func() { _ = session.Close() }()

	size := clablabruntime.TerminalSize{Width: DefaultTerminalCols, Height: DefaultTerminalRows}
	select {
	case size = <-resize:
	default:
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400}
	if err := session.RequestPty("xterm-256color", int(size.Height), int(size.Width), modes); err != nil {
		_, _ = fmt.Fprintf(stdout, "ssh: %v\r\n", err)
		return err
	}
	session.Stdin = stdin
	session.Stdout = stdout
	session.Stderr = stdout
	if err := session.Shell(); err != nil {
		_, _ = fmt.Fprintf(stdout, "ssh: %v\r\n", err)
		return err
	}

	resizeDone := make(chan struct{})
	defer close(resizeDone)
	go func() {
		for {
			select {
			case <-resizeDone:
				return
			case size, open := <-resize:
				if !open {
					return
				}
				_ = session.WindowChange(int(size.Height), int(size.Width))
			}
		}
	}()

	return session.Wait()
}

// terminalPrompt asks questions in the session's terminal before the remote shell runs.
type terminalPrompt struct {
	in  io.Reader
	out io.Writer
}

// ask writes question and reads one line of input. Without echo, typed characters are
// not shown, like a password prompt.
func (p *terminalPrompt) ask(question string, echo bool) (string, error) {
	if _, err := io.WriteString(p.out, question); err != nil {
		return "", err
	}
	var line []byte
	buffer := make([]byte, 1)
	for {
		if _, err := p.in.Read(buffer); err != nil {
			return "", err
		}
		switch b := buffer[0]; b {
		case '\r', '\n':
			_, _ = io.WriteString(p.out, "\r\n")
			return string(line), nil
		case 0x7f, 0x08: // backspace
			if len(line) > 0 {
				line = line[:len(line)-1]
				if echo {
					_, _ = io.WriteString(p.out, "\b \b")
				}
			}
		case 0x03: // Ctrl-C
			_, _ = io.WriteString(p.out, "^C\r\n")
			return "", errors.New("login cancelled")
		default:
			line = append(line, b)
			if echo {
				_, _ = p.out.Write(buffer)
			}
		}
	}
}

func (p *terminalPrompt) challenge(name, instruction string, questions []string, echos []bool) ([]string, error) {
	if text := strings.TrimSpace(strings.Join([]string{name, instruction}, "\n")); text != "" {
		_, _ = io.WriteString(p.out, strings.ReplaceAll(text, "\n", "\r\n")+"\r\n")
	}
	answers := make([]string, len(questions))
	for i, question := range questions {
		answer, err := p.ask(question, i < len(echos) && echos[i])
		if err != nil {
			return nil, err
		}
		answers[i] = answer
	}
	return answers, nil
}

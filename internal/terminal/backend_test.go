package terminal

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/srl-labs/clab-api-server/internal/models"
)

// fakeAttach is a lab runtime attach: an echo shell that records the command and every
// terminal size, and ends with "exit N".
type fakeAttach struct {
	mu       sync.Mutex
	commands [][]string
	sizes    []clablabruntime.TerminalSize
	tty      bool
}

func (f *fakeAttach) attach(ctx context.Context, command []string, tty bool, streams clablabruntime.AttachStreams) error {
	f.mu.Lock()
	f.commands = append(f.commands, command)
	f.tty = tty
	f.mu.Unlock()
	go func() {
		for size := range streams.Resize {
			f.mu.Lock()
			f.sizes = append(f.sizes, size)
			f.mu.Unlock()
		}
	}()
	_, _ = io.WriteString(streams.Stdout, "ready\r\n")
	scanner := bufio.NewScanner(streams.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		var code int
		if _, err := fmt.Sscanf(line, "exit %d", &code); err == nil {
			if code == 0 {
				return nil
			}
			return &clablabruntime.CommandExitError{Code: code}
		}
		_, _ = fmt.Fprintf(streams.Stdout, "echo:%s\r\n", line)
	}
	return ctx.Err()
}

func (f *fakeAttach) lastSize() clablabruntime.TerminalSize {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sizes) == 0 {
		return clablabruntime.TerminalSize{}
	}
	return f.sizes[len(f.sizes)-1]
}

func createAttachSession(t *testing.T, m *Manager, attach *fakeAttach, protocol models.TerminalProtocol, resumable bool) *Session {
	t.Helper()
	info, err := m.CreateSession(CreateSessionOptions{
		Username: "alice", LabName: "lab", NodeName: "n1", ContainerID: "ns/lab/n1",
		ContainerKind: "nokia_srlinux", Protocol: protocol, Cols: 100, Rows: 30,
		Resumable: resumable, TelnetPort: 5001,
		Attach: attach.attach,
	})
	require.NoError(t, err)
	session, err := m.lookupSession(info.SessionID, "alice", false)
	require.NoError(t, err)
	t.Cleanup(func() {
		session.Terminate("test done")
		_ = session.WaitForExit(2 * time.Second)
	})
	return session
}

func TestAttachSessionResumesReplaysAndResizes(t *testing.T) {
	m := newTestManager(t, 4)
	attach := &fakeAttach{}
	session := createAttachSession(t, m, attach, models.TerminalProtocolShell, true)

	first, err := session.attach()
	require.NoError(t, err)
	readUntil(t, first, "ready")
	require.Equal(t, [][]string{{"sr_cli"}}, attach.commands, "shell runs the kind's CLI in the container")
	require.True(t, attach.tty)
	require.Eventually(t, func() bool { return attach.lastSize() == clablabruntime.TerminalSize{Width: 100, Height: 30} },
		2*time.Second, 10*time.Millisecond, "the initial size reaches the attach")

	require.NoError(t, session.Resize(132, 43))
	require.Eventually(t, func() bool { return attach.lastSize() == clablabruntime.TerminalSize{Width: 132, Height: 43} },
		2*time.Second, 10*time.Millisecond)

	session.Detach(first)
	require.Equal(t, "ready", session.Snapshot().State, "a resumable session survives its client")
	require.NoError(t, session.WriteInput("while-away\n"))
	time.Sleep(200 * time.Millisecond)

	second, err := session.attach()
	require.NoError(t, err)
	replay := string(second.Replay)
	require.Contains(t, replay, "ready")
	require.Contains(t, replay, "echo:while-away")

	require.NoError(t, session.WriteInput("exit 7\n"))
	for range second.Output() {
	}
	require.Equal(t, DetachReasonExited, second.Reason())
	require.NoError(t, session.WaitForExit(2*time.Second))
	snapshot := session.Snapshot()
	require.Equal(t, "closed", snapshot.State)
	require.NotNil(t, snapshot.ExitCode)
	require.Equal(t, 7, *snapshot.ExitCode)
	require.ErrorIs(t, session.Resize(80, 24), io.EOF)
}

func TestAttachSessionWithoutResumeEndsWithItsClient(t *testing.T) {
	m := newTestManager(t, 4)
	session := createAttachSession(t, m, &fakeAttach{}, models.TerminalProtocolShell, false)
	attachment, err := session.attach()
	require.NoError(t, err)
	readUntil(t, attachment, "ready")
	session.Detach(attachment)
	require.NoError(t, session.WaitForExit(3*time.Second))
	require.Equal(t, "closed", session.Snapshot().State)
}

func TestTelnetOverAttachRunsTelnetInTheContainer(t *testing.T) {
	m := newTestManager(t, 4)
	attach := &fakeAttach{}
	session := createAttachSession(t, m, attach, models.TerminalProtocolTelnet, false)
	attachment, err := session.attach()
	require.NoError(t, err)
	readUntil(t, attachment, "ready")
	require.Equal(t, [][]string{{"telnet", "127.0.0.1", "5001"}}, attach.commands)
}

func TestLabRuntimeSessionsNeedTheirAccess(t *testing.T) {
	_, err := resolveLabRuntimeBackend(models.TerminalProtocolShell, CreateSessionOptions{Dial: func(context.Context, int) (net.Conn, error) { return nil, nil }})
	require.Error(t, err)
	_, err = resolveLabRuntimeBackend(models.TerminalProtocolTelnet, CreateSessionOptions{Dial: func(context.Context, int) (net.Conn, error) { return nil, nil }})
	require.Error(t, err)
}

// sshTestServer accepts one password login and runs an echo shell, recording window changes.
type sshTestServer struct {
	password string
	mu       sync.Mutex
	sizes    [][2]uint32
	user     string
}

func (s *sshTestServer) serve(t *testing.T, conn net.Conn) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostKey, err := ssh.NewSignerFromKey(signer)
	require.NoError(t, err)
	config := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) == s.password {
				s.mu.Lock()
				s.user = meta.User()
				s.mu.Unlock()
				return nil, nil
			}
			return nil, fmt.Errorf("wrong password")
		},
	}
	config.AddHostKey(hostKey)
	serverConn, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer func() { _ = serverConn.Close() }()
	go ssh.DiscardRequests(requests)
	for newChannel := range channels {
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			return
		}
		go func() {
			for request := range channelRequests {
				switch request.Type {
				case "pty-req", "shell":
					_ = request.Reply(true, nil)
				case "window-change":
					if len(request.Payload) >= 8 {
						s.mu.Lock()
						s.sizes = append(s.sizes, [2]uint32{binary.BigEndian.Uint32(request.Payload[0:4]), binary.BigEndian.Uint32(request.Payload[4:8])})
						s.mu.Unlock()
					}
				default:
					_ = request.Reply(false, nil)
				}
			}
		}()
		_, _ = io.WriteString(channel, "welcome\r\n")
		scanner := bufio.NewScanner(channel)
		for scanner.Scan() {
			if scanner.Text() == "logout" {
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{4}))
				_ = channel.Close()
				return
			}
			_, _ = fmt.Fprintf(channel, "remote:%s\r\n", scanner.Text())
		}
	}
}

func (s *sshTestServer) lastSize() [2]uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sizes) == 0 {
		return [2]uint32{}
	}
	return s.sizes[len(s.sizes)-1]
}

func TestSSHOverDialPromptsForThePasswordAndResizes(t *testing.T) {
	m := newTestManager(t, 4)
	server := &sshTestServer{password: "NokiaSrl1!"}
	var dialedPorts []int
	var dialMu sync.Mutex
	info, err := m.CreateSession(CreateSessionOptions{
		Username: "alice", LabName: "lab", NodeName: "n1", ContainerID: "ns/lab/n1",
		ContainerKind: "nokia_srlinux", Protocol: models.TerminalProtocolSSH, SSHAddress: "n1",
		Resumable: true,
		Dial: func(_ context.Context, port int) (net.Conn, error) {
			dialMu.Lock()
			dialedPorts = append(dialedPorts, port)
			dialMu.Unlock()
			// A loopback connection: the SSH version exchange writes on both sides
			// before reading, which an unbuffered net.Pipe cannot carry.
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			go func() {
				defer func() { _ = listener.Close() }()
				serverSide, err := listener.Accept()
				if err == nil {
					server.serve(t, serverSide)
				}
			}()
			return net.Dial("tcp", listener.Addr().String())
		},
	})
	require.NoError(t, err)
	session, err := m.lookupSession(info.SessionID, "alice", false)
	require.NoError(t, err)
	t.Cleanup(func() {
		session.Terminate("test done")
		_ = session.WaitForExit(2 * time.Second)
	})

	attachment, err := session.attach()
	require.NoError(t, err)
	readUntil(t, attachment, "admin@n1's password: ")
	require.NoError(t, session.WriteInput("wrong\r"))
	readUntil(t, attachment, "\r\nadmin@n1's password: ")
	require.NoError(t, session.WriteInput("NokiaSrl1!\r"))
	got := readUntil(t, attachment, "welcome")
	require.NotContains(t, got, "NokiaSrl1!", "the password is not echoed")
	require.Equal(t, []int{22}, dialedPorts)
	server.mu.Lock()
	require.Equal(t, "admin", server.user, "nokia_srlinux logs in as its default user")
	server.mu.Unlock()

	require.NoError(t, session.Resize(150, 50))
	require.Eventually(t, func() bool { return server.lastSize() == [2]uint32{150, 50} }, 2*time.Second, 10*time.Millisecond)

	require.NoError(t, session.WriteInput("hello\n"))
	readUntil(t, attachment, "remote:hello")
	require.NoError(t, session.WriteInput("logout\n"))
	for range attachment.Output() {
	}
	require.NoError(t, session.WaitForExit(2*time.Second))
	require.Equal(t, 4, *session.Snapshot().ExitCode)
}

func TestSSHDialFailureEndsTheSessionWithAMessage(t *testing.T) {
	m := newTestManager(t, 4)
	info, err := m.CreateSession(CreateSessionOptions{
		Username: "alice", LabName: "lab", NodeName: "n1", ContainerID: "ns/lab/n1",
		Protocol: models.TerminalProtocolSSH, SSHAddress: "n1",
		Dial: func(context.Context, int) (net.Conn, error) { return nil, fmt.Errorf("pods \"x\" is forbidden") },
	})
	require.NoError(t, err)
	session, err := m.lookupSession(info.SessionID, "alice", false)
	require.NoError(t, err)
	require.NoError(t, session.WaitForExit(3*time.Second))
	snapshot := session.Snapshot()
	require.Equal(t, -1, *snapshot.ExitCode)
	require.Contains(t, snapshot.Error, "forbidden")
	attachment, err := session.attach()
	require.ErrorIs(t, err, ErrSessionExited)
	require.Nil(t, attachment)
	require.True(t, strings.Contains(string(session.scrollback.bytes()), "ssh: connect to n1"))
}

func TestTerminalPromptHandlesBackspaceAndCancel(t *testing.T) {
	var out strings.Builder
	prompt := &terminalPrompt{in: strings.NewReader("abx\x7fc\r"), out: &out}
	answer, err := prompt.ask("Q: ", true)
	require.NoError(t, err)
	require.Equal(t, "abc", answer)
	require.Equal(t, "Q: abx\b \bc\r\n", out.String())

	_, err = (&terminalPrompt{in: strings.NewReader("x\x03"), out: io.Discard}).ask("Q: ", false)
	require.ErrorContains(t, err, "cancelled")

	answers, err := (&terminalPrompt{in: strings.NewReader("one\rtwo\r"), out: io.Discard}).challenge("", "", []string{"a", "b"}, []bool{true, false})
	require.NoError(t, err)
	require.Equal(t, []string{"one", "two"}, answers)
}

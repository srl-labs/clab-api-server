package capture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordedCommand struct {
	name string
	args []string
	env  []string
}

type fakeCommandRunner struct {
	t         *testing.T
	mu        sync.Mutex
	commands  []recordedCommand
	responses map[string]string
	errors    map[string]error
	onRun     func(recordedCommand)
}

func (r *fakeCommandRunner) Run(ctx context.Context, name string, args []string, env []string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cmd := recordedCommand{
		name: name,
		args: append([]string(nil), args...),
		env:  append([]string(nil), env...),
	}
	r.commands = append(r.commands, cmd)
	if r.onRun != nil {
		r.onRun(cmd)
	}

	key := commandKey(name, args)
	if err := r.errors[key]; err != nil {
		return "", err
	}
	if out, ok := r.responses[key]; ok {
		return out, nil
	}
	if r.t != nil {
		r.t.Fatalf("unexpected command: %s %s", name, strings.Join(args, " "))
	}
	return "", fmt.Errorf("unexpected command: %s %s", name, strings.Join(args, " "))
}

func (r *fakeCommandRunner) commandArgsContaining(parts ...string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, cmd := range r.commands {
		joined := strings.Join(cmd.args, " ")
		found := true
		for _, part := range parts {
			if !strings.Contains(joined, part) {
				found = false
				break
			}
		}
		if found {
			return append([]string(nil), cmd.args...)
		}
	}
	return nil
}

func (r *fakeCommandRunner) commandEnvContaining(parts ...string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, cmd := range r.commands {
		joined := strings.Join(cmd.env, " ")
		found := true
		for _, part := range parts {
			if !strings.Contains(joined, part) {
				found = false
				break
			}
		}
		if found {
			return append([]string(nil), cmd.env...)
		}
	}
	return nil
}

func commandKey(name string, args []string) string {
	return name + " " + strings.Join(args, " ")
}

func localPortFromServer(t *testing.T, server *httptest.Server) int {
	t.Helper()

	addr, err := net.ResolveTCPAddr("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("failed parsing test server address %q: %v", server.URL, err)
	}
	return addr.Port
}

func newTestManager(t *testing.T, cfg ManagerConfig) *Manager {
	t.Helper()

	m := NewManager(cfg)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		m.Shutdown(ctx)
	})
	return m
}

func TestParseExtraEnvVars(t *testing.T) {
	parsed := parseExtraEnvVars("HTTP_PROXY=http://proxy, http_proxy=http://proxy2,EMPTY=,MALFORMED")

	if got := parsed["HTTP_PROXY"]; got != "http://proxy" {
		t.Fatalf("unexpected HTTP_PROXY value: %q", got)
	}
	if got := parsed["http_proxy"]; got != "http://proxy2" {
		t.Fatalf("unexpected http_proxy value: %q", got)
	}
	if got := parsed["EMPTY"]; got != "" {
		t.Fatalf("unexpected EMPTY value: %q", got)
	}
	if got := parsed["MALFORMED"]; got != "" {
		t.Fatalf("unexpected MALFORMED value: %q", got)
	}
}

func TestInjectComposeEnvironment(t *testing.T) {
	input := []byte(`
services:
  gostwire:
    image: example
  edgeshark:
    image: example
`)

	output, err := injectComposeEnvironment(input, map[string]string{
		"HTTP_PROXY": "http://proxy",
	})
	if err != nil {
		t.Fatalf("injectComposeEnvironment returned error: %v", err)
	}

	text := string(output)
	if !strings.Contains(text, "HTTP_PROXY=http://proxy") {
		t.Fatalf("expected injected env var in output, got:\n%s", text)
	}
}

func TestBuildPacketflixURI(t *testing.T) {
	uri := buildPacketflixURI("localhost", 5001, "clab-lab-srl1", []string{"e1-1", "e1-2"}, 0)

	if !strings.HasPrefix(uri, "packetflix:ws://localhost:5001/capture?") {
		t.Fatalf("unexpected prefix: %s", uri)
	}
	if !strings.Contains(uri, "nif=e1-1%2Fe1-2") {
		t.Fatalf("expected encoded nif list in URI: %s", uri)
	}
}

func TestBuildPacketflixURIForHostInterface(t *testing.T) {
	netnsID, err := currentNetworkNamespaceID()
	if err != nil {
		t.Fatalf("failed resolving test network namespace: %v", err)
	}
	uri, err := buildPacketflixURIForSpec("localhost", 5001, ContainerCaptureSpec{
		ContainerName:        "clab-lab-sros1",
		InterfaceNames:       []string{"clab-s-12345678"},
		HostNetworkNamespace: true,
	})
	if err != nil {
		t.Fatalf("failed building host capture URI: %v", err)
	}

	parsed, err := url.Parse(strings.TrimPrefix(uri, "packetflix:"))
	if err != nil {
		t.Fatalf("failed parsing URI: %v", err)
	}
	var target map[string]any
	if err := json.Unmarshal([]byte(parsed.Query().Get("container")), &target); err != nil {
		t.Fatalf("failed parsing capture target: %v", err)
	}
	if target["netns"] != float64(netnsID) {
		t.Fatalf("unexpected host netns: %#v", target["netns"])
	}
	if _, exists := target["name"]; exists {
		t.Fatalf("host capture target must not include a Docker container name: %#v", target)
	}
}

func TestEdgeSharkStatusReportsRunningVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte("edgeshark-test-version\n"))
	}))
	defer server.Close()

	manager := newTestManager(t, ManagerConfig{PacketflixPort: localPortFromServer(t, server)})
	status, err := manager.Status(context.Background())
	if err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if !status.Running {
		t.Fatalf("expected EdgeShark to be reported as running")
	}
	if status.Version != "edgeshark-test-version" {
		t.Fatalf("unexpected version: %q", status.Version)
	}
}

func TestEdgeSharkStatusFallsBackToRunningRuntimeContainer(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	runner := &fakeCommandRunner{
		t: t,
		responses: map[string]string{
			commandKey("docker", edgeSharkStatusPsArgs()): "edgeshark-edgeshark-1 ghcr.io/siemens/packetflix\n",
		},
		errors: map[string]error{},
	}

	manager := newTestManager(t, ManagerConfig{PacketflixPort: localPortFromServer(t, server)})
	manager.runner = runner

	status, err := manager.Status(context.Background())
	if err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if !status.Running {
		t.Fatalf("expected EdgeShark to be reported as running")
	}
	if status.Version != "" {
		t.Fatalf("expected no version from runtime fallback, got %q", status.Version)
	}
}

func TestEdgeSharkStatusReportsNotRunningWithoutRuntimeContainer(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	runner := &fakeCommandRunner{
		t: t,
		responses: map[string]string{
			commandKey("docker", edgeSharkStatusPsArgs()): "",
		},
		errors: map[string]error{},
	}

	manager := newTestManager(t, ManagerConfig{PacketflixPort: localPortFromServer(t, server)})
	manager.runner = runner

	status, err := manager.Status(context.Background())
	if err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if status.Running {
		t.Fatalf("expected EdgeShark to be reported as not running")
	}
}

func TestBuildPacketflixURIsRequiresRunningEdgeShark(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	manager := newTestManager(t, ManagerConfig{PacketflixPort: localPortFromServer(t, server)})
	manager.runner = &fakeCommandRunner{
		t: t,
		responses: map[string]string{
			commandKey("docker", edgeSharkStatusPsArgs()): "",
		},
		errors: map[string]error{},
	}
	_, err := manager.BuildPacketflixURIs(context.Background(), []ContainerCaptureSpec{{
		ContainerName:  "clab-lab-srl1",
		InterfaceNames: []string{"eth1"},
	}}, "")
	if !errors.Is(err, ErrEdgeSharkNotRunning) {
		t.Fatalf("expected ErrEdgeSharkNotRunning, got %v", err)
	}
}

func TestBuildPacketflixURIsWithRunningEdgeShark(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	manager := newTestManager(t, ManagerConfig{
		PacketflixPort: localPortFromServer(t, server),
		RemoteHostname: "capture.example.test",
	})
	captures, err := manager.BuildPacketflixURIs(context.Background(), []ContainerCaptureSpec{{
		ContainerName:  "clab-lab-srl1",
		InterfaceNames: []string{"eth1", "eth2"},
	}}, "")
	if err != nil {
		t.Fatalf("BuildPacketflixURIs returned error: %v", err)
	}
	if len(captures) != 1 {
		t.Fatalf("expected one capture, got %d", len(captures))
	}
	if captures[0].ContainerName != "clab-lab-srl1" {
		t.Fatalf("unexpected container name: %q", captures[0].ContainerName)
	}
	if !reflect.DeepEqual(captures[0].InterfaceNames, []string{"eth1", "eth2"}) {
		t.Fatalf("unexpected interfaces: %#v", captures[0].InterfaceNames)
	}
	expectedPrefix := fmt.Sprintf("packetflix:ws://capture.example.test:%d/capture?", localPortFromServer(t, server))
	if !strings.HasPrefix(captures[0].URI, expectedPrefix) {
		t.Fatalf("unexpected packetflix URI prefix: %s", captures[0].URI)
	}
	if !strings.Contains(captures[0].URI, "nif=eth1%2Feth2") {
		t.Fatalf("expected encoded interface list in URI: %s", captures[0].URI)
	}
}

func TestCreateWiresharkSessionsBuildsRuntimeCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("edgeshark-ok"))
	}))
	defer server.Close()

	runner := &fakeCommandRunner{
		t: t,
		responses: map[string]string{
			commandKey("docker", []string{"ps", "--filter", "name=edgeshark", "--format", "{{.ID}}"}):           "edgeshark-container-id\n",
			commandKey("docker", []string{"inspect", "edgeshark-container-id"}):                                 `[{"NetworkSettings":{"Networks":{"edgeshark_default":{},"bridge":{}}}}]`,
			commandKey("docker", []string{"network", "connect", "edgeshark_default", "wireshark-container-id"}): "",
			commandKey("docker", []string{"rm", "-f", "wireshark-container-id"}):                                "wireshark-container-id\n",
		},
	}
	runner.responses[commandKey("docker", []string{
		"run",
		"-d",
		"--rm",
		"--name", "placeholder",
	})] = "unused"

	manager := newTestManager(t, ManagerConfig{
		Runtime:              "docker",
		PacketflixPort:       localPortFromServer(t, server),
		WiresharkDockerImage: "example/wireshark:test",
		WiresharkPullPolicy:  "never",
		WiresharkSessionTTL:  time.Hour,
	})
	manager.runner = runner
	runner.onRun = func(cmd recordedCommand) {
		if len(cmd.args) == 0 || cmd.args[0] != "run" {
			return
		}
		runner.responses[commandKey(cmd.name, cmd.args)] = "wireshark-container-id\n"
	}

	sessions, err := manager.CreateWiresharkSessions(context.Background(), CreateWiresharkSessionsOptions{
		Username: "test-user",
		LabName:  "lab1",
		Theme:    "dark",
		Specs: []ContainerCaptureSpec{{
			ContainerName:  "clab-lab1-srl1",
			InterfaceNames: []string{"eth1"},
			LabDirectory:   "/tmp/lab1",
		}},
	})
	if err != nil {
		t.Fatalf("CreateWiresharkSessions returned error: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected one session, got %d", len(sessions))
	}
	if sessions[0].ContainerName != "clab-lab1-srl1" {
		t.Fatalf("unexpected session container name: %q", sessions[0].ContainerName)
	}
	if !sessions[0].ShowVolumeTip {
		t.Fatalf("expected ShowVolumeTip for lab directory mount")
	}

	runArgs := runner.commandArgsContaining("run", "example/wireshark:test")
	if runArgs == nil {
		t.Fatalf("expected docker run command, got %#v", runner.commands)
	}
	joined := strings.Join(runArgs, " ")
	for _, expected := range []string{
		"-d --rm",
		"-p 127.0.0.1:",
		"-v /tmp/lab1:/pcaps",
		"-e PACKETFLIX_LINK=packetflix:ws://edgeshark-edgeshark-1:",
		"-e DARK_MODE=1",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected docker run args to contain %q, got: %s", expected, joined)
		}
	}
	if strings.Contains(joined, "--network") {
		t.Fatalf("expected wireshark container to stay on the default runtime network, got: %s", joined)
	}
	if strings.Contains(joined, "--add-host") {
		t.Fatalf("expected wireshark container to use edgeshark network instead of host gateway, got: %s", joined)
	}
	if connectArgs := runner.commandArgsContaining("network", "connect", "edgeshark_default", "wireshark-container-id"); connectArgs == nil {
		t.Fatalf("expected docker network connect command, got %#v", runner.commands)
	}
}

func TestInstallAndUninstallEdgeSharkUseComposeCommands(t *testing.T) {
	composeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`
services:
  gostwire:
    image: gostwire:test
  edgeshark:
    image: edgeshark:test
`))
	}))
	defer composeServer.Close()

	previousComposeURL := edgesharkComposeURL
	edgesharkComposeURL = composeServer.URL
	t.Cleanup(func() {
		edgesharkComposeURL = previousComposeURL
	})

	var composeFiles []string
	runner := &fakeCommandRunner{
		t: t,
		responses: map[string]string{
			"docker compose -f placeholder up -d": "",
			"docker compose -f placeholder down":  "",
		},
	}
	runner.onRun = func(cmd recordedCommand) {
		if len(cmd.args) < 4 || cmd.args[0] != "compose" || cmd.args[1] != "-f" {
			return
		}
		composeFiles = append(composeFiles, cmd.args[2])
		runner.responses[commandKey(cmd.name, cmd.args)] = ""
		normalized := []string{"compose", "-f", "placeholder"}
		normalized = append(normalized, cmd.args[3:]...)
		runner.responses[commandKey(cmd.name, normalized)] = ""
	}

	manager := newTestManager(t, ManagerConfig{
		Runtime:               "docker",
		EdgesharkExtraEnvVars: "HTTP_PROXY=http://proxy.example,NO_PROXY=localhost",
	})
	manager.runner = runner

	if err := manager.InstallEdgeShark(context.Background()); err != nil {
		t.Fatalf("InstallEdgeShark returned error: %v", err)
	}
	if err := manager.UninstallEdgeShark(context.Background()); err != nil {
		t.Fatalf("UninstallEdgeShark returned error: %v", err)
	}

	if env := runner.commandEnvContaining("DOCKER_DEFAULT_PLATFORM="); env == nil {
		t.Fatalf("expected compose commands to clear DOCKER_DEFAULT_PLATFORM, got %#v", runner.commands)
	}
	if len(composeFiles) != 2 {
		t.Fatalf("expected two compose files to be prepared, got %d", len(composeFiles))
	}
	upArgs := runner.commandArgsContaining("compose", "up", "-d")
	if upArgs == nil {
		t.Fatalf("expected compose up command, got %#v", runner.commands)
	}
	downArgs := runner.commandArgsContaining("compose", "down")
	if downArgs == nil {
		t.Fatalf("expected compose down command, got %#v", runner.commands)
	}
}

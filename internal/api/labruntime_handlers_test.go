package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	"github.com/stretchr/testify/require"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/srl-labs/clab-api-server/internal/auth"
	"github.com/srl-labs/clab-api-server/internal/capture"
	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/kube"
	"github.com/srl-labs/clab-api-server/internal/models"
	"github.com/srl-labs/clab-api-server/internal/testsupport/fakec9s"
)

// c9sAPI is the full router on a c9s server backed by the fake lab runtime.
type c9sAPI struct {
	t        *testing.T
	router   *gin.Engine
	fake     *fakec9s.Runtime
	svc      *clab.Service
	username string
	token    string
}

func newC9sAPI(t *testing.T) *c9sAPI {
	t.Helper()
	gin.SetMode(gin.TestMode)
	previous := config.AppConfig
	previousService := GetClabService()
	previousTerminals, previousSSH := terminalManager, sshManager
	previousStats := nodeStatsAvailable
	previousVnc := wiresharkVncProbe
	previousTickets := captureTicketStore()
	t.Cleanup(func() {
		config.AppConfig = previous
		SetClabService(previousService)
		ShutdownTerminalManager()
		ShutdownSSHManager()
		terminalManager, sshManager = previousTerminals, previousSSH
		nodeStatsAvailable = previousStats
		wiresharkVncProbe = previousVnc
		setCaptureTicketStore(previousTickets)
	})
	// No Docker for Wireshark VNC unless a test provides it.
	wiresharkVncProbe = func() bool { return false }
	setCaptureTicketStore(capture.NewTicketStore(capture.DefaultTicketTTL))
	config.AppConfig.ClabRuntime = config.RuntimeC9s
	config.AppConfig.JWTSecret = "test-secret"
	config.AppConfig.SuperuserGroup = ""
	config.AppConfig.ClabSharedLabsRoot = ""
	config.AppConfig.ClabC9sExposeType = "None"
	config.AppConfig.ClabC9sPersistence = true
	config.AppConfig.SSHBasePort = 39400
	config.AppConfig.SSHMaxPort = 39450
	setTestClabLabsRoot(t, filepath.Join(t.TempDir(), "labs"))

	fake := fakec9s.Install(t)
	svc := clab.NewService()
	SetClabService(svc)
	InitTerminalManager()
	InitSSHManager()

	current, err := user.Current()
	require.NoError(t, err)
	token, err := auth.GenerateJWT(current.Username, time.Hour)
	require.NoError(t, err)

	router := gin.New()
	SetupRoutes(router)
	return &c9sAPI{t: t, router: router, fake: fake, svc: svc, username: current.Username, token: token}
}

func (a *c9sAPI) do(method, target string, body []byte) *httptest.ResponseRecorder {
	a.t.Helper()
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+a.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	a.router.ServeHTTP(recorder, request)
	return recorder
}

// addLab stores a lab of the test user in the fake, in containerlab's default namespace.
func (a *c9sAPI) addLab(name string, nodes ...string) {
	a.fake.AddLab("c9s-"+name, name, a.username, "", nodes...)
}

func decodeError(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var response models.ErrorResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response), recorder.Body.String())
	return response.Error
}

func healthResponse(t *testing.T) models.HealthResponse {
	t.Helper()
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/health", nil)
	HealthCheckHandler(c)
	require.Equal(t, http.StatusOK, recorder.Code)
	var response models.HealthResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	return response
}

func TestHealthReportsTheRuntimeAndItsFeatures(t *testing.T) {
	previous := config.AppConfig
	previousStats := nodeStatsAvailable
	t.Cleanup(func() {
		config.AppConfig = previous
		nodeStatsAvailable = previousStats
	})

	previousVnc := wiresharkVncProbe
	t.Cleanup(func() { wiresharkVncProbe = previousVnc })
	wiresharkVncProbe = func() bool { return false }

	config.AppConfig.ClabRuntime = "docker"
	nodeStatsAvailable = nil
	docker := healthResponse(t)
	require.Equal(t, "docker", docker.Runtime)
	require.Empty(t, docker.NamespaceMode)
	require.Subset(t, docker.Features, []string{"snapshot-save", "deploy-restore", "sshx-readers", "gotty-options",
		"node-stats", "node-logs-runtime", "interface-state", "terminal-resume"})
	require.NotContains(t, docker.Features, "c9s-runtime")
	require.NotContains(t, docker.Features, "capture-stream", "Docker captures go through Edgeshark")
	require.Contains(t, docker.Features, "wireshark-vnc")

	config.AppConfig.ClabRuntime = "c9s"
	config.AppConfig.ClabKubeNamespace = ""
	SetNodeStatsAvailability(func() bool { return true })
	c9s := healthResponse(t)
	require.Equal(t, "c9s", c9s.Runtime)
	require.Equal(t, "per-lab", c9s.NamespaceMode)
	require.Subset(t, c9s.Features, []string{"c9s-runtime", "node-logs-runtime", "interface-state", "node-stats",
		"terminal-resume", "log-stream", "validate", "graph-mermaid", "graph-dot", "exec-filters", "save-copy"})
	for _, feature := range []string{"snapshot-save", "deploy-restore", "sshx-readers", "gotty-options"} {
		require.NotContains(t, c9s.Features, feature)
	}
	require.Contains(t, c9s.Features, "capture-stream")
	require.NotContains(t, c9s.Features, "wireshark-vnc", "no Docker on the server host")
	wiresharkVncProbe = func() bool { return true }
	require.Contains(t, healthResponse(t).Features, "wireshark-vnc", "Docker on the server host")

	SetNodeStatsAvailability(func() bool { return false })
	withoutMetrics := healthResponse(t)
	require.NotContains(t, withoutMetrics.Features, "node-stats")
	require.Equal(t, "per-lab", withoutMetrics.NamespaceMode)
}

func TestContainerRuntimeRoutesAnswer501OnC9s(t *testing.T) {
	api := newC9sAPI(t)
	api.addLab("lab1", "n1")
	for _, route := range []struct{ method, target string }{
		{http.MethodGet, "/api/v1/health/metrics"},
		{http.MethodGet, "/api/v1/images"},
		{http.MethodPost, "/api/v1/images/pull"},
		{http.MethodDelete, "/api/v1/images"},
		{http.MethodGet, "/api/v1/labs/lab1/links"},
		{http.MethodPost, "/api/v1/labs/lab1/snapshots"},
		{http.MethodPost, "/api/v1/labs/lab1/capture/packetflix"},
		{http.MethodPost, "/api/v1/labs/lab1/capture/wireshark-vnc-sessions"},
		{http.MethodPost, "/api/v1/labs/lab1/sshx/attach"},
		{http.MethodPost, "/api/v1/labs/lab1/gotty/attach"},
		{http.MethodPost, "/api/v1/labs/lab1/fcli"},
		{http.MethodGet, "/api/v1/labs/lab1/tailscale"},
		{http.MethodPost, "/api/v1/labs/lab1/nodes/n1/pause"},
		{http.MethodPost, "/api/v1/labs/lab1/nodes/n1/unpause"},
		{http.MethodDelete, "/api/v1/capture/wireshark-vnc-sessions"},
		{http.MethodGet, "/api/v1/tools/edgeshark/status"},
		{http.MethodPost, "/api/v1/tools/edgeshark/install"},
		{http.MethodPost, "/api/v1/tools/disable-tx-offload"},
		{http.MethodPost, "/api/v1/tools/veth"},
		{http.MethodPost, "/api/v1/tools/vxlan"},
		{http.MethodPost, "/api/v1/tools/netem/set"},
		{http.MethodGet, "/api/v1/tools/netem/show"},
	} {
		recorder := api.do(route.method, route.target, nil)
		require.Equal(t, http.StatusNotImplemented, recorder.Code, "%s %s: %s", route.method, route.target, recorder.Body.String())
		require.Contains(t, decodeError(t, recorder), "not supported by lab runtime c9s", route.target)
	}
	require.Empty(t, api.fake.CallsOf("deploy"))
}

func TestRequireContainerRuntimePassesOnDocker(t *testing.T) {
	previous := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previous })
	config.AppConfig.ClabRuntime = "docker"
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/x", requireContainerRuntime("images"), func(c *gin.Context) { c.Status(http.StatusTeapot) })
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/x", nil))
	require.Equal(t, http.StatusTeapot, recorder.Code)
}

func TestInspectListAndLifecycleOnC9s(t *testing.T) {
	api := newC9sAPI(t)
	api.addLab("lab1", "n1", "n2")
	api.fake.AddLab("c9s-other", "other", "someone-else", "", "n1")

	recorder := api.do(http.MethodGet, "/api/v1/labs/lab1", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var nodes []models.ClabContainerInfo
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &nodes))
	require.Len(t, nodes, 2)
	require.Equal(t, "c9s-lab1", nodes[0].Namespace)
	require.Equal(t, "c9s-lab1/lab1/n1", nodes[0].ContainerID)
	require.Equal(t, "lab1-n1-pod", nodes[0].Pod)
	require.Equal(t, "running", nodes[0].State, "Docker's state vocabulary")
	require.Equal(t, "healthy", nodes[0].Status)

	recorder = api.do(http.MethodGet, "/api/v1/labs", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var labs models.ClabInspectOutput
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &labs))
	require.Contains(t, labs, "lab1")
	require.NotContains(t, labs, "other", "labs of other users stay hidden")

	recorder = api.do(http.MethodGet, "/api/v1/labs/other", nil)
	require.Equal(t, http.StatusNotFound, recorder.Code)

	recorder = api.do(http.MethodPost, "/api/v1/labs/lab1/stop?nodeFilter=n1", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Equal(t, []string{"n1"}, api.fake.CallsOf("stop")[0].Nodes)

	recorder = api.do(http.MethodPost, "/api/v1/labs/lab1/nodes/lab1-n2/restart", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Equal(t, []string{"n2"}, api.fake.CallsOf("restart")[0].Nodes)

	recorder = api.do(http.MethodPost, "/api/v1/labs/lab1/exec", []byte(`{"command":"ip a"}`))
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Contains(t, recorder.Body.String(), "ran ip a on n1")

	recorder = api.do(http.MethodPost, "/api/v1/labs/lab1/save", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Len(t, api.fake.CallsOf("save"), 1)

	recorder = api.do(http.MethodDelete, "/api/v1/labs/lab1?cleanup=true", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	destroys := api.fake.CallsOf("destroy")
	require.Len(t, destroys, 1)
	require.True(t, destroys[0].Cleanup)

	api.addLab("lab2", "n1")
	recorder = api.do(http.MethodDelete, "/api/v1/labs/lab2?graceful=true", nil)
	require.Equal(t, http.StatusNotImplemented, recorder.Code, recorder.Body.String())
}

func TestDeployOnC9sRejectsNamesKubernetesCannotCarry(t *testing.T) {
	api := newC9sAPI(t)
	body := []byte(`{"topologyContent":{"name":"Bad_Lab","topology":{"nodes":{"n1":{"kind":"linux","image":"alpine"}}}}}`)
	recorder := api.do(http.MethodPost, "/api/v1/labs", body)
	require.Equal(t, http.StatusBadRequest, recorder.Code, recorder.Body.String())
	require.Contains(t, decodeError(t, recorder), `"bad-lab"`)

	body = []byte(`{"topologyContent":{"name":"good-lab","topology":{"nodes":{"n1":{"kind":"linux","image":"alpine"}}}}}`)
	recorder = api.do(http.MethodPost, "/api/v1/labs?nodeFilter=n1", body)
	require.Equal(t, http.StatusNotImplemented, recorder.Code, recorder.Body.String())

	recorder = api.do(http.MethodPost, "/api/v1/labs", body)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	deploys := api.fake.CallsOf("deploy")
	require.Len(t, deploys, 1)
	require.Equal(t, "c9s-good-lab", deploys[0].Namespace)
	require.Equal(t, api.username, deploys[0].Owner)
}

func TestNodeLogsOnC9s(t *testing.T) {
	api := newC9sAPI(t)
	api.addLab("lab1", "n1")
	api.fake.Logs = "2026-10-27T10:00:00Z booted\n2026-10-27T10:00:01Z ready\n"

	recorder := api.do(http.MethodGet, "/api/v1/labs/lab1/nodes/lab1-n1/logs?tail=10", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var logs models.LogsResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &logs))
	require.Equal(t, "lab1-n1", logs.ContainerName)
	require.Equal(t, api.fake.Logs, logs.Logs)
	call := api.fake.CallsOf("logs")[0]
	require.Equal(t, []string{"n1"}, call.Nodes)
	require.Equal(t, 10, call.Port, "tail reaches the runtime")

	recorder = api.do(http.MethodGet, "/api/v1/labs/lab1/nodes/lab1-n1/logs?follow=true", nil)
	require.Equal(t, http.StatusOK, recorder.Code)
	var lines []models.LogLine
	scanner := bufio.NewScanner(bytes.NewReader(recorder.Body.Bytes()))
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var line models.LogLine
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &line))
		lines = append(lines, line)
	}
	require.Len(t, lines, 2)
	require.Equal(t, "stdout", lines[0].Stream)
	require.Contains(t, lines[1].Line, "ready")

	recorder = api.do(http.MethodGet, "/api/v1/labs/lab1/nodes/lab1-missing/logs", nil)
	require.Equal(t, http.StatusNotFound, recorder.Code)
	recorder = api.do(http.MethodGet, "/api/v1/labs/lab1/nodes/clab-otherlab-n1/logs", nil)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	recorder = api.do(http.MethodGet, "/api/v1/labs/lab1/nodes/lab1-n1/logs?tail=-1", nil)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestTerminalSessionsOnC9s(t *testing.T) {
	api := newC9sAPI(t)
	api.addLab("lab1", "n1")

	recorder := api.do(http.MethodPost, "/api/v1/labs/lab1/nodes/n1/terminal-sessions",
		[]byte(`{"protocol":"shell","cols":90,"rows":20,"resumable":true}`))
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var info models.TerminalSessionInfo
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &info))
	require.True(t, info.Resumable)

	session, attachment, err := terminalManager.Attach(info.SessionID, api.username, false)
	require.NoError(t, err)
	output := readAttachmentUntil(t, attachment.Replay, attachment.Output(), "sh$ ")
	require.Contains(t, output, "sh$ ")
	require.NoError(t, session.Resize(100, 40))
	require.Eventually(t, func() bool {
		sizes := api.fake.Resizes()
		return len(sizes) > 0 && sizes[len(sizes)-1] == clablabruntime.TerminalSize{Width: 100, Height: 40}
	}, 3*time.Second, 20*time.Millisecond)
	require.NoError(t, session.WriteInput("hi\n"))
	readAttachmentUntil(t, nil, attachment.Output(), "echo: hi")
	attach := api.fake.CallsOf("attach")[0]
	require.Equal(t, "c9s-lab1", attach.Namespace)
	require.Equal(t, []string{"n1"}, attach.Nodes)
	session.Terminate("done")

	recorder = api.do(http.MethodPost, "/api/v1/labs/lab1/nodes/n1/terminal-sessions", []byte(`{"protocol":"ssh"}`))
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Eventually(t, func() bool { return len(api.fake.CallsOf("dial")) == 1 }, 3*time.Second, 20*time.Millisecond)
	require.Equal(t, 22, api.fake.CallsOf("dial")[0].Port)
}

func readAttachmentUntil(t *testing.T, replay []byte, output <-chan []byte, want string) string {
	t.Helper()
	got := string(replay)
	deadline := time.After(5 * time.Second)
	for !strings.Contains(got, want) {
		select {
		case chunk, open := <-output:
			require.True(t, open, "output ended before %q; got %q", want, got)
			got += string(chunk)
		case <-deadline:
			t.Fatalf("timed out waiting for %q; got %q", want, got)
		}
	}
	return got
}

func TestLoadBalancerSSHTarget(t *testing.T) {
	_, _, ok := loadBalancerSSHTarget(&models.ClabContainerInfo{ExposedPorts: []models.ClabExposedPort{{Port: 22, ExposePort: 22}}})
	require.False(t, ok, "no address, no direct target")
	address, port, ok := loadBalancerSSHTarget(&models.ClabContainerInfo{
		LoadBalancerAddress: "203.0.113.5",
		ExposedPorts:        []models.ClabExposedPort{{Port: 80, ExposePort: 80, Protocol: "tcp"}, {Port: 22, ExposePort: 2222, Protocol: "tcp"}},
	})
	require.True(t, ok)
	require.Equal(t, "203.0.113.5", address)
	require.Equal(t, 2222, port)
}

func TestSSHAccessProxiesThroughThePortForward(t *testing.T) {
	api := newC9sAPI(t)
	api.addLab("lab1", "n1")

	recorder := api.do(http.MethodPost, "/api/v1/labs/lab1/nodes/lab1-n1/ssh", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var access models.SSHAccessResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &access))

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", access.Port))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte("SSH-2.0-test\r\n"))
	require.NoError(t, err)
	buffer := make([]byte, 14)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(conn, buffer)
	require.NoError(t, err)
	require.Equal(t, "SSH-2.0-test\r\n", string(buffer))
	dial := api.fake.CallsOf("dial")[0]
	require.Equal(t, 22, dial.Port)
	require.Equal(t, []string{"n1"}, dial.Nodes)

	recorder = api.do(http.MethodPost, "/api/v1/labs/lab1/nodes/clab-other-n1/ssh", nil)
	require.Equal(t, http.StatusNotFound, recorder.Code)
}

func TestStatsOnC9s(t *testing.T) {
	api := newC9sAPI(t)
	api.addLab("lab1", "n1")
	api.fake.Stats = []clablabruntime.NodeStats{{NodeName: "n1", CPUMilliCores: 250, MemoryBytes: 64 << 20}}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/labs/lab1/stats?interval=1s", nil).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer "+api.token)
	recorder := httptest.NewRecorder()
	api.router.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	firstLine, _, _ := strings.Cut(strings.TrimSpace(recorder.Body.String()), "\n")
	var sample models.LabStatsSample
	require.NoError(t, json.Unmarshal([]byte(firstLine), &sample))
	require.Len(t, sample.Nodes, 1)
	require.Equal(t, "lab1-n1", sample.Nodes[0].Name)
	require.Equal(t, 25.0, *sample.Nodes[0].CPUPercent)
	require.Equal(t, uint64(64<<20), sample.Nodes[0].MemoryBytes)

	api.fake.StatsErr = fakec9s.ErrMetricsUnavailable
	recorder = api.do(http.MethodGet, "/api/v1/labs/lab1/stats", nil)
	require.Equal(t, http.StatusNotImplemented, recorder.Code, recorder.Body.String())
	require.Contains(t, decodeError(t, recorder), "metrics.k8s.io")
}

func TestBrowserPortsAndProxyOnC9s(t *testing.T) {
	api := newC9sAPI(t)
	api.fake.ExposedPorts = []clablabruntime.ExposedPort{{Port: 80, ExposePort: 80, Protocol: "tcp"}, {Port: 161, ExposePort: 161, Protocol: "udp"}}
	api.addLab("lab1", "n1")
	seen := make(chan *http.Request, 1)
	api.fake.PortHandler = func(port int, conn net.Conn) {
		defer func() { _ = conn.Close() }()
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		seen <- request
		body := fmt.Sprintf("port %d path %s", port, request.URL.Path)
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n%s", len(body), body)
	}

	recorder := api.do(http.MethodGet, "/api/v1/labs/lab1/nodes/n1/browser-ports", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var ports models.NodeBrowserPortsResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &ports))
	require.Len(t, ports.Ports, 1, "only TCP ports can be browsed")
	require.Equal(t, 80, ports.Ports[0].ContainerPort)
	require.Equal(t, "/api/v1/labs/lab1/nodes/n1/ports/80/proxy/", ports.Ports[0].ProxyPath)

	// The reverse proxy needs a real connection (CloseNotify), so this goes through a server.
	server := httptest.NewServer(api.router)
	defer server.Close()
	request, err := http.NewRequest(http.MethodGet, server.URL+ports.Ports[0].ProxyPath+"ui/index.html", nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+api.token)
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode, string(body))
	require.Equal(t, "port 80 path /ui/index.html", string(body))
	forwarded := <-seen
	require.Empty(t, forwarded.Header.Get("Authorization"), "the API token never reaches the node")

	recorder = api.do(http.MethodGet, "/api/v1/labs/lab1/nodes/n1/ports/0/proxy/", nil)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	recorder = api.do(http.MethodGet, "/api/v1/labs/lab1/nodes/missing/ports/80/proxy/", nil)
	require.Equal(t, http.StatusNotFound, recorder.Code)
}

func TestNodePortProxyNeedsALabRuntime(t *testing.T) {
	previous := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previous })
	config.AppConfig.ClabRuntime = "docker"
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Any("/labs/:labName/nodes/:nodeName/ports/:port/proxy/*proxyPath", ProxyNodePortHandler)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/labs/lab1/nodes/n1/ports/80/proxy/", nil))
	require.Equal(t, http.StatusNotImplemented, recorder.Code)
}

func TestEventsOnC9s(t *testing.T) {
	api := newC9sAPI(t)
	api.addLab("lab1", "n1")
	api.fake.AddLab("c9s-other", "other", "someone-else", "", "n1")

	// The events stream watches the connection (CloseNotify), so it needs a real server.
	server := httptest.NewServer(api.router)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/v1/events", nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+api.token)
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, http.StatusOK, response.StatusCode)
	body, _ := io.ReadAll(response.Body) // ends at the deadline

	type event struct {
		Type       string            `json:"type"`
		Action     string            `json:"action"`
		ActorID    string            `json:"actor_id"`
		Attributes map[string]string `json:"attributes"`
	}
	var events []event
	for _, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var parsed event
		require.NoError(t, json.Unmarshal([]byte(line), &parsed), line)
		require.Equal(t, "c9s-lab1", parsed.Attributes["namespace"], "events of other users' labs are filtered: %s", line)
		events = append(events, parsed)
	}
	require.Len(t, events, 2)

	// containerlab describes c9s nodes with the attributes of Docker events, so the server's
	// own ownership check reads the same labels as for Docker.
	container := events[0]
	require.Equal(t, "container", container.Type)
	require.Equal(t, "start", container.Action)
	require.Equal(t, "c9s-lab1/lab1/n1", container.ActorID)
	for key, value := range map[string]string{
		"containerlab": "lab1", "clab-node-name": "n1", "clab-node-longname": "lab1-n1", "clab-node-kind": "linux",
		"clab-owner": api.username, "clab-topo-file": "k8s://c9s-lab1/topologies/lab1", "image": "alpine",
		"mgmt_ipv4": "10.0.0.1/32", "state": "running",
	} {
		require.Equal(t, value, container.Attributes[key], "attribute %s", key)
	}
	iface := events[1]
	require.Equal(t, "interface", iface.Type)
	require.Equal(t, "create", iface.Action)
	for key, value := range map[string]string{
		"lab": "lab1", "ifname": "eth1", "state": "up", "type": "veth", "mtu": "9500", "mac": "aa:c1:ab:00:00:01",
	} {
		require.Equal(t, value, iface.Attributes[key], "attribute %s", key)
	}
}

func TestKubeUsersInWorkspace(t *testing.T) {
	labsRoot := t.TempDir()
	setTestClabLabsRoot(t, labsRoot)
	current, err := user.Current()
	require.NoError(t, err)
	workspace := filepath.Join(labsRoot, current.Username)
	require.NoError(t, os.MkdirAll(filepath.Join(workspace, "demo"), 0o755))
	outside := t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(workspace, "escape")))

	users := KubeUsers()
	require.True(t, users.InWorkspace(current.Username, filepath.Join(workspace, "demo", "demo.clab.yml")))
	require.True(t, users.InWorkspace(current.Username, filepath.Join(workspace, "new", "new.clab.yml")), "a file that is gone by now")
	require.False(t, users.InWorkspace(current.Username, workspace), "the workspace itself")
	require.False(t, users.InWorkspace(current.Username, filepath.Join(workspace, "..", "other", "x.clab.yml")))
	require.False(t, users.InWorkspace(current.Username, filepath.Join(workspace, "escape", "x.clab.yml")), "a symbolic link out of the workspace")
	require.False(t, users.InWorkspace(current.Username, "demo/demo.clab.yml"), "a relative path")
	require.False(t, users.InWorkspace(current.Username, "/etc/passwd"))
	require.False(t, users.InWorkspace("no-such-user-c9s", filepath.Join(workspace, "demo", "demo.clab.yml")))
}

// TestEventsAndInspectAgreeOnc9s runs the events stream and inspect with the c9s scoper after
// the user edited the Topology's owner label and topology file annotation: both report the
// server's records, never the edited values.
func TestEventsAndInspectAgreeOnc9s(t *testing.T) {
	api := newC9sAPI(t)
	labsRoot := t.TempDir()
	setTestClabLabsRoot(t, labsRoot)
	topology := filepath.Join(labsRoot, api.username, "lab1", "lab1.clab.yml")
	require.NoError(t, os.MkdirAll(filepath.Dir(topology), 0o755))
	require.NoError(t, os.WriteFile(topology, []byte("name: lab1\n"), 0o644))
	provisioner := kube.NewProvisioner(k8sfake.NewClientset(), nil, kube.Settings{
		UserPrefix: "clab:", NamespaceTemplate: kube.DefaultNamespaceTemplate,
	})
	scoper := kube.NewScoper(provisioner, KubeUsers())
	scope, err := scoper.PrepareDeploy(context.Background(), api.username, "lab1", topology)
	require.NoError(t, err)
	api.svc.SetLabScoper(scoper)
	api.fake.AddLab(scope.Namespace, "lab1", api.username, topology, "n1")

	streamed := func() map[string]string {
		t.Helper()
		server := httptest.NewServer(api.router)
		defer server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/v1/events", nil)
		require.NoError(t, err)
		request.Header.Set("Authorization", "Bearer "+api.token)
		response, err := http.DefaultClient.Do(request)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()
		body, _ := io.ReadAll(response.Body)
		for _, line := range strings.Split(string(body), "\n") {
			var event struct {
				Type       string            `json:"type"`
				Attributes map[string]string `json:"attributes"`
			}
			if json.Unmarshal([]byte(line), &event) == nil && event.Type == "container" {
				return event.Attributes
			}
		}
		t.Fatalf("no container event in %q", body)
		return nil
	}
	inspected := func() models.ClabContainerInfo {
		t.Helper()
		recorder := api.do(http.MethodGet, "/api/v1/labs/lab1", nil)
		require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
		var nodes []models.ClabContainerInfo
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &nodes))
		require.Len(t, nodes, 1)
		return nodes[0]
	}

	attributes, node := streamed(), inspected()
	require.Equal(t, topology, attributes["clab-topo-file"])
	require.Equal(t, api.username, attributes["clab-owner"])
	require.Equal(t, node.AbsLabPath, attributes["clab-topo-file"])
	require.Equal(t, node.Owner, attributes["clab-owner"])

	state := api.fake.Lab(scope.Namespace, "lab1")
	state.Owner, state.TopologyPath = "mallory", "/etc/shadow"
	attributes, node = streamed(), inspected()
	require.Equal(t, "k8s://"+scope.Namespace+"/topologies/lab1", attributes["clab-topo-file"])
	require.Equal(t, api.username, attributes["clab-owner"])
	require.Equal(t, node.AbsLabPath, attributes["clab-topo-file"], "events and inspect agree")
	require.Equal(t, node.Owner, attributes["clab-owner"])
}

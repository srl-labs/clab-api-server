package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/srl-labs/clab-api-server/internal/fcling"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// fclingDocker puts a docker command on PATH that logs its arguments and answers `container
// inspect` with <dir>/inspect.json, or as the runtime does for a container that does not
// exist. It makes the real manager the server's. It returns the directory.
func fclingDocker(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
dir="` + dir + `"
printf '%s\n' "$*" >> "$dir/docker.log"
if [ "$1 $2" = "container inspect" ]; then
	if [ -f "$dir/inspect.json" ]; then
		cat "$dir/inspect.json"
		exit 0
	fi
	echo "Error response from daemon: No such container: $3" >&2
	exit 1
fi
if [ "$1" = "logs" ]; then
	echo "it failed like this"
fi
exit 0
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	fclingManagerMu.Lock()
	previous := fclingManager
	fclingManager = fcling.NewManager(fcling.Config{Runtime: "docker", StateDir: filepath.Join(dir, "state")})
	fclingManagerMu.Unlock()
	t.Cleanup(func() {
		ShutdownFclingManager()
		fclingManagerMu.Lock()
		fclingManager = previous
		fclingManagerMu.Unlock()
	})
	return dir
}

func fclingDockerLog(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "docker.log"))
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func writeFclingContainer(t *testing.T, dir, status string, running bool, hostPort, token string) {
	t.Helper()
	encoded, err := json.Marshal([]any{map[string]any{
		"State":  map[string]any{"Status": status, "Running": running, "StartedAt": "2026-11-05T14:08:47Z"},
		"Config": map[string]any{"Image": "example/fcling:test", "Env": []string{"FCLI_API_TOKEN=" + token}},
		"NetworkSettings": map[string]any{
			"Ports": map[string]any{"8765/tcp": []map[string]string{{"HostIp": "127.0.0.1", "HostPort": hostPort}}},
		},
	}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "inspect.json"), encoded, 0o644))
}

// fclingEngineRoutes serves the engine handlers without their runtime guard: the fake lab
// lives on the c9s runtime, and what the guard does is tested on its own.
func fclingEngineRoutes(api *c9sAPI) *gin.Engine {
	router := gin.New()
	labs := router.Group("/labs/:labName", func(c *gin.Context) { c.Set("username", api.username) })
	labs.GET("/fcling/engine", GetFclingEngineHandler)
	labs.POST("/fcling/engine", StartFclingEngineHandler)
	labs.DELETE("/fcling/engine", StopFclingEngineHandler)
	labs.Any("/fcling/api/*proxyPath", ProxyFclingAPIHandler)
	return router
}

func fclingRequest(router http.Handler, method, target string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(method, target, nil))
	return recorder
}

func portOf(t *testing.T, server *httptest.Server) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	require.NoError(t, err)
	return port
}

func TestFclingEngineStatusThroughTheRoute(t *testing.T) {
	api := newC9sAPI(t)
	api.addLab("lab1", "n1")
	dir := fclingDocker(t)
	router := fclingEngineRoutes(api)

	recorder := fclingRequest(router, http.MethodGet, "/labs/lab1/fcling/engine")
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.JSONEq(t, `{"state":"stopped","gnmiPort":57400}`, recorder.Body.String(), "empty fields are left out")

	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer engine-token" {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer engine.Close()
	writeFclingContainer(t, dir, "running", true, portOf(t, engine), "engine-token")
	recorder = fclingRequest(router, http.MethodGet, "/labs/lab1/fcling/engine")
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.JSONEq(t, `{"state":"ready","image":"example/fcling:test","containerName":"clab-lab1-fcling","startedAt":"2026-11-05T14:08:47Z","gnmiPort":57400}`, recorder.Body.String())

	writeFclingContainer(t, dir, "exited", false, "", "engine-token")
	recorder = fclingRequest(router, http.MethodGet, "/labs/lab1/fcling/engine")
	var status models.FclingEngineStatus
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &status))
	require.Equal(t, fcling.StateFailed, status.State)
	require.Equal(t, "it failed like this", status.Error)

	recorder = fclingRequest(router, http.MethodDelete, "/labs/lab1/fcling/engine")
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.JSONEq(t, `{"state":"stopped"}`, recorder.Body.String())
	log := fclingDockerLog(t, dir)
	require.Contains(t, log, "rm -f clab-lab1-fcling")
	require.NotContains(t, log, "volume rm -f clab-lab1-fcling", "stopping keeps the history")
}

func TestFclingEngineStartRefusesWhatIsNotAGnmiPort(t *testing.T) {
	api := newC9sAPI(t)
	api.addLab("lab1", "n1")
	dir := fclingDocker(t)
	router := fclingEngineRoutes(api)

	for body, want := range map[string]string{
		`{"gnmiPort":70000}`:   "between 1 and 65535",
		`{"gnmiPort":-1}`:      "between 1 and 65535",
		`{"gnmiPort":"57410"}`: "Invalid request body",
		`not json`:             "Invalid request body",
	} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/labs/lab1/fcling/engine", strings.NewReader(body))
		router.ServeHTTP(recorder, request)
		require.Equal(t, http.StatusBadRequest, recorder.Code, body)
		require.Contains(t, recorder.Body.String(), want, body)
	}
	require.Empty(t, fclingDockerLog(t, dir), "nothing is started")
}

func TestFclingEngineRoutesCheckTheLab(t *testing.T) {
	api := newC9sAPI(t)
	fclingDocker(t)
	router := fclingEngineRoutes(api)

	require.Equal(t, http.StatusNotFound, fclingRequest(router, http.MethodGet, "/labs/nolab/fcling/engine").Code)
	require.Equal(t, http.StatusNotFound, fclingRequest(router, http.MethodGet, "/labs/nolab/fcling/api/status").Code)
	require.Equal(t, http.StatusBadRequest, fclingRequest(router, http.MethodGet, "/labs/bad%20name/fcling/engine").Code)
}

func TestFclingProxyRefusesWhatIsNotTheFabricAPI(t *testing.T) {
	api := newC9sAPI(t)
	api.addLab("lab1", "n1")
	dir := fclingDocker(t)
	router := fclingEngineRoutes(api)

	for _, request := range []struct{ method, path string }{
		{http.MethodPost, "chat"},
		{http.MethodGet, "chat"},
		{http.MethodGet, "mcp"},
		{http.MethodPost, "mcp"},
		{http.MethodGet, "openapi.json"},
		{http.MethodGet, ""},
		{http.MethodPut, "acks"},
		{http.MethodPost, "status"},
	} {
		recorder := fclingRequest(router, request.method, "/labs/lab1/fcling/api/"+request.path)
		require.Equal(t, http.StatusForbidden, recorder.Code, "%s %s: %s", request.method, request.path, recorder.Body.String())
		require.NotEmpty(t, decodeError(t, recorder))
	}
	require.Empty(t, fclingDockerLog(t, dir), "nothing refused reaches the runtime")
}

func TestFclingProxyWithoutARunningEngineConflicts(t *testing.T) {
	api := newC9sAPI(t)
	api.addLab("lab1", "n1")
	dir := fclingDocker(t)
	router := fclingEngineRoutes(api)

	recorder := fclingRequest(router, http.MethodGet, "/labs/lab1/fcling/api/status")
	require.Equal(t, http.StatusConflict, recorder.Code, recorder.Body.String())
	require.Contains(t, decodeError(t, recorder), "is not running")

	writeFclingContainer(t, dir, "exited", false, "", "engine-token")
	require.Equal(t, http.StatusConflict, fclingRequest(router, http.MethodGet, "/labs/lab1/fcling/api/status").Code)
}

func TestFclingProxyInjectsTheTokenAndStreams(t *testing.T) {
	api := newC9sAPI(t)
	api.addLab("lab1", "n1")
	dir := fclingDocker(t)

	release := make(chan struct{})
	defer close(release)
	seen := make(chan *http.Request, 1)
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Clone(context.Background())
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "event: status\ndata: {}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer engine.Close()
	writeFclingContainer(t, dir, "running", true, portOf(t, engine), "engine-token")

	server := httptest.NewServer(fclingEngineRoutes(api))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/labs/lab1/fcling/api/events?after=7", nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer the-users-jwt")
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "text/event-stream", response.Header.Get("Content-Type"))

	// The first event comes through while the stream stays open.
	line, err := bufio.NewReader(response.Body).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "event: status\n", line)

	upstream := <-seen
	require.Equal(t, "Bearer engine-token", upstream.Header.Get("Authorization"))
	require.Equal(t, "/api/events", upstream.URL.Path)
	require.Equal(t, "7", upstream.URL.Query().Get("after"))
	require.NotContains(t, fmt.Sprint(upstream.Header), "the-users-jwt")
}

func TestFclingProxyPassesAcknowledgements(t *testing.T) {
	api := newC9sAPI(t)
	api.addLab("lab1", "n1")
	dir := fclingDocker(t)

	var method, path, body string
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		method, path, body = r.Method, r.URL.Path, string(data)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"incident":"x"}`))
	}))
	defer engine.Close()
	writeFclingContainer(t, dir, "running", true, portOf(t, engine), "engine-token")

	server := httptest.NewServer(fclingEngineRoutes(api))
	defer server.Close()
	response, err := http.Post(server.URL+"/labs/lab1/fcling/api/acks", "application/json", strings.NewReader(`{"incident":"x"}`))
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, http.MethodPost, method)
	require.Equal(t, "/api/acks", path)
	require.JSONEq(t, `{"incident":"x"}`, body)
}

func TestDestroyRemovesTheFclingEngineAndItsHistory(t *testing.T) {
	api := newC9sAPI(t)
	api.addLab("lab1", "n1")
	dir := fclingDocker(t)

	recorder := api.do(http.MethodDelete, "/api/v1/labs/lab1", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

	log := fclingDockerLog(t, dir)
	require.Contains(t, log, "stop -t 5 clab-lab1-fcling")
	require.Contains(t, log, "rm -f clab-lab1-fcling")
	require.Contains(t, log, "volume rm -f clab-lab1-fcling")
}

func TestRedeployStopsTheFclingEngineAndKeepsItsHistory(t *testing.T) {
	api := newC9sAPI(t)
	dir := fclingDocker(t)
	body := []byte(`{"topologyContent":{"name":"again","topology":{"nodes":{"n1":{"kind":"linux","image":"alpine"}}}}}`)
	recorder := api.do(http.MethodPost, "/api/v1/labs", body)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Empty(t, fclingDockerLog(t, dir), "a new lab has no engine to stop")

	recorder = api.do(http.MethodPut, "/api/v1/labs/again", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

	log := fclingDockerLog(t, dir)
	require.Contains(t, log, "rm -f clab-again-fcling")
	require.NotContains(t, log, "volume rm -f clab-again-fcling")
}

func TestLifecycleWithoutAFclingManager(t *testing.T) {
	api := newC9sAPI(t)
	api.addLab("lab1", "n1")
	require.Nil(t, GetFclingManager(), "a lab runtime has no engines")
	InitFclingManager()
	require.Nil(t, GetFclingManager())
	recorder := api.do(http.MethodDelete, "/api/v1/labs/lab1", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
}

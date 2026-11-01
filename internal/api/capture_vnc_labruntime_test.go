package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	"github.com/stretchr/testify/require"

	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// fakeDocker puts a docker command on PATH that logs its arguments, answers run with the
// container's name as its ID, and plays the capture pipe for exec: it reports the pipe open
// and appends its stdin to <dir>/pipe-<container>. It returns the directory.
func fakeDocker(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
dir="` + dir + `"
case "$1" in
run)
	printf '%s\n' "$*" >> "$dir/docker.log"
	prev=""
	for arg in "$@"; do
		[ "$prev" = "--name" ] && name="$arg"
		prev="$arg"
	done
	echo "$name"
	;;
exec)
	printf 'exec %s\n' "$3" >> "$dir/docker.log"
	echo open
	exec cat >> "$dir/pipe-$3"
	;;
*)
	printf '%s\n' "$*" >> "$dir/docker.log"
	;;
esac
exit 0
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

// dockerLog returns the lines the fake docker logged.
func dockerLog(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "docker.log"))
	require.NoError(t, err)
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

// pipeContent returns what the server wrote into the capture pipe of a node's session.
func pipeContent(t *testing.T, dir, containerName string) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "pipe-clab_ws_vnc_*_"+containerName+"_*"))
	require.NoError(t, err)
	if len(files) != 1 {
		return ""
	}
	data, err := os.ReadFile(files[0])
	require.NoError(t, err)
	return string(data)
}

// labCaptures records the captures the fake lab runtime runs, and ends them with their context.
type labCaptures struct {
	mu       sync.Mutex
	requests []clablabruntime.CaptureRequest
	running  int
	fail     error
}

func (l *labCaptures) capture(ctx context.Context, req clablabruntime.CaptureRequest, w io.Writer) error {
	l.mu.Lock()
	l.requests = append(l.requests, req)
	l.running++
	fail := l.fail
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		l.running--
		l.mu.Unlock()
	}()
	names := make([]string, 0, len(req.Targets))
	for _, target := range req.Targets {
		names = append(names, target.Node+":"+target.Interface)
	}
	if _, err := fmt.Fprintf(w, "pcapng of %s;", strings.Join(names, ",")); err != nil {
		return err
	}
	if fail != nil {
		return fail
	}
	<-ctx.Done()
	return nil
}

func (l *labCaptures) runningCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.running
}

// startVncSessions creates Wireshark VNC sessions on the c9s fake.
func startVncSessions(t *testing.T, api *c9sAPI, body string) []models.CaptureWiresharkVncSession {
	t.Helper()
	config.AppConfig.CaptureWiresharkPullPolicy = "never"
	config.AppConfig.CaptureWiresharkDockerImage = "example/wireshark:test"
	InitCaptureManager()
	t.Cleanup(ShutdownCaptureManager)
	wiresharkVncProbe = func() bool { return true }

	recorder := api.do(http.MethodPost, "/api/v1/labs/lab1/capture/wireshark-vnc-sessions", []byte(body))
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var response models.CaptureWiresharkVncCreateResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	return response.Sessions
}

// TestWiresharkVncOnC9sFeedsACapturePipe starts sessions for two interfaces of one node and
// one of another: one session per node, each fed with one capture of its node's interfaces,
// as the requesting user, through the container's capture pipe. Closing a session ends its
// capture.
func TestWiresharkVncOnC9sFeedsACapturePipe(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()
	api.fake.CaptureIfaces["n1"] = append(api.fake.CaptureIfaces["n1"],
		clablabruntime.CaptureInterface{Node: "n1", Interface: "eth2", PeerNode: "host", PeerInterface: "n1-eth2"})
	captures := &labCaptures{}
	api.fake.CaptureFunc = captures.capture
	dir := fakeDocker(t)

	sessions := startVncSessions(t, api, `{"theme":"dark","targets":[
		{"containerName":"lab1-n1","interfaceName":"eth1"},
		{"containerName":"lab1-srl1","interfaceName":"ethernet-1/1"},
		{"containerName":"lab1-n1","interfaceName":"eth2"}]}`)
	require.Len(t, sessions, 2, "one session per node")
	require.Equal(t, "lab1-n1", sessions[0].ContainerName)
	require.Equal(t, []string{"eth1", "eth2"}, sessions[0].InterfaceNames)
	require.Equal(t, "lab1-srl1", sessions[1].ContainerName)
	require.Equal(t, []string{"e1-1"}, sessions[1].InterfaceNames)

	var runs []string
	for _, line := range dockerLog(t, dir) {
		require.NotContains(t, line, "network connect", "no Edgeshark network")
		require.False(t, strings.HasPrefix(line, "ps"), "no Edgeshark lookup: %s", line)
		if strings.HasPrefix(line, "run ") {
			runs = append(runs, line)
		}
	}
	require.Len(t, runs, 2)
	require.Contains(t, runs[0], "-e CLABWIRE_CAPTURE_PIPE=/tmp/clabwire/lab1-n1 -e DARK_MODE=1 example/wireshark:test")
	require.Contains(t, runs[1], "-e CLABWIRE_CAPTURE_PIPE=/tmp/clabwire/lab1-srl1 -e DARK_MODE=1 example/wireshark:test")
	for _, run := range runs {
		require.NotContains(t, run, "PACKETFLIX_LINK")
		require.NotContains(t, run, "--add-host", "the container does not reach the server")
		require.NotContains(t, run, "SSL_CERT_FILE")
	}

	require.Eventually(t, func() bool {
		return pipeContent(t, dir, "lab1-n1") == "pcapng of n1:eth1,n1:eth2;" &&
			pipeContent(t, dir, "lab1-srl1") == "pcapng of srl1:e1-1;"
	}, 10*time.Second, 50*time.Millisecond, "each session's Wireshark reads its node's capture")
	captures.mu.Lock()
	requests := append([]clablabruntime.CaptureRequest(nil), captures.requests...)
	captures.mu.Unlock()
	require.Len(t, requests, 2)
	for _, req := range requests {
		require.Equal(t, "lab1", req.Name)
		require.Zero(t, req.Duration, "the capture lasts as long as the session")
	}

	recorder := api.do(http.MethodDelete, "/api/v1/capture/wireshark-vnc-sessions/"+sessions[0].SessionID, nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Equal(t, 1, captures.runningCount(), "closing a session ends its capture")
	recorder = api.do(http.MethodDelete, "/api/v1/capture/wireshark-vnc-sessions", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Zero(t, captures.runningCount())
	require.Contains(t, dockerLog(t, dir), "rm -f "+strings.Fields(runs[0])[4])
}

// TestWiresharkVncOnC9sReportsAFailedCapture fails the session's capture: the session's
// container stops and its routes answer with the reason.
func TestWiresharkVncOnC9sReportsAFailedCapture(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()
	api.fake.CaptureFunc = (&labCaptures{fail: errors.New("pod n1 is gone")}).capture
	dir := fakeDocker(t)

	sessions := startVncSessions(t, api, `{"targets":[{"containerName":"lab1-n1","interfaceName":"eth1"}]}`)
	require.Len(t, sessions, 1)
	ready := "/api/v1/capture/wireshark-vnc-sessions/" + sessions[0].SessionID + "/ready"
	require.Eventually(t, func() bool {
		return api.do(http.MethodGet, ready, nil).Code == http.StatusInternalServerError
	}, 10*time.Second, 50*time.Millisecond)
	recorder := api.do(http.MethodGet, ready, nil)
	require.Contains(t, decodeError(t, recorder), "pod n1 is gone")
	require.Equal(t, "pcapng of n1:eth1;", pipeContent(t, dir, "lab1-n1"))
	var stopped bool
	for _, line := range dockerLog(t, dir) {
		stopped = stopped || strings.HasPrefix(line, "rm -f clab_ws_vnc_")
	}
	require.True(t, stopped, "the failed session's container is stopped")

	recorder = api.do(http.MethodDelete, "/api/v1/capture/wireshark-vnc-sessions/"+sessions[0].SessionID, nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
}

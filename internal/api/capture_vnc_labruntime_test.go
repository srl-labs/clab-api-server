package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	"github.com/stretchr/testify/require"

	"github.com/srl-labs/clab-api-server/internal/capture"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
	"github.com/srl-labs/clab-api-server/internal/tlsconfig"
)

// fakeDocker puts a docker command on PATH that logs its arguments and answers run with a
// container ID. It returns the log path.
func fakeDocker(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "docker.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"" + logPath + "\"\n[ \"$1\" = run ] && echo wireshark-id\nexit 0\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

var packetflixLinkRx = regexp.MustCompile(`PACKETFLIX_LINK=(\S+)`)

// startVncSessions creates Wireshark VNC sessions on the c9s fake and returns the docker run
// lines, the links, the grants of the tickets the links carry, and the sessions.
func startVncSessions(t *testing.T, api *c9sAPI, logPath string) ([]string, []string, []capture.TicketGrant, []models.CaptureWiresharkVncSession) {
	t.Helper()
	config.AppConfig.CaptureWiresharkPullPolicy = "never"
	config.AppConfig.CaptureWiresharkDockerImage = "example/wireshark:test"
	InitCaptureManager()
	t.Cleanup(ShutdownCaptureManager)
	wiresharkVncProbe = func() bool { return true }

	recorder := api.do(http.MethodPost, "/api/v1/labs/lab1/capture/wireshark-vnc-sessions", []byte(`{"theme":"dark","targets":[
		{"containerName":"lab1-n1","interfaceName":"eth1"},
		{"containerName":"lab1-srl1","interfaceName":"ethernet-1/1"}]}`))
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var response models.CaptureWiresharkVncCreateResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	require.Len(t, response.Sessions, 2, "one session per node")
	require.Equal(t, "lab1-n1", response.Sessions[0].ContainerName)
	require.Equal(t, []string{"eth1"}, response.Sessions[0].InterfaceNames)
	require.Equal(t, []string{"e1-1"}, response.Sessions[1].InterfaceNames)

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	var runs []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		require.NotContains(t, line, "network connect", "no Edgeshark network")
		require.False(t, strings.HasPrefix(line, "ps"), "no Edgeshark lookup: %s", line)
		if strings.HasPrefix(line, "run ") {
			runs = append(runs, line)
		}
	}
	require.Len(t, runs, 2)
	var links []string
	var grants []capture.TicketGrant
	for _, run := range runs {
		require.Contains(t, run, "-e DARK_MODE=1 example/wireshark:test")
		match := packetflixLinkRx.FindStringSubmatch(run)
		require.NotNil(t, match, run)
		links = append(links, match[1])
		parsed, err := url.Parse(strings.TrimPrefix(match[1], "packetflix:"))
		require.NoError(t, err)
		ticket := strings.TrimPrefix(parsed.Path, captureTicketPath)
		redemption, err := captureTicketStore().Redeem(ticket, nil)
		require.NoError(t, err, "the link carries a fresh ticket")
		require.NotNil(t, redemption.Revoked, "a session ticket")
		grants = append(grants, redemption.TicketGrant)
	}
	return runs, links, grants, response.Sessions
}

func TestWiresharkVncOnC9sCapturesThroughATicket(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()
	logPath := fakeDocker(t)
	config.AppConfig.TLSEnable = false
	config.AppConfig.APIPort = "8080"

	runs, links, grants, _ := startVncSessions(t, api, logPath)
	for _, run := range runs {
		require.Contains(t, run, "--add-host host.docker.internal:host-gateway")
		require.NotContains(t, run, "SSL_CERT_FILE")
	}
	require.True(t, strings.HasPrefix(links[0], "packetflix:ws://host.docker.internal:8080/api/v1/capture/packetflix/"), links[0])
	require.Equal(t, capture.TicketGrant{Username: api.username, LabName: "lab1",
		Targets: []capture.Target{{Node: "n1", Interface: "eth1"}}}, grants[0], "the requesting user's ticket, without a duration")
	require.Equal(t, []capture.Target{{Node: "srl1", Interface: "e1-1"}}, grants[1].Targets)
}

func TestWiresharkVncOnC9sTrustsTheServerCertificate(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()
	logPath := fakeDocker(t)
	certDir := t.TempDir()
	certFile, keyFile := filepath.Join(certDir, "server.crt"), filepath.Join(certDir, "server.key")
	_, err := tlsconfig.EnsureSelfSignedCertificate(certFile, keyFile, []string{"localhost", "127.0.0.1", "clab-host.test"})
	require.NoError(t, err)
	SetServerCertificateFile(certFile)
	t.Cleanup(func() { SetServerCertificateFile("") })
	config.AppConfig.TLSEnable = true
	config.AppConfig.APIPort = "8443"

	runs, links, _, _ := startVncSessions(t, api, logPath)
	for _, run := range runs {
		require.Contains(t, run, "-v "+certFile+":/etc/clab-api-server/server.crt:ro -e SSL_CERT_FILE=/etc/clab-api-server/server.crt --add-host clab-host.test:host-gateway")
	}
	for _, link := range links {
		require.True(t, strings.HasPrefix(link, "packetflix:wss://clab-host.test:8443/api/v1/capture/packetflix/"), link)
	}
}

func TestCertificateHostForContainers(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, hosts ...string) string {
		certFile := filepath.Join(dir, name+".crt")
		_, err := tlsconfig.EnsureSelfSignedCertificate(certFile, filepath.Join(dir, name+".key"), hosts)
		require.NoError(t, err)
		return certFile
	}
	host, isIP, err := certificateHostForContainers(write("dns", "localhost", "127.0.0.1", "clab.example.com", "10.0.0.5"))
	require.NoError(t, err)
	require.Equal(t, "clab.example.com", host)
	require.False(t, isIP)
	host, isIP, err = certificateHostForContainers(write("ip", "localhost", "127.0.0.1", "::1", "10.0.0.5"))
	require.NoError(t, err)
	require.Equal(t, "10.0.0.5", host)
	require.True(t, isIP)
	_, _, err = certificateHostForContainers(write("loopback", "localhost", "127.0.0.1"))
	require.ErrorContains(t, err, "names no host")
	_, _, err = certificateHostForContainers(filepath.Join(dir, "missing.crt"))
	require.Error(t, err)
}

// TestWiresharkVncSessionTicketLastsForTheSession restarts the capture inside a session's
// Wireshark (cshargextcap connects again with the same link) and closes the session: its
// ticket redeems for the whole session, is refused for other targets, and is revoked with the
// session, which also ends a capture that still runs on it.
func TestWiresharkVncSessionTicketLastsForTheSession(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()
	logPath := fakeDocker(t)
	config.AppConfig.TLSEnable = false
	config.AppConfig.APIPort = "8080"
	var captures atomic.Int32
	var block atomic.Bool
	ended := make(chan error, 1)
	api.fake.CaptureFunc = func(ctx context.Context, req clablabruntime.CaptureRequest, w io.Writer) error {
		captures.Add(1)
		if _, err := w.Write([]byte("SHB")); err != nil {
			return err
		}
		if block.CompareAndSwap(true, false) {
			<-ctx.Done()
			ended <- ctx.Err()
		}
		return nil
	}
	server := api.server()

	_, links, _, sessions := startVncSessions(t, api, logPath)
	readCapture := func(link string) {
		t.Helper()
		conn, _, err := dialPacketflix(server.URL, link)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		_, data, err := conn.ReadMessage()
		require.NoError(t, err)
		require.Equal(t, "SHB", string(data))
		_, _, err = conn.ReadMessage()
		var closeErr *websocket.CloseError
		require.ErrorAs(t, err, &closeErr)
		require.Equal(t, websocket.CloseNormalClosure, closeErr.Code)
	}
	for range 3 {
		readCapture(links[0])
	}
	require.Equal(t, int32(3), captures.Load(), "the session's Wireshark restarts its capture with the same link")

	// The ticket never captures other targets: the other session's interface is refused.
	other := strings.Replace(links[0], url.QueryEscape(`"n1:eth1"`), url.QueryEscape(`"srl1:e1-1"`), 1)
	require.NotEqual(t, links[0], other)
	_, response, err := dialPacketflix(server.URL, other)
	require.ErrorIs(t, err, websocket.ErrBadHandshake)
	require.Equal(t, http.StatusForbidden, response.StatusCode)
	readCapture(links[0])

	// A capture still runs when the session is closed.
	block.Store(true)
	conn, _, err := dialPacketflix(server.URL, links[0])
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, _, err = conn.ReadMessage()
	require.NoError(t, err)
	recorder := api.do(http.MethodDelete, "/api/v1/capture/wireshark-vnc-sessions/"+sessions[0].SessionID, nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	select {
	case err := <-ended:
		require.ErrorIs(t, err, context.Canceled, "closing the session ends the capture on its ticket")
	case <-time.After(5 * time.Second):
		t.Fatal("the capture outlived its session")
	}
	_, _, err = conn.ReadMessage()
	var closeErr *websocket.CloseError
	require.ErrorAs(t, err, &closeErr)
	require.Equal(t, websocket.ClosePolicyViolation, closeErr.Code)
	require.Equal(t, "capture ticket revoked", closeErr.Text)

	_, response, err = dialPacketflix(server.URL, links[0])
	require.ErrorIs(t, err, websocket.ErrBadHandshake)
	require.Equal(t, http.StatusNotFound, response.StatusCode, "a closed session's ticket is refused")

	// The other session's ticket is still valid until that session is closed as well.
	readCapture(links[1])
	recorder = api.do(http.MethodDelete, "/api/v1/capture/wireshark-vnc-sessions", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	_, response, err = dialPacketflix(server.URL, links[1])
	require.ErrorIs(t, err, websocket.ErrBadHandshake)
	require.Equal(t, http.StatusNotFound, response.StatusCode)
	require.Zero(t, captureTicketStore().Pending())
}

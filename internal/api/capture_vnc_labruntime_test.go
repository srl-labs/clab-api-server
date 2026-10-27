package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

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
// lines and the grants of the tickets their links carry.
func startVncSessions(t *testing.T, api *c9sAPI, logPath string) ([]string, []string, []capture.TicketGrant) {
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
		grant, err := captureTicketStore().Redeem(ticket)
		require.NoError(t, err, "the link carries a fresh ticket")
		grants = append(grants, grant)
	}
	return runs, links, grants
}

func TestWiresharkVncOnC9sCapturesThroughATicket(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()
	logPath := fakeDocker(t)
	config.AppConfig.TLSEnable = false
	config.AppConfig.APIPort = "8080"

	runs, links, grants := startVncSessions(t, api, logPath)
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

	runs, links, _ := startVncSessions(t, api, logPath)
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

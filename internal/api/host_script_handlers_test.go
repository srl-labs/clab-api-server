package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/srl-labs/clab-api-server/internal/auth"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// hostScriptLab is a topology of the current user in a temporary labs root, with the
// script routes behind a router that signs in as that user.
type hostScriptLab struct {
	router   *gin.Engine
	folder   string
	topology string
	query    string
}

func newHostScriptLab(t *testing.T) hostScriptLab {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("these tests run as the signed-in user, which needs a non-root test account")
	}
	router, workspace := workspaceTestRouter(t)
	previous := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previous })
	config.AppConfig.ClabRuntime = "docker"
	config.AppConfig.APIHostScripts = true

	router.POST("/labs/:labName/host-script/describe", requireHostScripts(), DescribeHostScriptHandler)
	router.POST("/labs/:labName/host-script/stream", requireHostScripts(), StreamHostScriptHandler)

	folder := filepath.Join(workspace, "demo")
	require.NoError(t, os.MkdirAll(folder, 0o755))
	topology := filepath.Join(folder, "demo.clab.yml")
	require.NoError(t, os.WriteFile(topology, []byte("name: demo\n"), 0o644))

	current, err := user.Current()
	require.NoError(t, err)
	previousLookup := hostScriptLabTopology
	t.Cleanup(func() { hostScriptLabTopology = previousLookup })
	hostScriptLabTopology = func(context.Context, *gin.Context, string, string) (string, string, bool) {
		return topology, current.Username, true
	}
	return hostScriptLab{router: router, folder: folder, topology: topology, query: "?path=demo/demo.clab.yml"}
}

// ownedBy makes the lab look like another user's, as a superuser sees it.
func (l hostScriptLab) ownedBy(owner string) {
	hostScriptLabTopology = func(context.Context, *gin.Context, string, string) (string, string, bool) {
		return l.topology, owner, true
	}
}

func (l hostScriptLab) post(t *testing.T, route string, body any) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPost, "/labs/demo/host-script/"+route+l.query, strings.NewReader(string(payload)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	l.router.ServeHTTP(recorder, request)
	return recorder
}

func parseHostScriptEvents(t *testing.T, body string) (string, string, *models.HostScriptResult) {
	t.Helper()
	var stdout, stderr strings.Builder
	var result *models.HostScriptResult
	scanner := bufio.NewScanner(strings.NewReader(body))
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var event models.HostScriptEvent
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &event), scanner.Text())
		switch event.Type {
		case "output":
			if event.Stream == "stderr" {
				stderr.WriteString(event.Text)
			} else {
				stdout.WriteString(event.Text)
			}
		case "exit":
			result = event.Result
		}
	}
	return stdout.String(), stderr.String(), result
}

func uniqueSleepCommand() string {
	return fmt.Sprintf("sleep 30.%d%d", os.Getpid(), rand.Intn(1_000_000))
}

func sleepIsRunning(command string) bool {
	return exec.Command("pgrep", "-xf", command).Run() == nil
}

func killSleep(command string) {
	_ = exec.Command("pkill", "-KILL", "-xf", command).Run()
}

func TestHostScriptsAreOffByDefaultAndNeverOnC9s(t *testing.T) {
	lab := newHostScriptLab(t)

	config.AppConfig.APIHostScripts = false
	recorder := lab.post(t, "stream", models.HostScriptSourceRequest{Script: "echo hi"})
	require.Equal(t, http.StatusNotImplemented, recorder.Code)
	require.NotContains(t, healthResponse(t).Features, "host-scripts")

	config.AppConfig.APIHostScripts = true
	require.Contains(t, healthResponse(t).Features, "host-scripts")

	config.AppConfig.ClabRuntime = "c9s"
	recorder = lab.post(t, "describe", models.HostScriptSourceRequest{Script: "echo hi"})
	require.Equal(t, http.StatusNotImplemented, recorder.Code)
	require.NotContains(t, healthResponse(t).Features, "host-scripts")
}

func TestHostScriptRunsInTheTopologyFolderAsTheSignedInUser(t *testing.T) {
	lab := newHostScriptLab(t)
	current, err := user.Current()
	require.NoError(t, err)

	recorder := lab.post(t, "stream", models.HostScriptSourceRequest{
		Script: `printf "%s|%s|%s|%s|%s" "$(id -u)" "$(pwd -P)" "$CLAB_LAB_NAME" "$CLAB_TOPOLOGY" "$USER"; echo oops >&2; exit 3`,
	})
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	stdout, stderr, result := parseHostScriptEvents(t, recorder.Body.String())

	folder, err := filepath.EvalSymlinks(lab.folder)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%s|%s|demo|%s|%s", current.Uid, folder, lab.topology, current.Username), stdout)
	require.Equal(t, "oops\n", stderr)
	require.NotNil(t, result)
	require.NotNil(t, result.ExitCode)
	require.Equal(t, 3, *result.ExitCode)
}

func TestHostScriptGetsAMinimalEnvironment(t *testing.T) {
	lab := newHostScriptLab(t)
	t.Setenv("JWT_SECRET", "do-not-leak")

	recorder := lab.post(t, "stream", models.HostScriptSourceRequest{Script: `printf "[%s]" "${JWT_SECRET:-}"`})
	stdout, _, _ := parseHostScriptEvents(t, recorder.Body.String())
	require.Equal(t, "[]", stdout)
}

func TestHostScriptAccountNeverFallsBackToTheServerAccount(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs a non-root test account")
	}
	current, err := user.Current()
	require.NoError(t, err)
	uid, err := strconv.Atoi(current.Uid)
	require.NoError(t, err)

	credential, err := hostScriptAccount{username: current.Username, uid: uid}.credential()
	require.NoError(t, err)
	require.Nil(t, credential, "the server's own account needs no switch")

	_, err = hostScriptAccount{username: "someone-else", uid: uid + 1}.credential()
	require.Error(t, err, "a non-root server must refuse to run a script for another account")
}

func TestHostScriptAccountCredentialCarriesItsGroups(t *testing.T) {
	account := hostScriptAccount{username: "alice", uid: 1234, gid: 1234, groups: []int{1234, 77}}
	if os.Geteuid() != 0 {
		_, err := account.credential()
		require.Error(t, err)
		return
	}
	credential, err := account.credential()
	require.NoError(t, err)
	require.Equal(t, uint32(1234), credential.Uid)
	require.Equal(t, uint32(1234), credential.Gid)
	require.Equal(t, []uint32{1234, 77}, credential.Groups)
}

func TestHostScriptDescribeShowsContentAndHash(t *testing.T) {
	lab := newHostScriptLab(t)
	script := filepath.Join(lab.folder, "reset.sh")
	require.NoError(t, os.WriteFile(script, []byte("echo reset\n"), 0o644))

	recorder := lab.post(t, "describe", models.HostScriptSourceRequest{ScriptPath: "reset.sh"})
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var description models.HostScriptDescription
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &description))
	require.Equal(t, "file", description.Kind)
	require.Equal(t, "echo reset\n", description.Content)
	require.False(t, description.Foreign)
	require.Len(t, description.Sha256, 64)
	require.True(t, strings.HasSuffix(description.ResolvedPath, "/demo/reset.sh"), description.ResolvedPath)

	var inline models.HostScriptDescription
	recorder = lab.post(t, "describe", models.HostScriptSourceRequest{Script: "echo inline"})
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &inline))
	require.Equal(t, "inline", inline.Kind)
	require.Equal(t, "echo inline", inline.Content)
	require.NotEqual(t, description.Sha256, inline.Sha256)
}

func TestHostScriptDescribeCannotReadOutsideTheWorkspace(t *testing.T) {
	lab := newHostScriptLab(t)

	for _, path := range []string{"/etc/shadow", "/etc/passwd", "../../../../../../etc/passwd"} {
		recorder := lab.post(t, "describe", models.HostScriptSourceRequest{ScriptPath: path})
		require.Equal(t, http.StatusBadRequest, recorder.Code, "%s: %s", path, recorder.Body.String())
		require.NotContains(t, recorder.Body.String(), "root:", path)
	}

	// A link inside the workspace that points out of it.
	require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(lab.folder, "link.sh")))
	recorder := lab.post(t, "describe", models.HostScriptSourceRequest{ScriptPath: "link.sh"})
	require.Equal(t, http.StatusBadRequest, recorder.Code, recorder.Body.String())
	require.NotContains(t, recorder.Body.String(), "root:")

	// Not a regular file.
	require.NoError(t, os.Mkdir(filepath.Join(lab.folder, "dir.sh"), 0o755))
	recorder = lab.post(t, "describe", models.HostScriptSourceRequest{ScriptPath: "dir.sh"})
	require.Equal(t, http.StatusForbidden, recorder.Code, recorder.Body.String())

	recorder = lab.post(t, "describe", models.HostScriptSourceRequest{ScriptPath: "missing.sh"})
	require.Equal(t, http.StatusNotFound, recorder.Code, recorder.Body.String())
}

func TestHostScriptRefusesAScriptThatChangedSinceItWasConfirmed(t *testing.T) {
	lab := newHostScriptLab(t)
	script := filepath.Join(lab.folder, "a.sh")
	marker := filepath.Join(lab.folder, "ran")
	require.NoError(t, os.WriteFile(script, []byte("echo first\n"), 0o644))

	var description models.HostScriptDescription
	require.NoError(t, json.Unmarshal(lab.post(t, "describe", models.HostScriptSourceRequest{ScriptPath: "a.sh"}).Body.Bytes(), &description))
	require.NoError(t, os.WriteFile(script, []byte("touch ran\n"), 0o644))

	recorder := lab.post(t, "stream", models.HostScriptRunRequest{
		HostScriptSourceRequest: models.HostScriptSourceRequest{ScriptPath: "a.sh"},
		ExpectedSha256:          description.Sha256,
	})
	require.Equal(t, http.StatusConflict, recorder.Code, recorder.Body.String())
	require.NoFileExists(t, marker)
}

func TestHostScriptRejectsBadInput(t *testing.T) {
	lab := newHostScriptLab(t)
	negative := -1.0
	tooLong := 24*60*60 + 1.0

	for name, body := range map[string]any{
		"empty":      models.HostScriptSourceRequest{Script: "  "},
		"too big":    models.HostScriptSourceRequest{Script: "#" + strings.Repeat("x", maxInlineScriptBytes)},
		"negative":   models.HostScriptRunRequest{HostScriptSourceRequest: models.HostScriptSourceRequest{Script: "echo"}, TimeoutSeconds: &negative},
		"over a day": models.HostScriptRunRequest{HostScriptSourceRequest: models.HostScriptSourceRequest{Script: "echo"}, TimeoutSeconds: &tooLong},
	} {
		recorder := lab.post(t, "stream", body)
		require.Equal(t, http.StatusBadRequest, recorder.Code, "%s: %s", name, recorder.Body.String())
	}
}

func TestHostScriptTimeoutStopsChildren(t *testing.T) {
	lab := newHostScriptLab(t)
	child := uniqueSleepCommand()
	t.Cleanup(func() { killSleep(child) })
	timeout := 0.3

	started := time.Now()
	recorder := lab.post(t, "stream", models.HostScriptRunRequest{
		HostScriptSourceRequest: models.HostScriptSourceRequest{Script: child + "; echo late"},
		TimeoutSeconds:          &timeout,
	})
	require.Less(t, time.Since(started), 3*time.Second)
	stdout, _, result := parseHostScriptEvents(t, recorder.Body.String())
	require.Empty(t, stdout)
	require.NotNil(t, result)
	require.True(t, result.TimedOut)
	require.Nil(t, result.ExitCode)
	require.Eventually(t, func() bool { return !sleepIsRunning(child) }, 3*time.Second, 25*time.Millisecond, "the child survived the timeout")
}

func TestHostScriptDisconnectStopsAQuietScriptAndItsChildren(t *testing.T) {
	lab := newHostScriptLab(t)
	child := uniqueSleepCommand()
	t.Cleanup(func() { killSleep(child) })

	server := httptest.NewServer(lab.router)
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	body := fmt.Sprintf(`{"script":%q}`, child+"; echo late")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/labs/demo/host-script/stream"+lab.query, strings.NewReader(body))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, http.StatusOK, response.StatusCode)

	require.Eventually(t, func() bool { return sleepIsRunning(child) }, 3*time.Second, 25*time.Millisecond)
	cancel()
	require.Eventually(t, func() bool { return !sleepIsRunning(child) }, 3*time.Second, 25*time.Millisecond, "the script kept running after the client left")
}

func TestHostScriptThatLeavesAProcessBehindFinishes(t *testing.T) {
	lab := newHostScriptLab(t)
	child := uniqueSleepCommand()
	t.Cleanup(func() { killSleep(child) })

	started := time.Now()
	recorder := lab.post(t, "stream", models.HostScriptSourceRequest{Script: child + " & echo started; exit 0"})
	require.Less(t, time.Since(started), 3*time.Second, "the run waited for the background process")
	stdout, _, result := parseHostScriptEvents(t, recorder.Body.String())
	require.Equal(t, "started\n", stdout)
	require.NotNil(t, result.ExitCode)
	require.Equal(t, 0, *result.ExitCode)
	require.True(t, sleepIsRunning(child), "a normal exit must not kill what the script started")
}

func TestHostScriptKeepsAllOutputAndSplitCharacters(t *testing.T) {
	lab := newHostScriptLab(t)

	recorder := lab.post(t, "stream", models.HostScriptSourceRequest{Script: `for i in $(seq 1 20000); do printf 'é%d\n' "$i"; done`})
	stdout, _, _ := parseHostScriptEvents(t, recorder.Body.String())
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	require.Len(t, lines, 20000)
	require.Equal(t, "é20000", lines[len(lines)-1])
	require.NotContains(t, stdout, "�", "a character split across two reads was broken")
}

func TestHostScriptLimitsRunningScriptsPerUser(t *testing.T) {
	lab := newHostScriptLab(t)
	current, err := user.Current()
	require.NoError(t, err)

	for range maxHostScriptsPerUser {
		require.True(t, claimHostScriptSlot(current.Username))
	}
	t.Cleanup(func() {
		for range maxHostScriptsPerUser {
			releaseHostScriptSlot(current.Username)
		}
	})

	recorder := lab.post(t, "stream", models.HostScriptSourceRequest{Script: "echo hi"})
	require.Equal(t, http.StatusTooManyRequests, recorder.Code, recorder.Body.String())
}

func TestHostScriptOnAnotherUsersLabRunsAsTheSignedInUserAndCountsAsForeign(t *testing.T) {
	lab := newHostScriptLab(t)
	current, err := user.Current()
	require.NoError(t, err)
	lab.ownedBy("root")

	var description models.HostScriptDescription
	recorder := lab.post(t, "describe", models.HostScriptSourceRequest{Script: "id -u"})
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &description))
	require.True(t, description.Foreign, "someone else's lab must always ask")

	recorder = lab.post(t, "stream", models.HostScriptSourceRequest{Script: "id -u"})
	stdout, _, _ := parseHostScriptEvents(t, recorder.Body.String())
	require.Equal(t, current.Uid+"\n", stdout, "it must run as the signed-in user, not the lab's owner")
}

func TestHostScriptAccountWithoutLoginShellIsRefused(t *testing.T) {
	// nobody exists everywhere, and has no shell on the systems this server supports.
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("no nobody account here")
	}
	newHostScriptLab(t)
	require.False(t, auth.HasLoginShell(nobody.Username))

	recorder := httptest.NewRecorder()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(recorder)
	c.Set("username", nobody.Username)
	c.Params = gin.Params{{Key: "labName", Value: "demo"}}
	c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"script":"echo hi"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	DescribeHostScriptHandler(c)
	require.Equal(t, http.StatusForbidden, recorder.Code, recorder.Body.String())
}

func TestHostScriptStartFailuresNameTheFolder(t *testing.T) {
	denied := &os.PathError{Op: "fork/exec", Path: "/usr/bin/bash", Err: syscall.EACCES}
	require.Equal(t, http.StatusForbidden, hostScriptStartStatus(denied))
	require.Contains(t, hostScriptStartMessage(denied, "/home/a/.clab/demo"), "cannot enter the lab's folder /home/a/.clab/demo")
	require.NotContains(t, hostScriptStartMessage(denied, "/home/a/.clab/demo"), "bash")

	missing := &os.PathError{Op: "chdir", Path: "/gone", Err: syscall.ENOENT}
	require.Equal(t, http.StatusNotFound, hostScriptStartStatus(missing))
	require.Contains(t, hostScriptStartMessage(missing, "/gone"), "does not exist")
}

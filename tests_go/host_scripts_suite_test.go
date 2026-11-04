package tests_go

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// Enable explicitly, because script buttons are off unless the server has
// API_HOST_SCRIPTS=true.
func TestHostScriptSuite(t *testing.T) {
	if os.Getenv("GOTEST_HOST_SCRIPTS") != "true" {
		t.Skip("set GOTEST_HOST_SCRIPTS=true and run the server with API_HOST_SCRIPTS=true")
	}
	suite.Run(t, new(HostScriptSuite))
}

type HostScriptSuite struct {
	BaseSuite
	apiUserHeaders   http.Header
	superuserHeaders http.Header
	// An undeployed topology of the API user, in the user's workspace.
	labName  string
	topology string
}

type hostScriptDescription struct {
	Kind         string `json:"kind"`
	ResolvedPath string `json:"resolvedPath"`
	Sha256       string `json:"sha256"`
	Owner        string `json:"owner"`
	Foreign      bool   `json:"foreign"`
	Content      string `json:"content"`
}

type hostScriptOutcome struct {
	Status   int
	Body     string
	Stdout   string
	Stderr   string
	ExitCode *int
	TimedOut bool
}

func (s *HostScriptSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	s.apiUserHeaders, s.superuserHeaders = s.loginBothUsers()

	s.labName = fmt.Sprintf("%s-script-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	s.topology = s.labName + "/" + s.labName + ".clab.yml"
	body := s.mustMarshal(map[string]string{"path": s.labName})
	response, status, err := s.doRequest("POST", s.cfg.APIURL+"/api/v1/labs/workspace/directory", s.apiUserHeaders, bytes.NewBuffer(body), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Less(status, 300, string(response))
	s.writeFile(s.topology, "name: "+s.labName+"\ntopology:\n  nodes: {}\n")
}

func (s *HostScriptSuite) TearDownSuite() {
	_, _, _ = s.doRequest("DELETE", s.cfg.APIURL+"/api/v1/labs/workspace/file?recursive=true&path="+url.QueryEscape(s.labName), s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.BaseSuite.TearDownSuite()
}

func (s *HostScriptSuite) writeFile(path, content string) {
	s.T().Helper()
	response, status, err := s.doRequest("PUT", s.cfg.APIURL+"/api/v1/labs/workspace/file?path="+url.QueryEscape(path), s.apiUserHeaders, strings.NewReader(content), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Less(status, 300, string(response))
}

func (s *HostScriptSuite) routeURL(labName, topology, route string) string {
	address := fmt.Sprintf("%s/api/v1/labs/%s/host-script/%s", s.cfg.APIURL, labName, route)
	if topology != "" {
		address += "?path=" + url.QueryEscape(topology)
	}
	return address
}

func (s *HostScriptSuite) describeOn(headers http.Header, labName, topology string, source map[string]any) (hostScriptDescription, int, string) {
	s.T().Helper()
	response, status, err := s.doRequest("POST", s.routeURL(labName, topology, "describe"), headers, bytes.NewBuffer(s.mustMarshal(source)), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	var description hostScriptDescription
	if status == http.StatusOK {
		s.Require().NoError(json.Unmarshal(response, &description), string(response))
	}
	return description, status, string(response)
}

func (s *HostScriptSuite) runOn(headers http.Header, labName, topology string, request map[string]any) hostScriptOutcome {
	s.T().Helper()
	response, status, err := s.doRequest("POST", s.routeURL(labName, topology, "stream"), headers, bytes.NewBuffer(s.mustMarshal(request)), s.cfg.DeployTimeout)
	s.Require().NoError(err)
	outcome := hostScriptOutcome{Status: status, Body: string(response)}
	if status != http.StatusOK {
		return outcome
	}
	scanner := bufio.NewScanner(bytes.NewReader(response))
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var event struct {
			Type   string `json:"type"`
			Stream string `json:"stream"`
			Text   string `json:"text"`
			Result *struct {
				ExitCode *int `json:"exitCode"`
				TimedOut bool `json:"timedOut"`
			} `json:"result"`
		}
		s.Require().NoError(json.Unmarshal(scanner.Bytes(), &event), scanner.Text())
		switch event.Type {
		case "output":
			if event.Stream == "stderr" {
				outcome.Stderr += event.Text
			} else {
				outcome.Stdout += event.Text
			}
		case "exit":
			s.Require().NotNil(event.Result)
			outcome.ExitCode = event.Result.ExitCode
			outcome.TimedOut = event.Result.TimedOut
		}
	}
	return outcome
}

func (s *HostScriptSuite) run(request map[string]any) hostScriptOutcome {
	s.T().Helper()
	outcome := s.runOn(s.apiUserHeaders, s.labName, s.topology, request)
	s.Require().Equal(http.StatusOK, outcome.Status, outcome.Body)
	return outcome
}

// uniqueSleep is a command line nothing else runs, so a later script can look for it.
func (s *HostScriptSuite) uniqueSleep() string {
	return "sleep 30." + strconv.FormatInt(time.Now().UnixNano()%1000000000, 10) + "1"
}

// isRunning asks the lab host, through a script, whether the command line still runs.
func (s *HostScriptSuite) isRunning(command string) bool {
	s.T().Helper()
	outcome := s.run(map[string]any{"script": fmt.Sprintf(`pgrep -xf '%s' >/dev/null && echo running || echo gone`, command)})
	return strings.TrimSpace(outcome.Stdout) == "running"
}

func (s *HostScriptSuite) TestAdvertisedOnHealth() {
	response, status, err := s.doRequest("GET", s.cfg.APIURL+"/health", http.Header{}, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	var health struct {
		Features []string `json:"features"`
	}
	s.Require().NoError(json.Unmarshal(response, &health))
	s.Assert().Contains(health.Features, "host-scripts")
}

func (s *HostScriptSuite) TestRoutesNeedALogin() {
	_, status, err := s.doRequest("POST", s.routeURL(s.labName, s.topology, "stream"), http.Header{"Content-Type": {"application/json"}}, strings.NewReader(`{"script":"id"}`), s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Assert().Equal(http.StatusUnauthorized, status)
}

func (s *HostScriptSuite) TestRunsAsTheSignedInUserFromTheTopologyFolder() {
	outcome := s.run(map[string]any{"script": `id -un; printf '%s|%s\n' "$USER" "$CLAB_LAB_NAME"; pwd -P; echo problem >&2; exit 3`})
	lines := strings.Split(strings.TrimSpace(outcome.Stdout), "\n")
	s.Require().Len(lines, 3, outcome.Body)
	s.Assert().Equal(s.cfg.APIUserUser, lines[0], "scripts must run as the signed-in user, not the server's account")
	s.Assert().Equal(s.cfg.APIUserUser+"|"+s.labName, lines[1])
	s.Assert().True(strings.HasSuffix(lines[2], "/"+s.labName), lines[2])
	s.Assert().Equal("problem\n", outcome.Stderr)
	s.Require().NotNil(outcome.ExitCode)
	s.Assert().Equal(3, *outcome.ExitCode)
}

func (s *HostScriptSuite) TestFilesCreatedBelongToTheSignedInUser() {
	outcome := s.run(map[string]any{"script": `touch created-by-script && stat -c %U created-by-script; rm -f created-by-script`})
	s.Assert().Equal(s.cfg.APIUserUser, strings.TrimSpace(outcome.Stdout))
}

func (s *HostScriptSuite) TestEnvironmentHasNoServerSettings() {
	outcome := s.run(map[string]any{"script": "env"})
	for _, name := range []string{"JWT_SECRET", "API_HOST_SCRIPTS", "SUPERUSER_GROUP", "SUDO_"} {
		s.Assert().NotContains(outcome.Stdout, name)
	}
}

func (s *HostScriptSuite) TestDescribeAndChangedScripts() {
	path := s.labName + "/changing.sh"
	s.writeFile(path, "echo first\n")
	description, status, body := s.describeOn(s.apiUserHeaders, s.labName, s.topology, map[string]any{"scriptPath": "changing.sh"})
	s.Require().Equal(http.StatusOK, status, body)
	s.Assert().Equal("file", description.Kind)
	s.Assert().Equal("echo first\n", description.Content)
	s.Assert().Equal(s.cfg.APIUserUser, description.Owner)
	s.Assert().False(description.Foreign)
	s.Assert().Len(description.Sha256, 64)

	agreed := s.run(map[string]any{"scriptPath": "changing.sh", "expectedSha256": description.Sha256})
	s.Assert().Equal("first\n", agreed.Stdout)

	s.writeFile(path, "touch must-not-exist\n")
	changed := s.runOn(s.apiUserHeaders, s.labName, s.topology, map[string]any{"scriptPath": "changing.sh", "expectedSha256": description.Sha256})
	s.Assert().Equal(http.StatusConflict, changed.Status, changed.Body)
	check := s.run(map[string]any{"script": `test -e must-not-exist && echo ran || echo refused`})
	s.Assert().Equal("refused\n", check.Stdout)
}

func (s *HostScriptSuite) TestTheServerReadsNothingForAUserOutsideItsFolders() {
	for _, path := range []string{"/etc/shadow", "../../../../../../etc/shadow"} {
		_, status, body := s.describeOn(s.apiUserHeaders, s.labName, s.topology, map[string]any{"scriptPath": path})
		s.Assert().NotEqual(http.StatusOK, status, path)
		s.Assert().NotContains(body, "root:", path)
	}
	s.run(map[string]any{"script": "ln -sf /etc/shadow shadow-link.sh"})
	_, status, body := s.describeOn(s.apiUserHeaders, s.labName, s.topology, map[string]any{"scriptPath": "shadow-link.sh"})
	s.Assert().NotEqual(http.StatusOK, status)
	s.Assert().NotContains(body, "root:")

	outcome := s.run(map[string]any{"script": "cat /etc/shadow 2>&1; rm -f shadow-link.sh; true"})
	s.Assert().NotContains(outcome.Stdout, "root:", "a script has the signed-in user's rights, not the server's")
}

func (s *HostScriptSuite) TestTimeoutStopsTheScriptAndItsChildren() {
	child := s.uniqueSleep()
	started := time.Now()
	outcome := s.run(map[string]any{"script": child + "; echo late", "timeoutSeconds": 1})
	s.Assert().Less(time.Since(started), 5*time.Second)
	s.Assert().True(outcome.TimedOut, outcome.Body)
	s.Assert().Nil(outcome.ExitCode)
	s.Assert().Empty(outcome.Stdout)
	s.Assert().Eventually(func() bool { return !s.isRunning(child) }, 8*time.Second, 200*time.Millisecond, "the child survived the timeout")
}

func (s *HostScriptSuite) TestClosingTheConnectionStopsAQuietScript() {
	child := s.uniqueSleep()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "POST", s.routeURL(s.labName, s.topology, "stream"), bytes.NewBuffer(s.mustMarshal(map[string]any{"script": child + "; echo late"})))
	s.Require().NoError(err)
	request.Header = s.apiUserHeaders.Clone()
	response, err := http.DefaultClient.Do(request)
	s.Require().NoError(err)
	defer func() { _ = response.Body.Close() }()
	s.Require().Equal(http.StatusOK, response.StatusCode)

	s.Require().Eventually(func() bool { return s.isRunning(child) }, 5*time.Second, 100*time.Millisecond)
	cancel()
	s.Assert().Eventually(func() bool { return !s.isRunning(child) }, 8*time.Second, 200*time.Millisecond, "the script kept running after the client left")
}

func (s *HostScriptSuite) TestAProcessLeftBehindDoesNotHoldTheRun() {
	child := s.uniqueSleep()
	started := time.Now()
	outcome := s.run(map[string]any{"script": child + " & echo started; exit 0"})
	s.Assert().Less(time.Since(started), 5*time.Second, "the run waited for the background process")
	s.Assert().Equal("started\n", outcome.Stdout)
	s.Assert().True(s.isRunning(child), "a normal exit must not kill what the script started")
	s.run(map[string]any{"script": fmt.Sprintf("pkill -xf '%s'; true", child)})
}

func (s *HostScriptSuite) TestLimits() {
	big := s.runOn(s.apiUserHeaders, s.labName, s.topology, map[string]any{"script": "#" + strings.Repeat("x", 100*1024)})
	s.Assert().Equal(http.StatusBadRequest, big.Status)
	long := s.runOn(s.apiUserHeaders, s.labName, s.topology, map[string]any{"script": "echo", "timeoutSeconds": 86401})
	s.Assert().Equal(http.StatusBadRequest, long.Status)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for range 4 {
		request, err := http.NewRequestWithContext(ctx, "POST", s.routeURL(s.labName, s.topology, "stream"), bytes.NewBuffer(s.mustMarshal(map[string]any{"script": s.uniqueSleep()})))
		s.Require().NoError(err)
		request.Header = s.apiUserHeaders.Clone()
		response, err := http.DefaultClient.Do(request)
		s.Require().NoError(err)
		defer func() { _ = response.Body.Close() }()
		s.Require().Equal(http.StatusOK, response.StatusCode)
	}
	fifth := s.runOn(s.apiUserHeaders, s.labName, s.topology, map[string]any{"script": "echo fifth"})
	s.Assert().Equal(http.StatusTooManyRequests, fifth.Status, fifth.Body)
	cancel()
	s.Eventually(func() bool {
		return s.runOn(s.apiUserHeaders, s.labName, s.topology, map[string]any{"script": "true"}).Status == http.StatusOK
	}, 8*time.Second, 200*time.Millisecond, "ended scripts must give their slots back")
}

// A superuser on a user's lab acts as themselves, and is told the script is not theirs.
func (s *HostScriptSuite) TestSuperuserOnAUsersLab() {
	labName, ownerHeaders := s.setupEphemeralLab()
	defer s.cleanupLab(labName, true)

	secret := s.runOn(ownerHeaders, labName, "", map[string]any{"script": "printf 'echo top-secret\\n' > secret.sh && chmod 600 secret.sh"})
	s.Require().Equal(http.StatusOK, secret.Status, secret.Body)
	description, status, body := s.describeOn(ownerHeaders, labName, "", map[string]any{"scriptPath": "secret.sh"})
	s.Require().Equal(http.StatusOK, status, body)
	s.Assert().False(description.Foreign, "the owner's own script is not foreign")

	description, status, body = s.describeOn(s.superuserHeaders, labName, "", map[string]any{"script": "id -un"})
	s.Require().Equal(http.StatusOK, status, body)
	s.Assert().True(description.Foreign, "someone else's lab must always ask")

	// Either it runs as the superuser, or the superuser may not enter the lab's folder.
	outcome := s.runOn(s.superuserHeaders, labName, "", map[string]any{"script": "id -un"})
	if outcome.Status == http.StatusOK {
		s.Assert().Equal(s.cfg.SuperuserUser, strings.TrimSpace(outcome.Stdout))
	} else {
		s.Assert().Equal(http.StatusForbidden, outcome.Status, outcome.Body)
		s.Assert().Contains(outcome.Body, "cannot enter the lab's folder")
	}

	// The server runs as root, and still must not read a private file for someone else.
	if s.cfg.SuperuserUser != "root" {
		_, status, body = s.describeOn(s.superuserHeaders, labName, "", map[string]any{"scriptPath": "secret.sh"})
		s.Assert().NotEqual(http.StatusOK, status, body)
		s.Assert().NotContains(body, "top-secret")
		run := s.runOn(s.superuserHeaders, labName, "", map[string]any{"scriptPath": "secret.sh"})
		s.Assert().NotEqual(http.StatusOK, run.Status, run.Body)
		s.Assert().NotContains(run.Body, "top-secret")
	}
}

// A regular user gets nothing of another user's lab.
func (s *HostScriptSuite) TestRegularUserOnAnotherUsersLab() {
	response, status, err := s.doRequest("GET", s.cfg.APIURL+"/api/v1/users/"+s.cfg.APIUserUser, s.superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status, string(response))
	var details struct {
		IsSuperuser bool `json:"isSuperuser"`
	}
	s.Require().NoError(json.Unmarshal(response, &details))
	if details.IsSuperuser {
		s.T().Skipf("%s is a superuser here, so it can see every lab", s.cfg.APIUserUser)
	}

	labName, _ := s.setupSuperuserLab()
	defer s.cleanupLab(labName, true)
	_, status, body := s.describeOn(s.apiUserHeaders, labName, "", map[string]any{"script": "id -un"})
	s.Assert().Equal(http.StatusNotFound, status, body)
	outcome := s.runOn(s.apiUserHeaders, labName, "", map[string]any{"script": "id -un"})
	s.Assert().Equal(http.StatusNotFound, outcome.Status, outcome.Body)
}

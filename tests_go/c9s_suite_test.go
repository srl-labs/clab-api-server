// tests_go/c9s_suite_test.go
package tests_go

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	clabcore "github.com/srl-labs/containerlab/core"
	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	_ "github.com/srl-labs/containerlab/labruntime/all"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	"github.com/stretchr/testify/suite"
)

// C9sSuite runs against a server with CLAB_RUNTIME=c9s whose Kubernetes identity holds only
// the provisioner role. It is opt-in (GOTEST_C9S=true) and needs:
//
//   - APIUSER_USER / SUPERUSER_USER: an API user and a superuser
//   - GOTEST_C9S_OTHER_USER / GOTEST_C9S_OTHER_PASS: a second API user
//   - GOTEST_C9S_KUBECONFIG: a cluster-admin kubeconfig of the same cluster, for assertions
//   - GOTEST_C9S_PROVISIONER_KUBECONFIG: the server's kubeconfig, to call the cluster as a
//     user without the server's checks
//   - GOTEST_C9S_USER_PREFIX (default "clab:")
type C9sSuite struct {
	BaseSuite

	userHeaders, otherHeaders, adminHeaders http.Header
	otherUser                               string
	adminKubeconfig, provisionerKubeconfig  string
	prefix                                  string
	labName                                 string
	namespace                               string
}

func TestC9sSuite(t *testing.T) {
	if os.Getenv("GOTEST_C9S") != "true" {
		t.Skip("set GOTEST_C9S=true to run the c9s suite against a server with CLAB_RUNTIME=c9s")
	}
	suite.Run(t, new(C9sSuite))
}

const c9sTopology = `{
  "name": "{lab_name}",
  "topology": {
    "kinds": {"linux": {"image": "ghcr.io/srl-labs/network-multitool:latest"}},
    "nodes": {"n1": {"kind": "linux"}, "n2": {"kind": "linux"}},
    "links": [{"endpoints": ["n1:eth1", "n2:eth1"]}]
  }
}`

func (s *C9sSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	s.otherUser = getEnvOrDie("GOTEST_C9S_OTHER_USER")
	s.adminKubeconfig = getEnvOrDie("GOTEST_C9S_KUBECONFIG")
	s.provisionerKubeconfig = getEnvOrDie("GOTEST_C9S_PROVISIONER_KUBECONFIG")
	s.prefix = getEnv("GOTEST_C9S_USER_PREFIX", "clab:")
	s.userHeaders = s.getAuthHeaders(s.login(s.cfg.APIUserUser, s.cfg.APIUserPass))
	s.otherHeaders = s.getAuthHeaders(s.login(s.otherUser, getEnvOrDie("GOTEST_C9S_OTHER_PASS")))
	s.adminHeaders = s.getAuthHeaders(s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass))
	s.labName = fmt.Sprintf("gotest-c9s-%s", strings.ToLower(s.randomSuffix(5)))
	s.namespace = fmt.Sprintf("c9s-%s-%s", s.cfg.APIUserUser, s.labName)
}

func (s *C9sSuite) TearDownSuite() {
	for _, headers := range []http.Header{s.userHeaders, s.otherHeaders} {
		if headers != nil {
			_, _, _ = s.destroyLab(headers, s.labName, true, s.cfg.CleanupTimeout)
		}
	}
	s.BaseSuite.TearDownSuite()
}

func (s *C9sSuite) url(format string, args ...any) string {
	return s.cfg.APIURL + fmt.Sprintf(format, args...)
}

func (s *C9sSuite) request(method, target string, headers http.Header, body any, timeout time.Duration) ([]byte, int) {
	s.T().Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(s.mustMarshal(body))
	}
	data, status, err := s.doRequest(method, target, headers, reader, timeout)
	s.Require().NoError(err)
	return data, status
}

// kubectl runs kubectl with the cluster-admin kubeconfig.
func (s *C9sSuite) kubectl(args ...string) (string, error) {
	cmd := exec.Command("kubectl", append([]string{"--kubeconfig", s.adminKubeconfig}, args...)...)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

func (s *C9sSuite) canI(user string, args ...string) string {
	s.T().Helper()
	output, _ := s.kubectl(append([]string{"auth", "can-i", "--as", s.prefix + user, "--as-group", s.prefix + "users"}, args...)...)
	// The answer is the last line; kubectl may warn before it.
	lines := strings.Split(output, "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func (s *C9sSuite) inspect(headers http.Header) ([]ClabContainerInfo, int) {
	data, status := s.request(http.MethodGet, s.url("/api/v1/labs/%s", s.labName), headers, nil, s.cfg.RequestTimeout)
	var nodes []ClabContainerInfo
	if status == http.StatusOK {
		s.Require().NoError(json.Unmarshal(data, &nodes), string(data))
	}
	return nodes, status
}

func (s *C9sSuite) TestC9sMultiUserLab() {
	s.Run("health reports c9s", func() {
		data, status := s.request(http.MethodGet, s.url("/health"), nil, nil, s.cfg.RequestTimeout)
		s.Require().Equal(http.StatusOK, status)
		var health struct {
			Runtime, NamespaceMode string
			Features               []string
		}
		s.Require().NoError(json.Unmarshal(data, &health))
		s.Require().Equal("c9s", health.Runtime)
		s.Require().Equal("per-lab", health.NamespaceMode)
		s.Require().Contains(health.Features, "c9s-runtime")
		s.Require().NotContains(health.Features, "snapshot-save")
	})

	s.Run("deploy as the user into a provisioned namespace", func() {
		topology := strings.ReplaceAll(c9sTopology, "{lab_name}", s.labName)
		data, status, err := s.createLab(s.userHeaders, s.labName, topology, false, s.cfg.DeployTimeout)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusOK, status, string(data))

		labels, err := s.kubectl("get", "namespace", s.namespace, "-o", "jsonpath={.metadata.labels}")
		s.Require().NoError(err, labels)
		s.Require().Contains(labels, `"clab-owner":"`+s.cfg.APIUserUser+`"`)
		s.Require().Contains(labels, `"pod-security.kubernetes.io/enforce":"privileged"`)
		s.Require().Contains(labels, `"containerlab.dev/runtime":"clabernetes"`)
		subjects, err := s.kubectl("get", "rolebinding", "clab-lab-editor", "-n", s.namespace, "-o", "jsonpath={.roleRef.name} {.subjects[0].name}")
		s.Require().NoError(err, subjects)
		s.Require().Equal("clabernetes-lab-editor "+s.prefix+s.cfg.APIUserUser, subjects)
		owner, err := s.kubectl("get", "topology.c9s.run", s.labName, "-n", s.namespace, "-o", "jsonpath={.metadata.labels.clab-owner}")
		s.Require().NoError(err, owner)
		s.Require().Equal(s.cfg.APIUserUser, owner, "--owner reaches the Topology")
	})

	s.Run("inspect shows the workload", func() {
		var nodes []ClabContainerInfo
		s.Require().Eventually(func() bool {
			var status int
			nodes, status = s.inspect(s.userHeaders)
			if status != http.StatusOK || len(nodes) != 2 {
				return false
			}
			for _, node := range nodes {
				if node.Pod == "" || node.Container == "" {
					return false
				}
			}
			return true
		}, 3*time.Minute, 3*time.Second, "inspect reports pods and containers")
		s.Require().Equal(s.namespace, nodes[0].Namespace)
		s.Require().Equal(fmt.Sprintf("%s/%s/n1", s.namespace, s.labName), nodes[0].ContainerID)
		s.Require().NotEmpty(nodes[0].NodeUID)
	})

	s.Run("another user cannot see or touch the lab", func() {
		_, status := s.inspect(s.otherHeaders)
		s.Require().Equal(http.StatusNotFound, status)
		data, status := s.request(http.MethodGet, s.url("/api/v1/labs"), s.otherHeaders, nil, s.cfg.RequestTimeout)
		s.Require().Equal(http.StatusOK, status)
		s.Require().NotContains(string(data), s.labName)
		_, status = s.request(http.MethodDelete, s.url("/api/v1/labs/%s", s.labName), s.otherHeaders, nil, s.cfg.RequestTimeout)
		s.Require().Equal(http.StatusNotFound, status)
		_, status = s.request(http.MethodGet, s.url("/api/v1/labs/%s/nodes/%s-n1/logs", s.labName, s.labName), s.otherHeaders, nil, s.cfg.RequestTimeout)
		s.Require().Equal(http.StatusNotFound, status)
	})

	s.Run("Kubernetes enforces the separation", func() {
		s.Require().Equal("yes", s.canI(s.cfg.APIUserUser, "get", "pods", "-n", s.namespace))
		s.Require().Equal("yes", s.canI(s.cfg.APIUserUser, "create", "pods", "--subresource", "exec", "-n", s.namespace))
		s.Require().Equal("no", s.canI(s.otherUser, "get", "pods", "-n", s.namespace))
		s.Require().Equal("no", s.canI(s.otherUser, "delete", "topologies.c9s.run", "-n", s.namespace))
		s.Require().Equal("no", s.canI(s.otherUser, "create", "pods", "--subresource", "exec", "-n", s.namespace))
		s.Require().Equal("no", s.canI(s.cfg.APIUserUser, "delete", "namespaces"), "users cannot delete namespaces")

		// Without the server's checks: the containerlab library with the server's
		// credentials, impersonating the other user, is refused by the cluster.
		other := s.labRuntimeClab(clablabruntime.Identity{User: s.prefix + s.otherUser, Groups: []string{s.prefix + "users"}})
		_, err := other.ListLabRuntimeContainers(context.Background(), false)
		s.Require().Error(err)
		s.Require().Contains(err.Error(), "forbidden")
		owner := s.labRuntimeClab(clablabruntime.Identity{User: s.prefix + s.cfg.APIUserUser, Groups: []string{s.prefix + "users"}})
		containers, err := owner.ListLabRuntimeContainers(context.Background(), false)
		s.Require().NoError(err)
		s.Require().Len(containers, 2)
		// The server's own identity has no access to lab resources at all.
		server := s.labRuntimeClab(clablabruntime.Identity{})
		_, err = server.ListLabRuntimeContainers(context.Background(), false)
		s.Require().Error(err)
		s.Require().Contains(err.Error(), "forbidden")
	})

	s.Run("the superuser sees and inspects it", func() {
		data, status := s.request(http.MethodGet, s.url("/api/v1/labs"), s.adminHeaders, nil, s.cfg.RequestTimeout)
		s.Require().Equal(http.StatusOK, status, string(data))
		s.Require().Contains(string(data), s.labName)
		nodes, status := s.inspect(s.adminHeaders)
		s.Require().Equal(http.StatusOK, status)
		s.Require().Len(nodes, 2)
	})

	s.Run("logs", func() {
		data, status := s.request(http.MethodGet, s.url("/api/v1/labs/%s/nodes/%s-n1/logs?tail=20", s.labName, s.labName), s.userHeaders, nil, s.cfg.RequestTimeout)
		s.Require().Equal(http.StatusOK, status, string(data))
		var logs struct{ Logs string }
		s.Require().NoError(json.Unmarshal(data, &logs))
		s.Require().NotEmpty(logs.Logs)
	})

	s.Run("exec", func() {
		data, status := s.request(http.MethodPost, s.url("/api/v1/labs/%s/exec", s.labName), s.userHeaders,
			map[string]string{"command": "ip -br link show eth1"}, s.cfg.RequestTimeout)
		s.Require().Equal(http.StatusOK, status, string(data))
		s.Require().Contains(string(data), "eth1")
		s.Require().Contains(string(data), s.labName+"-n2")
	})

	s.Run("terminal with resume", func() {
		data, status := s.request(http.MethodPost, s.url("/api/v1/labs/%s/nodes/n1/terminal-sessions", s.labName), s.userHeaders,
			map[string]any{"protocol": "shell", "cols": 100, "rows": 30, "resumable": true}, s.cfg.RequestTimeout)
		s.Require().Equal(http.StatusOK, status, string(data))
		var session struct{ SessionID string }
		s.Require().NoError(json.Unmarshal(data, &session))

		conn := s.terminalStream(session.SessionID)
		s.Require().NoError(conn.WriteJSON(map[string]any{"type": "resize", "cols": 120, "rows": 40}))
		s.Require().NoError(conn.WriteJSON(map[string]string{"type": "input", "data": "stty size; echo marker-$((6*7))\n"}))
		output := s.readTerminalUntil(conn, "marker-42")
		s.Require().Contains(output, "40 120", "the resize reaches the device container")
		_ = conn.Close()

		// The session survives the dropped connection and replays what was missed.
		time.Sleep(time.Second)
		conn = s.terminalStream(session.SessionID)
		replay := s.readTerminalUntil(conn, "marker-42")
		s.Require().Contains(replay, "marker-42")
		s.Require().NoError(conn.WriteJSON(map[string]string{"type": "close"}))
		_ = conn.Close()
	})

	s.Run("save", func() {
		data, status := s.request(http.MethodPost, s.url("/api/v1/labs/%s/save", s.labName), s.userHeaders, nil, 2*time.Minute)
		s.Require().Equal(http.StatusOK, status, string(data))
	})

	s.Run("node port proxy", func() {
		var data []byte
		s.Require().Eventually(func() bool {
			var status int
			data, status = s.request(http.MethodGet, s.url("/api/v1/labs/%s/nodes/n1/ports/80/proxy/", s.labName), s.userHeaders, nil, s.cfg.RequestTimeout)
			return status == http.StatusOK
		}, time.Minute, 2*time.Second, "nginx answers through the port-forward: %s", string(data))
		s.Require().Contains(strings.ToLower(string(data)), "network multitool", "the node's own web page")
	})

	s.Run("events", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url("/api/v1/events?initialState=true"), nil)
		s.Require().NoError(err)
		request.Header = s.userHeaders.Clone()
		response, err := http.DefaultClient.Do(request)
		s.Require().NoError(err)
		defer func() { _ = response.Body.Close() }()
		s.Require().Equal(http.StatusOK, response.StatusCode)
		scanner := bufio.NewScanner(response.Body)
		var sawInterface bool
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) == "" {
				continue
			}
			s.Require().Contains(line, s.labName, "only the user's lab: %s", line)
			if strings.Contains(line, `"type":"interface"`) {
				sawInterface = true
				break
			}
		}
		s.Require().True(sawInterface, "interface state events of the lab arrive")
	})

	s.Run("stats", func() {
		var nodes int
		s.Require().Eventually(func() bool {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url("/api/v1/labs/%s/stats?interval=1s", s.labName), nil)
			if err != nil {
				return false
			}
			request.Header = s.userHeaders.Clone()
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				return false
			}
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode != http.StatusOK {
				return false
			}
			line, err := bufio.NewReader(response.Body).ReadString('\n')
			if err != nil {
				return false
			}
			var sample struct{ Nodes []json.RawMessage }
			if json.Unmarshal([]byte(line), &sample) != nil {
				return false
			}
			nodes = len(sample.Nodes)
			return nodes == 2
		}, 3*time.Minute, 5*time.Second, "metrics.k8s.io reports both nodes (got %d)", nodes)
	})

	s.Run("stop and start a node", func() {
		data, status := s.request(http.MethodPost, s.url("/api/v1/labs/%s/stop?nodeFilter=n2", s.labName), s.userHeaders, nil, 5*time.Minute)
		if status != http.StatusOK && strings.Contains(string(data), `cannot update resource \"deployments\"`) {
			s.T().Skipf("the linked containerlab still stops nodes by scaling Deployments, which clabernetes-lab-editor does not allow; "+
				"it needs containerlab with Node.spec.runState: %s", string(data))
		}
		s.Require().Equal(http.StatusOK, status, string(data))
		runState, err := s.kubectl("get", "nodes.c9s.run", "n2", "-n", s.namespace, "-o", "jsonpath={.spec.runState}")
		s.Require().NoError(err, runState)
		s.Require().Equal("Stopped", runState)
		data, status = s.request(http.MethodPost, s.url("/api/v1/labs/%s/start?nodeFilter=n2", s.labName), s.userHeaders, nil, 5*time.Minute)
		s.Require().Equal(http.StatusOK, status, string(data))
		runState, err = s.kubectl("get", "nodes.c9s.run", "n2", "-n", s.namespace, "-o", "jsonpath={.spec.runState}")
		s.Require().NoError(err, runState)
		s.Require().Equal("Running", runState)
	})

	s.Run("lab names are unique per user", func() {
		topology := strings.ReplaceAll(c9sTopology, "{lab_name}", s.labName)
		data, status, err := s.createLab(s.otherHeaders, s.labName, topology, false, s.cfg.DeployTimeout)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusOK, status, string(data))
		s.Require().Contains(string(data), fmt.Sprintf("c9s-%s-%s", s.otherUser, s.labName))
		data, status, err = s.destroyLab(s.otherHeaders, s.labName, true, s.cfg.CleanupTimeout)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusOK, status, string(data))
		nodes, status := s.inspect(s.userHeaders)
		s.Require().Equal(http.StatusOK, status, "the first user's lab is untouched")
		s.Require().Len(nodes, 2)
	})

	s.Run("a plain destroy keeps the storage and the namespace", func() {
		data, status, err := s.destroyLab(s.userHeaders, s.labName, false, s.cfg.CleanupTimeout)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusOK, status, string(data))
		claims, err := s.kubectl("get", "pvc", "-n", s.namespace, "-o", "name")
		s.Require().NoError(err, claims)
		s.Require().NotEmpty(claims, "persistence keeps the node claims")
		_, status = s.inspect(s.userHeaders)
		s.Require().Equal(http.StatusNotFound, status)

		topology := strings.ReplaceAll(c9sTopology, "{lab_name}", s.labName)
		data, status, err = s.createLab(s.userHeaders, s.labName, topology, false, s.cfg.DeployTimeout)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusOK, status, string(data))
		s.Require().Contains(string(data), s.namespace, "the redeploy reuses the namespace")
	})

	s.Run("destroy with cleanup removes the namespace", func() {
		data, status, err := s.destroyLab(s.userHeaders, s.labName, true, s.cfg.CleanupTimeout)
		s.Require().NoError(err)
		s.Require().Equal(http.StatusOK, status, string(data))
		s.Require().Eventually(func() bool {
			_, err := s.kubectl("get", "namespace", s.namespace)
			return err != nil
		}, 3*time.Minute, 3*time.Second, "the namespace is deleted")
	})
}

// labRuntimeClab is a containerlab instance on the lab's namespace with the server's
// credentials, acting as identity.
func (s *C9sSuite) labRuntimeClab(identity clablabruntime.Identity) *clabcore.CLab {
	s.T().Helper()
	s.T().Setenv("CLAB_KUBECONFIG", s.provisionerKubeconfig)
	s.T().Setenv("CLAB_KUBE_CONTEXT", "")
	lab, err := clabcore.NewContainerLab(
		clabcore.WithRuntime("c9s", &clabruntime.RuntimeConfig{Timeout: time.Minute, LabNamespace: s.namespace}),
		clabcore.WithLabRuntimeIdentity(identity),
		clabcore.WithLabNameOnly(s.labName),
	)
	s.Require().NoError(err)
	return lab
}

func (s *C9sSuite) terminalStream(sessionID string) *websocket.Conn {
	s.T().Helper()
	streamURL := strings.Replace(s.url("/api/v1/terminal-sessions/%s/stream", sessionID), "http", "ws", 1)
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = s.cfg.RequestTimeout
	conn, response, err := dialer.Dial(streamURL, s.userHeaders)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	s.Require().NoError(err)
	var ready map[string]any
	s.Require().NoError(conn.ReadJSON(&ready))
	s.Require().Equal("ready", ready["type"])
	return conn
}

func (s *C9sSuite) readTerminalUntil(conn *websocket.Conn, want string) string {
	s.T().Helper()
	var output strings.Builder
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(output.String(), want) {
		_ = conn.SetReadDeadline(deadline)
		var message struct {
			Type string `json:"type"`
			Data string `json:"data"`
		}
		s.Require().NoError(conn.ReadJSON(&message), "waiting for %q; got %q", want, output.String())
		if message.Type == "output" {
			decoded, err := base64.StdEncoding.DecodeString(message.Data)
			s.Require().NoError(err)
			output.Write(decoded)
		}
	}
	return output.String()
}

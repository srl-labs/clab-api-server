package fcling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

type recordedRun struct {
	args []string
	env  []string
}

// fakeRunner answers by the runtime command's first arguments, longest match first.
type fakeRunner struct {
	mu        sync.Mutex
	runs      []recordedRun
	responses map[string]string
	failures  map[string]error
}

func (r *fakeRunner) Run(_ context.Context, _ string, args []string, env []string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runs = append(r.runs, recordedRun{args: slices.Clone(args), env: slices.Clone(env)})
	line := strings.Join(args, " ")
	if err := longestMatch(r.failures, line); err != nil {
		return "", err
	}
	return longestMatch(r.responses, line), nil
}

func longestMatch[V any](table map[string]V, line string) V {
	var best string
	var value V
	for prefix, candidate := range table {
		if strings.HasPrefix(line, prefix) && len(prefix) >= len(best) {
			best, value = prefix, candidate
		}
	}
	return value
}

func (r *fakeRunner) lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	lines := make([]string, 0, len(r.runs))
	for _, run := range r.runs {
		lines = append(lines, strings.Join(run.args, " "))
	}
	return lines
}

func (r *fakeRunner) runOf(prefix string) *recordedRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.runs {
		if strings.HasPrefix(strings.Join(r.runs[i].args, " "), prefix) {
			return &r.runs[i]
		}
	}
	return nil
}

var errNoContainer = errors.New("exit status 1: Error: No such container: clab-lab1-fcling")

func inspectJSON(t *testing.T, status string, running bool, port, token string) string {
	t.Helper()
	container := map[string]any{
		"State": map[string]any{"Status": status, "Running": running, "StartedAt": "2026-11-05T14:08:47.5Z"},
		"Config": map[string]any{
			"Image": "example/fcling:test",
			"Env":   []string{"PATH=/usr/bin", "FCLI_API_TOKEN=" + token, "XDG_STATE_HOME=/state"},
		},
		"NetworkSettings": map[string]any{
			"Ports": map[string]any{"8765/tcp": []map[string]string{{"HostIp": "127.0.0.1", "HostPort": port}}},
		},
	}
	encoded, err := json.Marshal([]any{container})
	require.NoError(t, err)
	return string(encoded)
}

// engineAt answers /api/status for one token, like a running engine.
func engineAt(t *testing.T, token string) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/status" || r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"fabric":"lab1"}`))
	}))
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	require.NoError(t, err)
	return port
}

func TestReportArgsGiveTablesAWidth(t *testing.T) {
	args := ReportArgs(Config{}, []string{"--network", "clab"}, "/labs/lab1.clab.yml", []string{"bgp-peers", "-d"})
	require.Equal(t, []string{
		"run", "--pull", "missing", "--rm", "-e", "COLUMNS=400",
		"--network", "clab",
		"-v", "/etc/hosts:/etc/hosts:ro",
		"-v", "/labs/lab1.clab.yml:/topo.yml",
		DefaultImage,
		"-t", "/topo.yml",
		"bgp-peers", "-d",
	}, args)

	args = ReportArgs(Config{Image: "example/fcling:1", PullPolicy: "Never"}, nil, "/t.yml", []string{"lldp"})
	require.Contains(t, strings.Join(args, " "), "--pull never")
	require.Contains(t, args, "example/fcling:1")

	args = ReportArgs(Config{PullPolicy: "sometimes"}, nil, "/t.yml", []string{"lldp"})
	require.Contains(t, strings.Join(args, " "), "--pull missing", "an unknown policy falls back to the default")
}

func TestDefaultImageIsPinned(t *testing.T) {
	require.Regexp(t, `:\d+\.\d+\.\d+$`, DefaultImage, "clients read the fields of its API: bump it on purpose")
}

func TestContainerNamesAndLabs(t *testing.T) {
	require.Equal(t, "clab-my-lab-fcling", ContainerName("my-lab"))
	for name, want := range map[string]string{
		"clab-my-lab-fcling":  "my-lab",
		"/clab-lab1-fcling":   "lab1",
		"clab-fcling-fcling":  "fcling",
		"WARN something else": "",
		"clab--fcling":        "",
	} {
		lab, ok := labOfContainer(name)
		require.Equal(t, want, lab, name)
		require.Equal(t, want != "", ok, name)
	}
}

func TestStartRunsTheEngine(t *testing.T) {
	runner := &fakeRunner{
		failures: map[string]error{"container inspect": errNoContainer},
	}
	m := newManager(Config{Runtime: "docker", Image: "example/fcling:test", PullPolicy: "missing"}, runner)

	networkCalls := 0
	status, err := m.Start(context.Background(), StartOptions{
		LabName:      "lab1",
		TopologyPath: "/labs/lab1.clab.yml",
		NetworkArgs: func(context.Context) ([]string, error) {
			networkCalls++
			return []string{"--network", "mgmt1", "--ip", "172.20.20.9"}, nil
		},
	})
	require.NoError(t, err)
	require.Equal(t, StateStopped, status.State, "the fake still finds no container afterwards")
	require.Equal(t, 1, networkCalls)

	run := runner.runOf("run ")
	require.NotNil(t, run)
	require.Equal(t, []string{
		"run", "-d",
		"--pull", "missing",
		"--name", "clab-lab1-fcling",
		"--label", "clab-fcling-lab=lab1",
		"--network", "mgmt1", "--ip", "172.20.20.9",
		"-p", "127.0.0.1::8765",
		"-v", "/labs/lab1.clab.yml:/topo.yml:ro",
		"-v", "clab-lab1-fcling:/state",
		"-e", "FCLI_API_TOKEN",
		"example/fcling:test",
		"-t", "/topo.yml",
		"serve", "--host", "0.0.0.0", "--no-tls", "--persist-acks",
	}, run.args)

	line := strings.Join(run.args, " ")
	require.NotContains(t, line, "containerlab=", "inspect would list the engine as a node of the lab")
	require.NotContains(t, line, "API_KEY", "no model provider's key goes into the container")

	require.Len(t, run.env, 1)
	token, ok := strings.CutPrefix(run.env[0], "FCLI_API_TOKEN=")
	require.True(t, ok)
	require.Len(t, token, 64)
	require.NotContains(t, line, token, "the token stays out of the process list")
}

func TestStartTwoLabsTokensDiffer(t *testing.T) {
	first, err := newToken()
	require.NoError(t, err)
	second, err := newToken()
	require.NoError(t, err)
	require.NotEqual(t, first, second)
}

func TestStartLeavesARunningEngineAlone(t *testing.T) {
	const token = "engine-token"
	runner := &fakeRunner{responses: map[string]string{
		"container inspect": inspectJSON(t, "running", true, engineAt(t, token), token),
	}}
	m := newManager(Config{}, runner)

	status, err := m.Start(context.Background(), StartOptions{
		LabName: "lab1",
		NetworkArgs: func(context.Context) ([]string, error) {
			t.Fatal("no address is reserved for an engine that runs")
			return nil, nil
		},
	})
	require.NoError(t, err)
	require.Equal(t, StateReady, status.State)
	require.Nil(t, runner.runOf("run "))
	require.Nil(t, runner.runOf("rm "))
}

func TestStartReplacesAnExitedEngine(t *testing.T) {
	runner := &fakeRunner{responses: map[string]string{
		"container inspect": inspectJSON(t, "exited", false, "", "old"),
		"logs":              "lab1 lists no nodes",
	}}
	m := newManager(Config{}, runner)

	_, err := m.Start(context.Background(), StartOptions{LabName: "lab1", TopologyPath: "/t.yml"})
	require.NoError(t, err)

	lines := runner.lines()
	removal := slices.Index(lines, "rm -f clab-lab1-fcling")
	require.GreaterOrEqual(t, removal, 0, lines)
	require.NotNil(t, runner.runOf("run "))
	require.Less(t, removal, slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "run ") }))
	require.Nil(t, runner.runOf("volume"), "the history stays")
}

func TestFailedStartCleansUp(t *testing.T) {
	runner := &fakeRunner{failures: map[string]error{
		"container inspect": errNoContainer,
		"run ":              errors.New("exit status 125: port is already allocated"),
	}}
	m := newManager(Config{}, runner)

	_, err := m.Start(context.Background(), StartOptions{LabName: "lab1", TopologyPath: "/t.yml"})
	require.ErrorContains(t, err, "port is already allocated")
	require.Contains(t, runner.lines(), "rm -f clab-lab1-fcling")
}

func TestStartReportsNetworkFailures(t *testing.T) {
	runner := &fakeRunner{failures: map[string]error{"container inspect": errNoContainer}}
	m := newManager(Config{}, runner)
	_, err := m.Start(context.Background(), StartOptions{
		LabName: "lab1",
		NetworkArgs: func(context.Context) ([]string, error) {
			return nil, errors.New("no address left")
		},
	})
	require.ErrorContains(t, err, "no address left")
	require.Nil(t, runner.runOf("run "))
}

func TestStatusStates(t *testing.T) {
	const token = "engine-token"
	port := engineAt(t, token)

	t.Run("no container is stopped", func(t *testing.T) {
		m := newManager(Config{}, &fakeRunner{failures: map[string]error{"container inspect": errNoContainer}})
		status, err := m.Status(context.Background(), "lab1")
		require.NoError(t, err)
		require.Equal(t, Status{State: StateStopped}, status)
	})

	t.Run("an empty listing is stopped", func(t *testing.T) {
		m := newManager(Config{}, &fakeRunner{responses: map[string]string{"container inspect": "[]"}})
		status, err := m.Status(context.Background(), "lab1")
		require.NoError(t, err)
		require.Equal(t, StateStopped, status.State)
	})

	t.Run("answering with its token, read back from inspect, is ready", func(t *testing.T) {
		m := newManager(Config{}, &fakeRunner{responses: map[string]string{
			"container inspect": inspectJSON(t, "running", true, port, token),
		}})
		status, err := m.Status(context.Background(), "lab1")
		require.NoError(t, err)
		require.Equal(t, Status{
			State:         StateReady,
			Image:         "example/fcling:test",
			ContainerName: "clab-lab1-fcling",
			StartedAt:     "2026-11-05T14:08:47.5Z",
		}, status)
	})

	t.Run("refusing the token is still starting", func(t *testing.T) {
		m := newManager(Config{}, &fakeRunner{responses: map[string]string{
			"container inspect": inspectJSON(t, "running", true, port, "another-token"),
		}})
		status, err := m.Status(context.Background(), "lab1")
		require.NoError(t, err)
		require.Equal(t, StateStarting, status.State)
	})

	t.Run("not listening yet is starting", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		closedPort := fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)
		require.NoError(t, listener.Close())
		m := newManager(Config{}, &fakeRunner{responses: map[string]string{
			"container inspect": inspectJSON(t, "running", true, closedPort, token),
		}})
		status, err := m.Status(context.Background(), "lab1")
		require.NoError(t, err)
		require.Equal(t, StateStarting, status.State)
	})

	t.Run("created is starting", func(t *testing.T) {
		m := newManager(Config{}, &fakeRunner{responses: map[string]string{
			"container inspect": inspectJSON(t, "created", false, "", token),
		}})
		status, err := m.Status(context.Background(), "lab1")
		require.NoError(t, err)
		require.Equal(t, StateStarting, status.State)
	})

	t.Run("exited is failed, with the end of its log", func(t *testing.T) {
		runner := &fakeRunner{responses: map[string]string{
			"container inspect": inspectJSON(t, "exited", false, "", token),
			"logs":              "topology lists no SR Linux nodes",
		}}
		m := newManager(Config{}, runner)
		status, err := m.Status(context.Background(), "lab1")
		require.NoError(t, err)
		require.Equal(t, StateFailed, status.State)
		require.Equal(t, "topology lists no SR Linux nodes", status.Error)
		require.Contains(t, runner.lines(), "logs --tail 20 clab-lab1-fcling")
	})

	t.Run("a runtime that does not answer is an error, not stopped", func(t *testing.T) {
		m := newManager(Config{}, &fakeRunner{failures: map[string]error{
			"container inspect": errors.New("Cannot connect to the Docker daemon"),
		}})
		_, err := m.Status(context.Background(), "lab1")
		require.ErrorContains(t, err, "Cannot connect")
	})
}

func TestTargetIsReadBackFromInspect(t *testing.T) {
	m := newManager(Config{}, &fakeRunner{responses: map[string]string{
		"container inspect": inspectJSON(t, "running", true, "49153", "engine-token"),
	}})
	target, err := m.Target(context.Background(), "lab1")
	require.NoError(t, err)
	require.Equal(t, Target{Host: "127.0.0.1:49153", Token: "engine-token"}, target)

	for name, runner := range map[string]*fakeRunner{
		"no container": {failures: map[string]error{"container inspect": errNoContainer}},
		"exited":       {responses: map[string]string{"container inspect": inspectJSON(t, "exited", false, "49153", "x")}},
		"no port":      {responses: map[string]string{"container inspect": inspectJSON(t, "running", true, "", "x")}},
		"no token":     {responses: map[string]string{"container inspect": inspectJSON(t, "running", true, "49153", "")}},
	} {
		_, err := newManager(Config{}, runner).Target(context.Background(), "lab1")
		require.ErrorIs(t, err, ErrEngineNotRunning, name)
	}
}

func TestStopKeepsTheHistoryAndRemoveDoesNot(t *testing.T) {
	runner := &fakeRunner{}
	m := newManager(Config{}, runner)
	require.NoError(t, m.Stop(context.Background(), "lab1"))
	require.Equal(t, []string{"stop -t 5 clab-lab1-fcling", "rm -f clab-lab1-fcling"}, runner.lines())

	runner = &fakeRunner{}
	m = newManager(Config{}, runner)
	require.NoError(t, m.Remove(context.Background(), "lab1"))
	require.Equal(t, []string{"rm -f clab-lab1-fcling", "volume rm -f clab-lab1-fcling"}, runner.lines())
}

func TestStopAndRemoveWithoutAnEngine(t *testing.T) {
	runner := &fakeRunner{failures: map[string]error{
		"stop":      errNoContainer,
		"rm":        errNoContainer,
		"volume rm": errors.New("no volume with name clab-lab1-fcling found"),
	}}
	m := newManager(Config{}, runner)
	require.NoError(t, m.Stop(context.Background(), "lab1"))
	require.NoError(t, m.Remove(context.Background(), "lab1"))

	m = newManager(Config{}, &fakeRunner{failures: map[string]error{"rm": errors.New("permission denied")}})
	require.ErrorContains(t, m.Stop(context.Background(), "lab1"), "permission denied")
}

func TestSweepRemovesEnginesWhoseLabIsGone(t *testing.T) {
	runner := &fakeRunner{
		responses: map[string]string{
			"ps -a --filter label=clab-fcling-lab":       "clab-gone-fcling\nclab-alive-fcling\nclab-broken-fcling\nWARN not a name",
			"ps -a -q --filter label=containerlab=alive": "0123456789ab",
			"ps -a -q --filter label=containerlab=gone":  "",
		},
		failures: map[string]error{
			"ps -a -q --filter label=containerlab=broken": errors.New("daemon hiccup"),
		},
	}
	m := newManager(Config{}, runner)
	m.sweep(context.Background())

	lines := runner.lines()
	require.Contains(t, lines, "rm -f clab-gone-fcling")
	require.Contains(t, lines, "volume rm -f clab-gone-fcling")
	require.NotContains(t, lines, "rm -f clab-alive-fcling")
	require.NotContains(t, lines, "rm -f clab-broken-fcling", "a failed look removes nothing")
}

func TestSweepSurvivesAFailedListing(t *testing.T) {
	runner := &fakeRunner{failures: map[string]error{"ps": errors.New("daemon down")}}
	newManager(Config{}, runner).sweep(context.Background())
	require.Len(t, runner.lines(), 1)
}

func TestShutdownStopsTheSweeperAndLeavesEngines(t *testing.T) {
	m := NewManager(Config{Runtime: "podman"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Shutdown(ctx)
	select {
	case <-m.doneCh:
	default:
		t.Fatal("the sweeper still runs")
	}
	m.Shutdown(ctx)
	require.Equal(t, "podman", m.cfg.runtimeBinary())
	require.Equal(t, "docker", Config{Runtime: "anything"}.runtimeBinary())
}

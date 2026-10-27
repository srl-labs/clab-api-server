package capture

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCreateLinkedWiresharkSessionsUsesTheGivenLink(t *testing.T) {
	runner := &fakeCommandRunner{t: t, responses: map[string]string{
		commandKey("docker", []string{"rm", "-f", "wireshark-container-id"}): "",
	}}
	manager := newTestManager(t, ManagerConfig{
		Runtime:              "c9s",
		WiresharkDockerImage: "example/wireshark:test",
		WiresharkPullPolicy:  "never",
		WiresharkSessionTTL:  time.Hour,
	})
	manager.runner = runner
	var linksMinted int
	runner.onRun = func(cmd recordedCommand) {
		if len(cmd.args) > 0 && cmd.args[0] == "run" {
			require.Equal(t, 1, linksMinted, "the link is minted right before its container starts")
			runner.responses[commandKey(cmd.name, cmd.args)] = "wireshark-container-id\n"
		}
	}

	sessions, err := manager.CreateLinkedWiresharkSessions(context.Background(), CreateLinkedWiresharkSessionsOptions{
		Username: "alice",
		LabName:  "lab1",
		Specs: []WiresharkLinkSpec{{
			ContainerName:  "lab1-n1",
			InterfaceNames: []string{"eth1", "eth2"},
			RunArgs:        []string{"--add-host", "clab-host:host-gateway"},
			PacketflixLink: func(time.Time) (string, func(), error) {
				linksMinted++
				return "packetflix:wss://clab-host:8443/api/v1/capture/packetflix/T", nil, nil
			},
		}},
	})
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	require.Equal(t, "lab1-n1", sessions[0].ContainerName)
	require.Equal(t, []string{"eth1", "eth2"}, sessions[0].InterfaceNames)
	require.False(t, sessions[0].ShowVolumeTip)

	runArgs := strings.Join(runner.commandArgsContaining("run", "example/wireshark:test"), " ")
	require.Contains(t, runArgs, "--add-host clab-host:host-gateway -e PACKETFLIX_LINK=packetflix:wss://clab-host:8443/api/v1/capture/packetflix/T example/wireshark:test")
	require.Contains(t, runArgs, "-p 127.0.0.1:")
	require.Nil(t, runner.commandArgsContaining("network", "connect"), "no Edgeshark network")
	require.Nil(t, runner.commandArgsContaining("ps"), "no Edgeshark lookup")
	require.Nil(t, runner.commandArgsContaining("-v"), "no lab directory mount")
}

func TestCreateLinkedWiresharkSessionsStopsOnALinkFailure(t *testing.T) {
	runner := &fakeCommandRunner{t: t, responses: map[string]string{
		commandKey("docker", []string{"rm", "-f", "first-id"}): "",
	}}
	manager := newTestManager(t, ManagerConfig{Runtime: "c9s", WiresharkPullPolicy: "never"})
	manager.runner = runner
	runner.onRun = func(cmd recordedCommand) {
		if len(cmd.args) > 0 && cmd.args[0] == "run" {
			runner.responses[commandKey(cmd.name, cmd.args)] = "first-id\n"
		}
	}
	released := 0
	link := func(time.Time) (string, func(), error) { return "packetflix:ws://h:1/x", func() { released++ }, nil }
	_, err := manager.CreateLinkedWiresharkSessions(context.Background(), CreateLinkedWiresharkSessionsOptions{
		Username: "alice", LabName: "lab1",
		Specs: []WiresharkLinkSpec{
			{ContainerName: "lab1-n1", InterfaceNames: []string{"eth1"}, PacketflixLink: link},
			{ContainerName: "lab1-n2", InterfaceNames: []string{"eth1"}, PacketflixLink: func(time.Time) (string, func(), error) {
				return "", nil, errors.New("no ticket")
			}},
		},
	})
	require.ErrorContains(t, err, "no ticket")
	require.NotNil(t, runner.commandArgsContaining("rm", "-f", "first-id"), "the started session is stopped")
	require.Equal(t, 1, released, "and its link released")
	closed, err := manager.CloseAllSessions(context.Background(), "", true)
	require.NoError(t, err)
	require.Zero(t, closed)
}

func TestContainerRuntimeAvailableIsCached(t *testing.T) {
	runner := &fakeCommandRunner{t: t, responses: map[string]string{}, errors: map[string]error{
		commandKey("docker", []string{"version", "--format", "{{.Server.Version}}"}): errors.New("cannot connect"),
	}}
	manager := newTestManager(t, ManagerConfig{Runtime: "c9s"})
	manager.runner = runner
	require.False(t, manager.ContainerRuntimeAvailable(context.Background()))
	require.False(t, manager.ContainerRuntimeAvailable(context.Background()))
	require.Len(t, runner.commands, 1, "probed once a minute")

	manager.runtimeProbedAt = time.Time{}
	runner.errors = nil
	runner.responses[commandKey("docker", []string{"version", "--format", "{{.Server.Version}}"})] = "29.0.0"
	require.True(t, manager.ContainerRuntimeAvailable(context.Background()))
}

// TestLinkedSessionReleasesItsLinkWhenItEnds checks that a session's link (a session capture
// ticket) is released exactly once whichever way the session ends: closed, closed with all
// sessions, expired, failed to start, or shut down.
func TestLinkedSessionReleasesItsLinkWhenItEnds(t *testing.T) {
	runner := &fakeCommandRunner{t: t, responses: map[string]string{}, errors: map[string]error{}}
	manager := newTestManager(t, ManagerConfig{Runtime: "c9s", WiresharkPullPolicy: "never", WiresharkSessionTTL: time.Hour})
	manager.runner = runner
	started, failRun := 0, false
	runner.onRun = func(cmd recordedCommand) {
		if len(cmd.args) == 0 || cmd.args[0] != "run" {
			return
		}
		if failRun {
			runner.errors[commandKey(cmd.name, cmd.args)] = errors.New("docker run failed")
			return
		}
		started++
		id := fmt.Sprintf("container-%d", started)
		runner.responses[commandKey(cmd.name, cmd.args)] = id + "\n"
		runner.responses[commandKey("docker", []string{"rm", "-f", id})] = ""
	}
	released := map[string]int{}
	var linkExpiry time.Time
	start := func(name string) WiresharkSessionInfo {
		t.Helper()
		sessions, err := manager.CreateLinkedWiresharkSessions(context.Background(), CreateLinkedWiresharkSessionsOptions{
			Username: "alice", LabName: "lab1",
			Specs: []WiresharkLinkSpec{{ContainerName: name, InterfaceNames: []string{"eth1"},
				PacketflixLink: func(expiresAt time.Time) (string, func(), error) {
					linkExpiry = expiresAt
					return "packetflix:ws://h:1/" + name, func() { released[name]++ }, nil
				}}},
		})
		require.NoError(t, err)
		require.Len(t, sessions, 1)
		return sessions[0]
	}

	closed := start("closed")
	require.Equal(t, closed.ExpiresAt, linkExpiry, "the link learns when its session expires")
	require.WithinDuration(t, time.Now().Add(time.Hour), linkExpiry, 5*time.Second)
	require.Zero(t, released["closed"], "a running session keeps its link")
	require.NoError(t, manager.CloseSession(context.Background(), closed.SessionID, "alice", false))
	require.Equal(t, 1, released["closed"])

	start("all")
	count, err := manager.CloseAllSessions(context.Background(), "alice", false)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Equal(t, 1, released["all"])

	expired := start("expired")
	manager.mu.Lock()
	manager.sessions[expired.SessionID].expiresAt = time.Now().Add(-time.Second)
	manager.mu.Unlock()
	manager.sweepExpiredSessions()
	require.Equal(t, 1, released["expired"])

	failRun = true
	_, err = manager.CreateLinkedWiresharkSessions(context.Background(), CreateLinkedWiresharkSessionsOptions{
		Username: "alice", LabName: "lab1",
		Specs: []WiresharkLinkSpec{{ContainerName: "failed", InterfaceNames: []string{"eth1"},
			PacketflixLink: func(time.Time) (string, func(), error) {
				return "packetflix:ws://h:1/failed", func() { released["failed"]++ }, nil
			}}},
	})
	require.ErrorContains(t, err, "docker run failed")
	require.Equal(t, 1, released["failed"], "a session that did not start releases its link")
	failRun = false

	// A server shutdown ends the sessions as well (a manager of its own: the test's cleanup
	// shuts the first one down).
	manager = NewManager(ManagerConfig{Runtime: "c9s", WiresharkPullPolicy: "never", WiresharkSessionTTL: time.Hour})
	manager.runner = runner
	start("shutdown")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	manager.Shutdown(ctx)
	require.Equal(t, 1, released["shutdown"])
	for name, times := range released {
		require.Equal(t, 1, times, "released once: %s", name)
	}
}

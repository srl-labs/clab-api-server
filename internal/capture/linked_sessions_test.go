package capture

import (
	"context"
	"errors"
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
			PacketflixLink: func() (string, error) {
				linksMinted++
				return "packetflix:wss://clab-host:8443/api/v1/capture/packetflix/T", nil
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
	link := func() (string, error) { return "packetflix:ws://h:1/x", nil }
	_, err := manager.CreateLinkedWiresharkSessions(context.Background(), CreateLinkedWiresharkSessionsOptions{
		Username: "alice", LabName: "lab1",
		Specs: []WiresharkLinkSpec{
			{ContainerName: "lab1-n1", InterfaceNames: []string{"eth1"}, PacketflixLink: link},
			{ContainerName: "lab1-n2", InterfaceNames: []string{"eth1"}, PacketflixLink: func() (string, error) {
				return "", errors.New("no ticket")
			}},
		},
	})
	require.ErrorContains(t, err, "no ticket")
	require.NotNil(t, runner.commandArgsContaining("rm", "-f", "first-id"), "the started session is stopped")
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

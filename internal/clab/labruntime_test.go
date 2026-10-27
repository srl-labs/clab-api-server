package clab

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	"github.com/stretchr/testify/require"

	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/testsupport/fakec9s"
)

// recordingScoper places every lab of a user in "ns-<user>-<lab>" and impersonates
// "clab:<user>", like the Kubernetes scoper does, and records what it was asked.
type recordingScoper struct {
	prepared  []string
	destroyed []string
	cleanup   []bool
	missing   map[string]bool
}

func (s *recordingScoper) scope(username, labName string) LabScope {
	return LabScope{
		LabName:   labName,
		Namespace: "ns-" + username + "-" + labName,
		Owner:     username,
		Identity:  clablabruntime.Identity{User: "clab:" + username, Groups: []string{"clab:users"}},
	}
}

func (s *recordingScoper) ScopeForLab(_ context.Context, username, labName string) (LabScope, error) {
	if s.missing[labName] {
		return LabScope{}, ErrLabNotFound
	}
	return s.scope(username, labName), nil
}

func (s *recordingScoper) PrepareDeploy(_ context.Context, username, labName, _ string) (LabScope, error) {
	s.prepared = append(s.prepared, username+"/"+labName)
	return s.scope(username, labName), nil
}

func (s *recordingScoper) ListScopes(_ context.Context, username string) ([]LabScope, error) {
	return []LabScope{s.scope(username, "lab1"), s.scope(username, "lab2")}, nil
}

func (s *recordingScoper) AfterDestroy(_ context.Context, scope LabScope, cleanup bool) error {
	s.destroyed = append(s.destroyed, scope.Namespace)
	s.cleanup = append(s.cleanup, cleanup)
	return nil
}

// useC9s selects the c9s runtime backed by the fake for one test.
func useC9s(t *testing.T) (*Service, *fakec9s.Runtime, *recordingScoper) {
	t.Helper()
	previous := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previous })
	config.AppConfig.ClabRuntime = config.RuntimeC9s
	config.AppConfig.ClabC9sExposeType = "None"
	config.AppConfig.ClabC9sPersistence = true

	fake := fakec9s.Install(t)
	scoper := &recordingScoper{missing: map[string]bool{}}
	svc := NewService()
	svc.SetLabScoper(scoper)
	return svc, fake, scoper
}

func currentUsername(t *testing.T) string {
	t.Helper()
	current, err := user.Current()
	require.NoError(t, err)
	return current.Username
}

func writeTopology(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name+".clab.yml")
	content := "name: " + name + "\ntopology:\n  nodes:\n    n1:\n      kind: linux\n      image: alpine\n    n2:\n      kind: linux\n      image: alpine\n  links:\n    - endpoints: [\"n1:eth1\", \"n2:eth1\"]\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func TestRuntimeKindAndUnsupportedError(t *testing.T) {
	previous := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previous })

	config.AppConfig.ClabRuntime = ""
	require.Equal(t, "docker", RuntimeKind())
	require.False(t, IsLabRuntime())
	require.NoError(t, RequireContainerRuntime("image management"))

	config.AppConfig.ClabRuntime = "c9s"
	require.True(t, IsLabRuntime())
	err := RequireContainerRuntime("image management")
	require.ErrorIs(t, err, ErrNotSupportedByLabRuntime)
	require.EqualError(t, err, "image management is not supported by lab runtime c9s")
}

func TestContainerRuntimeOnlyServiceCallsRefuseLabRuntime(t *testing.T) {
	svc, fake, _ := useC9s(t)
	ctx := context.Background()

	_, err := svc.ListRuntimeImages(ctx)
	require.ErrorIs(t, err, ErrNotSupportedByLabRuntime)
	_, err = svc.PullRuntimeImage(ctx, "alpine")
	require.ErrorIs(t, err, ErrNotSupportedByLabRuntime)
	_, err = svc.RunFcliCommand(ctx, FcliRunOptions{})
	require.ErrorIs(t, err, ErrNotSupportedByLabRuntime)
	_, err = svc.SaveSnapshots(ctx, SnapshotSaveOptions{LabName: "lab1"})
	require.ErrorIs(t, err, ErrNotSupportedByLabRuntime)
	_, err = svc.TailscaleStatus(ctx, "lab1")
	require.ErrorIs(t, err, ErrNotSupportedByLabRuntime)
	_, err = svc.ShowLabNetem(ctx, "lab1", "alice")
	require.ErrorIs(t, err, ErrNotSupportedByLabRuntime)
	_, err = svc.ListLabLinks(ctx, nil)
	require.ErrorIs(t, err, ErrNotSupportedByLabRuntime)
	_, err = svc.ContainerStats(ctx, nil)
	require.ErrorIs(t, err, ErrNotSupportedByLabRuntime)
	_, err = svc.RunContainerlabTool(ctx, ContainerlabToolRunOptions{Args: []string{"tools", "sshx"}})
	require.ErrorIs(t, err, ErrNotSupportedByLabRuntime)
	err = svc.RunNodeLifecycleAction(ctx, NodeLifecycleOptions{Action: NodeLifecycleActionPause, ContainerName: "x"})
	require.ErrorIs(t, err, ErrNotSupportedByLabRuntime)
	_, err = svc.getContainerRuntime()
	require.ErrorIs(t, err, ErrNotSupportedByLabRuntime)
	require.Empty(t, fake.Calls(), "refused calls must not reach the runtime")
}

func TestListContainersOnLabRuntimeActsAsTheUserPerScope(t *testing.T) {
	svc, fake, scoper := useC9s(t)
	ctx := context.Background()
	fake.AddLab("ns-alice-lab1", "lab1", "alice", "/home/alice/lab1.clab.yml", "n1", "n2")
	fake.AddLab("ns-alice-lab2", "lab2", "alice", "/home/alice/lab2.clab.yml", "n1")
	fake.AddLab("ns-bob-lab1", "lab1", "bob", "/home/bob/lab1.clab.yml", "n1")

	_, err := svc.ListContainers(ctx, ListOptions{})
	require.ErrorContains(t, err, "requesting user", "lab runtime listings fail closed without a user")

	containers, err := svc.ListContainers(ctx, ListOptions{Username: "alice"})
	require.NoError(t, err)
	require.Len(t, containers, 3)
	for _, call := range fake.CallsOf("list") {
		require.Equal(t, "clab:alice", call.Identity.User)
		require.True(t, strings.HasPrefix(call.Namespace, "ns-alice-"), call.Namespace)
	}

	containers, err = svc.ListContainers(ctx, ListOptions{Username: "alice", LabName: "lab1"})
	require.NoError(t, err)
	require.Len(t, containers, 2)
	info := ContainerToClabContainerInfo(containers[0])
	require.Equal(t, "lab1-n1", info.Name)
	require.Equal(t, "ns-alice-lab1/lab1/n1", info.ContainerID)
	require.Equal(t, "ns-alice-lab1", info.Namespace)
	require.Equal(t, "lab1-n1-pod", info.Pod)
	require.Equal(t, "node-n1", info.Container)
	require.Equal(t, "alice", info.Owner)
	inspect := fake.CallsOf("inspect")
	require.Equal(t, "ns-alice-lab1", inspect[len(inspect)-1].Namespace)

	scoper.missing["gone"] = true
	containers, err = svc.ListContainers(ctx, ListOptions{Username: "alice", LabName: "gone"})
	require.NoError(t, err)
	require.Empty(t, containers)

	containers, err = svc.ListContainers(ctx, ListOptions{Username: "alice", LabName: "lab3"})
	require.NoError(t, err, "a lab the runtime does not know is an empty listing")
	require.Empty(t, containers)
}

func TestDeployOnLabRuntimePreparesTheScopeAndAppliesC9sSettings(t *testing.T) {
	svc, fake, scoper := useC9s(t)
	username := currentUsername(t)
	topology := writeTopology(t, "demo")
	config.AppConfig.ClabC9sExposeType = "LoadBalancer"
	config.AppConfig.ClabC9sPersistence = false
	config.AppConfig.ClabC9sImagePullSecret = "regcred"

	containers, err := svc.Deploy(context.Background(), DeployOptions{
		TopoPath: topology, LabName: "demo", Username: username, Actor: username,
	})
	require.NoError(t, err)
	require.Len(t, containers, 2)
	require.Equal(t, []string{username + "/demo"}, scoper.prepared)
	deploys := fake.CallsOf("deploy")
	require.Len(t, deploys, 1)
	require.Equal(t, "ns-"+username+"-demo", deploys[0].Namespace)
	require.Equal(t, "clab:"+username, deploys[0].Identity.User)
	require.Equal(t, username, deploys[0].Owner)
	require.Equal(t, "LoadBalancer", deploys[0].ExposeType)
	require.Equal(t, "regcred", deploys[0].ImagePullSecret)
	require.True(t, deploys[0].NoPersistence)
	require.Equal(t, username, fake.Lab("ns-"+username+"-demo", "demo").Owner)
}

func TestDeployOnLabRuntimeRejectsLocalOnlyOptionsAndNames(t *testing.T) {
	svc, fake, scoper := useC9s(t)
	username := currentUsername(t)
	topology := writeTopology(t, "demo")
	ctx := context.Background()

	for _, opts := range []DeployOptions{
		{TopoPath: topology, LabName: "demo", Username: username, NodeFilter: []string{"n1"}},
		{TopoPath: topology, LabName: "demo", Username: username, MgmtNetwork: "x"},
		{TopoPath: topology, LabName: "demo", Username: username, RestoreNodeSnapshots: []string{"n1=/x.tar"}},
		{TopoPath: topology, LabName: "demo", Username: username, ExportTemplate: "t.tmpl"},
	} {
		_, err := svc.Deploy(ctx, opts)
		require.ErrorIs(t, err, ErrNotSupportedByLabRuntime)
	}
	_, err := svc.Deploy(ctx, DeployOptions{TopoPath: topology, LabName: "Demo_1", Username: username})
	require.ErrorIs(t, err, ErrInvalidLabName)
	require.ErrorContains(t, err, `"demo-1"`)
	require.ErrorIs(t, svc.ValidateDeploy(DeployOptions{TopoPath: topology, LabName: "Demo_1", Username: username}), ErrInvalidLabName)
	require.Empty(t, scoper.prepared)
	require.Empty(t, fake.CallsOf("deploy"))
}

func TestApplyOnLabRuntime(t *testing.T) {
	svc, fake, scoper := useC9s(t)
	username := currentUsername(t)
	topology := writeTopology(t, "demo")
	ctx := context.Background()

	outcome, err := svc.Apply(ctx, ApplyOptions{TopoPath: topology, LabName: "demo", Username: username, DryRun: true})
	require.NoError(t, err)
	require.True(t, outcome.DryRun)
	require.NotNil(t, outcome.RuntimePlan)
	require.Empty(t, scoper.prepared, "a dry run provisions nothing")
	response := ApplyOutcomeToResponse(outcome)
	require.Equal(t, "ns-"+username+"-demo", response.RuntimePlan.Namespace)
	require.Len(t, response.RuntimePlan.Changes, 2)
	require.Equal(t, "recreate", response.RuntimePlan.Changes[0].Action)
	require.Empty(t, fake.CallsOf("deploy"))

	outcome, err = svc.Apply(ctx, ApplyOptions{TopoPath: topology, LabName: "demo", Username: username})
	require.NoError(t, err)
	require.True(t, outcome.DeployedLab)
	require.Len(t, fake.CallsOf("deploy"), 1)
	require.Equal(t, []string{username + "/demo"}, scoper.prepared)

	_, err = svc.Apply(ctx, ApplyOptions{TopoPath: topology, LabName: "demo", Username: username, ExportTemplate: "x"})
	require.ErrorIs(t, err, ErrNotSupportedByLabRuntime)
}

func TestDestroyOnLabRuntime(t *testing.T) {
	svc, fake, scoper := useC9s(t)
	ctx := context.Background()
	fake.AddLab("ns-alice-lab1", "lab1", "alice", "", "n1")

	require.ErrorIs(t, svc.Destroy(ctx, DestroyOptions{LabName: "lab1", Username: "alice", Graceful: true}), ErrNotSupportedByLabRuntime)
	require.ErrorIs(t, svc.Destroy(ctx, DestroyOptions{LabName: "lab1", Username: "alice", NodeFilter: []string{"n1"}}), ErrNotSupportedByLabRuntime)

	require.NoError(t, svc.Destroy(ctx, DestroyOptions{LabName: "lab1", Username: "alice", Cleanup: true}))
	destroys := fake.CallsOf("destroy")
	require.Len(t, destroys, 1)
	require.Equal(t, "ns-alice-lab1", destroys[0].Namespace)
	require.Equal(t, "clab:alice", destroys[0].Identity.User)
	require.True(t, destroys[0].Cleanup)
	require.Equal(t, []string{"ns-alice-lab1"}, scoper.destroyed)
	require.Equal(t, []bool{true}, scoper.cleanup)
	require.Nil(t, fake.Lab("ns-alice-lab1", "lab1"))
}

func TestNodeLifecycleExecAndSaveOnLabRuntime(t *testing.T) {
	svc, fake, _ := useC9s(t)
	ctx := context.Background()
	fake.AddLab("ns-alice-lab1", "lab1", "alice", "", "n1", "n2")

	for _, action := range []NodeLifecycleAction{NodeLifecycleActionStop, NodeLifecycleActionStart, NodeLifecycleActionRestart} {
		require.NoError(t, svc.RunLabLifecycleAction(ctx, NodeLifecycleOptions{
			LabName: "lab1", Username: "alice", NodeNames: []string{"n1"}, Action: action,
		}))
		calls := fake.CallsOf(string(action))
		require.Len(t, calls, 1, action)
		require.Equal(t, []string{"n1"}, calls[0].Nodes)
		require.Equal(t, "ns-alice-lab1", calls[0].Namespace)
		require.Equal(t, "clab:alice", calls[0].Identity.User)
	}

	result, err := svc.Exec(ctx, ExecOptions{LabName: "lab1", Username: "alice", Commands: []string{"ip a"}})
	require.NoError(t, err)
	response := ExecCollectionToExecResponse(result)
	require.Len(t, response, 2)
	execs := fake.CallsOf("exec")
	require.Len(t, execs, 2)
	require.Equal(t, "clab:alice", execs[0].Identity.User)

	filtered, err := svc.ExecFiltered(ctx, ExecFilterOptions{LabName: "lab1", Username: "alice", NodeNames: []string{"n2"}, Commands: []string{"uname"}})
	require.NoError(t, err)
	filteredResponse := ExecCollectionToExecResponse(filtered)
	require.Len(t, filteredResponse, 1)
	require.Contains(t, filteredResponse, "lab1-n2")
	last := fake.CallsOf("exec")
	require.Equal(t, []string{"n2"}, last[len(last)-1].Nodes)
	require.Equal(t, "ns-alice-lab1", last[len(last)-1].Namespace)

	_, err = svc.ExecFiltered(ctx, ExecFilterOptions{LabName: "lab1", Username: "alice", NodeNames: []string{"missing"}, Commands: []string{"uname"}})
	require.ErrorIs(t, err, ErrNoMatchingContainers)

	root := t.TempDir()
	saved, err := svc.SaveConfig(ctx, SaveOptions{LabName: "lab1", Username: "alice", NodeFilter: []string{"n1"},
		CopyOut: &OutputDir{Root: root, Rel: "backup", UID: -1, GID: -1}})
	require.NoError(t, err)
	require.Equal(t, filepath.Join(root, "backup", "clab-lab1"), saved.CopyDir)
	data, err := os.ReadFile(filepath.Join(saved.CopyDir, "n1", "config.txt"))
	require.NoError(t, err, "the symlink resolves to the saved file")
	require.Equal(t, "config of n1", string(data))
	require.NoFileExists(t, filepath.Join(saved.CopyDir, "n2", "config-1.txt"))
	saves := fake.CallsOf("save")
	require.Equal(t, []string{"n1"}, saves[0].Nodes)
}

func TestWriteLabRuntimeSavedFilesRefusesEscapes(t *testing.T) {
	root := t.TempDir()
	dst := OutputDir{Root: root, UID: -1, GID: -1}
	_, err := writeLabRuntimeSavedFiles(dst, "clab-x", []clablabruntime.SavedFile{{NodeName: "n1", Name: "../../etc/passwd", Data: []byte("x")}})
	require.Error(t, err)
	_, err = writeLabRuntimeSavedFiles(dst, "clab-x", []clablabruntime.SavedFile{{NodeName: "n1", Name: "cfg", LinkTarget: "/etc/passwd"}})
	require.Error(t, err)
	_, err = writeLabRuntimeSavedFiles(dst, "../x", nil)
	require.Error(t, err)
}

func TestNodeAccessOnLabRuntimeActsAsTheUser(t *testing.T) {
	svc, fake, _ := useC9s(t)
	ctx := context.Background()
	fake.AddLab("ns-alice-lab1", "lab1", "alice", "", "n1")
	fake.Logs = "line one\nline two\n"
	fake.Stats = []clablabruntime.NodeStats{{NodeName: "n1", CPUMilliCores: 250, MemoryBytes: 1 << 20}}

	tail := int64(5)
	var stdout, stderr bytes.Buffer
	require.NoError(t, svc.NodeLogs(ctx, NodeLogsOptions{Username: "alice", LabName: "lab1", NodeName: "n1", Tail: &tail}, &stdout, &stderr))
	require.Equal(t, fake.Logs, stdout.String())
	logs := fake.CallsOf("logs")
	require.Equal(t, 5, logs[0].Port)
	require.Equal(t, "clab:alice", logs[0].Identity.User)

	conn, err := svc.DialNodePort(ctx, "alice", "lab1", "n1", 22)
	require.NoError(t, err)
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	buffer := make([]byte, 4)
	_, err = io.ReadFull(conn, buffer)
	require.NoError(t, err)
	require.Equal(t, "ping", string(buffer))
	require.NoError(t, conn.Close())
	dials := fake.CallsOf("dial")
	require.Equal(t, 22, dials[0].Port)
	require.Equal(t, []string{"n1"}, dials[0].Nodes)
	_, err = svc.DialNodePort(ctx, "alice", "lab1", "n1", 70000)
	require.Error(t, err)

	stats, err := svc.SampleNodeStats(ctx, "alice", "lab1")
	require.NoError(t, err)
	require.Equal(t, int64(250), stats[0].CPUMilliCores)

	fake.StatsErr = fakec9s.ErrMetricsUnavailable
	_, err = svc.SampleNodeStats(ctx, "alice", "lab1")
	require.ErrorIs(t, err, ErrMetricsUnavailable)

	stdinReader, stdinWriter := io.Pipe()
	var output bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- svc.AttachNode(ctx, "alice", "lab1", "n1", []string{"sh"}, true,
			clablabruntime.AttachStreams{Stdin: stdinReader, Stdout: &output})
	}()
	_, _ = stdinWriter.Write([]byte("exit 3\n"))
	select {
	case err := <-done:
		var exitErr *clablabruntime.CommandExitError
		require.True(t, errors.As(err, &exitErr), "got %v", err)
		require.Equal(t, 3, exitErr.Code)
	case <-time.After(5 * time.Second):
		t.Fatal("attach did not end")
	}
	attaches := fake.CallsOf("attach")
	require.Equal(t, "clab:alice", attaches[0].Identity.User)
	require.Equal(t, "ns-alice-lab1", attaches[0].Namespace)
}

func TestNodeAccessNeedsALabRuntime(t *testing.T) {
	previous := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previous })
	config.AppConfig.ClabRuntime = "docker"
	svc := NewService()
	_, err := svc.DialNodePort(context.Background(), "alice", "lab1", "n1", 22)
	require.ErrorContains(t, err, "needs a lab runtime")
	_, err = svc.SampleNodeStats(context.Background(), "alice", "lab1")
	require.ErrorContains(t, err, "needs a lab runtime")
}

func TestServerScoperUsesTheServerIdentity(t *testing.T) {
	svc, fake, _ := useC9s(t)
	svc.SetLabScoper(nil)
	fake.AddLab("c9s-lab1", "lab1", "alice", "", "n1")

	containers, err := svc.ListContainers(context.Background(), ListOptions{Username: "alice", LabName: "lab1"})
	require.NoError(t, err)
	require.Len(t, containers, 1)
	inspect := fake.CallsOf("inspect")
	require.True(t, inspect[0].Identity.IsZero())
	require.Equal(t, "c9s-lab1", inspect[0].Namespace)

	scopes, err := svc.EventScopes(context.Background(), "alice")
	require.NoError(t, err)
	require.Len(t, scopes, 1)
	require.Empty(t, scopes[0].Namespace)
}

func TestGraphExportRendersFromTheTopologyOnLabRuntime(t *testing.T) {
	svc, fake, _ := useC9s(t)
	topology := writeTopology(t, "graph")
	result, err := svc.GenerateGraphExport(context.Background(), GraphExportOptions{
		TopoPath: topology, Username: currentUsername(t), Format: GraphFormatMermaid,
	})
	require.NoError(t, err)
	require.Contains(t, result.Content, "n1")
	require.Empty(t, fake.Calls(), "graphs render offline")
}

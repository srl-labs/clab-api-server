package kube

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	clabconst "github.com/srl-labs/containerlab/constants"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	clabtypes "github.com/srl-labs/containerlab/types"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/testsupport/fakec9s"
)

// fakeUsers is a user directory: superusers, group members and shared topology paths.
type fakeUsers struct {
	superusers map[string]bool
	groups     map[string][]string // group -> members
	shared     map[string]string   // topology path -> owning group
	workspaces map[string]string   // user -> workspace directory
}

func (u fakeUsers) IsSuperuser(name string) bool { return u.superusers[name] }

func (u fakeUsers) InGroup(name, group string) bool {
	for _, member := range u.groups[group] {
		if member == name {
			return true
		}
	}
	return false
}

func (u fakeUsers) SharedGroup(topoPath string) (string, bool) {
	group, ok := u.shared[topoPath]
	return group, ok
}

func (u fakeUsers) InWorkspace(name, topoPath string) bool {
	root, ok := u.workspaces[name]
	return ok && strings.HasPrefix(topoPath, root+"/")
}

func testScoper(t *testing.T, users fakeUsers) (*Scoper, *fake.Clientset) {
	t.Helper()
	provisioner, client, _ := testProvisioner(t, Settings{})
	return NewScoper(provisioner, users), client
}

func TestScoperFindsLabsByOwnershipSharingAndSuperuser(t *testing.T) {
	ctx := context.Background()
	users := fakeUsers{
		superusers: map[string]bool{"root": true},
		groups:     map[string][]string{"netops": {"alice", "carol"}},
		shared:     map[string]string{"/shared/team/team.clab.yml": "netops"},
	}
	scoper, _ := testScoper(t, users)

	alice, err := scoper.PrepareDeploy(ctx, "alice", "lab1", "/home/alice/.clab/lab1/lab1.clab.yml")
	require.NoError(t, err)
	require.Equal(t, "c9s-alice-lab1", alice.Namespace)
	require.Equal(t, "clab:alice", alice.Identity.User)
	require.Equal(t, []string{"clab:users"}, alice.Identity.Groups)
	_, err = scoper.PrepareDeploy(ctx, "bob", "lab1", "/home/bob/.clab/lab1/lab1.clab.yml")
	require.NoError(t, err, "lab names are unique per user")
	team, err := scoper.PrepareDeploy(ctx, "alice", "team", "/shared/team/team.clab.yml")
	require.NoError(t, err)
	require.Equal(t, "c9s-shared-team", team.Namespace)
	require.Equal(t, []string{"clab:users", "clab:shared-netops"}, team.Identity.Groups)

	_, err = scoper.PrepareDeploy(ctx, "bob", "team", "/shared/team/team.clab.yml")
	require.ErrorContains(t, err, "not in group", "only members deploy a shared lab")

	scope, err := scoper.ScopeForLab(ctx, "bob", "lab1")
	require.NoError(t, err)
	require.Equal(t, "c9s-bob-lab1", scope.Namespace, "own labs come first")

	_, err = scoper.ScopeForLab(ctx, "bob", "lab2")
	require.ErrorIs(t, err, clab.ErrLabNotFound)
	_, err = scoper.ScopeForLab(ctx, "bob", "team")
	require.ErrorIs(t, err, clab.ErrLabNotFound, "a shared lab of a foreign group stays hidden")

	scope, err = scoper.ScopeForLab(ctx, "carol", "team")
	require.NoError(t, err)
	require.Equal(t, "c9s-shared-team", scope.Namespace)
	require.Contains(t, scope.Identity.Groups, "clab:shared-netops")

	_, err = scoper.ScopeForLab(ctx, "carol", "lab1")
	require.ErrorIs(t, err, clab.ErrLabNotFound, "other users' labs stay hidden")

	_, err = scoper.ScopeForLab(ctx, "root", "lab1")
	require.ErrorIs(t, err, ErrAmbiguousLab, "a superuser must not guess between users")
	scope, err = scoper.ScopeForLab(ctx, "root", "team")
	require.NoError(t, err)
	require.Equal(t, "c9s-shared-team", scope.Namespace)
	require.Contains(t, scope.Identity.Groups, "clab:admins")
}

func TestScoperListsOwnAndSharedLabs(t *testing.T) {
	ctx := context.Background()
	users := fakeUsers{
		superusers: map[string]bool{"root": true},
		groups:     map[string][]string{"netops": {"carol"}},
		shared:     map[string]string{"/shared/team.clab.yml": "netops"},
	}
	scoper, _ := testScoper(t, users)
	for _, deploy := range [][3]string{
		{"alice", "lab1", "/a/lab1.clab.yml"}, {"alice", "lab2", "/a/lab2.clab.yml"},
		{"bob", "lab1", "/b/lab1.clab.yml"}, {"carol", "team", "/shared/team.clab.yml"},
	} {
		_, err := scoper.PrepareDeploy(ctx, deploy[0], deploy[1], deploy[2])
		require.NoError(t, err)
	}

	scopes, err := scoper.ListScopes(ctx, "alice")
	require.NoError(t, err)
	require.Equal(t, []string{"c9s-alice-lab1", "c9s-alice-lab2"}, scopeNamespaces(scopes))
	for _, scope := range scopes {
		require.Equal(t, "clab:alice", scope.Identity.User)
	}

	scopes, err = scoper.ListScopes(ctx, "carol")
	require.NoError(t, err)
	require.Equal(t, []string{"c9s-shared-team"}, scopeNamespaces(scopes))

	scopes, err = scoper.ListScopes(ctx, "root")
	require.NoError(t, err)
	require.Len(t, scopes, 1, "a superuser lists every namespace at once")
	require.Empty(t, scopes[0].Namespace)
	require.Contains(t, scopes[0].Identity.Groups, "clab:admins")
}

func scopeNamespaces(scopes []clab.LabScope) []string {
	names := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		names = append(names, scope.Namespace)
	}
	return names
}

// TestServiceOnC9sProvisionsActsAsTheUserAndReleases runs the service with the Kubernetes
// scoper and the fake lab runtime: deploy provisions the namespace and deploys into it as
// the user, listings only reach the user's namespaces, and destroy releases the namespace
// by the storage rules.
func TestServiceOnC9sProvisionsActsAsTheUserAndReleases(t *testing.T) {
	previous := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previous })
	config.AppConfig.ClabRuntime = config.RuntimeC9s
	config.AppConfig.ClabC9sExposeType = "None"
	config.AppConfig.ClabC9sPersistence = true
	runtime := fakec9s.Install(t)

	current, err := user.Current()
	require.NoError(t, err)
	me := current.Username
	scoper, client := testScoper(t, fakeUsers{superusers: map[string]bool{"root": true}})
	svc := clab.NewService()
	svc.SetLabScoper(scoper)
	ctx := context.Background()

	topology := filepath.Join(t.TempDir(), "demo.clab.yml")
	require.NoError(t, os.WriteFile(topology, []byte("name: demo\ntopology:\n  nodes:\n    n1: {kind: linux, image: alpine}\n"), 0o644))
	_, err = svc.Deploy(ctx, clab.DeployOptions{TopoPath: topology, LabName: "demo", Username: me})
	require.NoError(t, err)

	namespace := NamespaceName(DefaultNamespaceTemplate, me, "demo")
	_, err = client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	require.NoError(t, err, "the namespace is provisioned before the deploy")
	deploy := runtime.CallsOf("deploy")[0]
	require.Equal(t, namespace, deploy.Namespace)
	require.Equal(t, "clab:"+me, deploy.Identity.User)
	require.Equal(t, []string{"clab:users"}, deploy.Identity.Groups)

	containers, err := svc.ListContainers(ctx, clab.ListOptions{Username: me})
	require.NoError(t, err)
	require.Len(t, containers, 1)
	containers, err = svc.ListContainers(ctx, clab.ListOptions{Username: "mallory"})
	require.NoError(t, err)
	require.Empty(t, containers, "another user lists none of it")
	containers, err = svc.ListContainers(ctx, clab.ListOptions{Username: "mallory", LabName: "demo"})
	require.NoError(t, err)
	require.Empty(t, containers)
	containers, err = svc.ListContainers(ctx, clab.ListOptions{Username: "root"})
	require.NoError(t, err)
	require.Len(t, containers, 1, "a superuser lists every lab")
	list := runtime.CallsOf("list")
	require.Contains(t, list[len(list)-1].Identity.Groups, "clab:admins")

	// A plain destroy keeps the namespace while storage is left.
	_, err = client.CoreV1().PersistentVolumeClaims(namespace).Create(ctx,
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "demo-n1", Namespace: namespace}}, metav1.CreateOptions{})
	require.NoError(t, err)
	require.NoError(t, svc.Destroy(ctx, clab.DestroyOptions{LabName: "demo", Username: me}))
	_, err = client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	require.NoError(t, err)

	// The redeploy reuses it, and destroy with cleanup removes it.
	_, err = svc.Deploy(ctx, clab.DeployOptions{TopoPath: topology, LabName: "demo", Username: me})
	require.NoError(t, err)
	require.Equal(t, namespace, runtime.CallsOf("deploy")[1].Namespace)
	require.NoError(t, svc.Destroy(ctx, clab.DestroyOptions{LabName: "demo", Username: me, Cleanup: true}))
	_, err = client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	require.Error(t, err, "destroy with cleanup deletes the namespace")
	require.True(t, runtime.CallsOf("destroy")[1].Cleanup)
}

func TestFailedFirstDeployReleasesItsNamespace(t *testing.T) {
	previous := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previous })
	config.AppConfig.ClabRuntime = config.RuntimeC9s
	runtime := fakec9s.Install(t)
	current, err := user.Current()
	require.NoError(t, err)
	me := current.Username
	scoper, client := testScoper(t, fakeUsers{})
	svc := clab.NewService()
	svc.SetLabScoper(scoper)
	ctx := context.Background()
	topology := filepath.Join(t.TempDir(), "broken.clab.yml")
	require.NoError(t, os.WriteFile(topology, []byte("name: broken\ntopology:\n  nodes:\n    n1: {kind: linux, image: alpine}\n"), 0o644))
	namespace := NamespaceName(DefaultNamespaceTemplate, me, "broken")

	runtime.DeployErr = errors.New("image pull denied")
	_, err = svc.Deploy(ctx, clab.DeployOptions{TopoPath: topology, LabName: "broken", Username: me})
	require.ErrorContains(t, err, "image pull denied")
	_, err = client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	require.Error(t, err, "a failed first deploy leaves no empty namespace behind")

	// A failed update of a running lab keeps everything.
	runtime.DeployErr = nil
	_, err = svc.Deploy(ctx, clab.DeployOptions{TopoPath: topology, LabName: "broken", Username: me})
	require.NoError(t, err)
	runtime.DeployErr = errors.New("update rejected")
	_, err = svc.Deploy(ctx, clab.DeployOptions{TopoPath: topology, LabName: "broken", Username: me})
	require.Error(t, err)
	_, err = client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	require.NoError(t, err, "the running lab keeps its namespace")
}

// labNode is a listed lab node as containerlab reports it from a lab runtime.
func labNode(namespace, lab, owner, topoFile string) clabruntime.GenericContainer {
	return clabruntime.GenericContainer{
		Labels: map[string]string{
			clabconst.Containerlab: lab,
			clabconst.Owner:        owner,
			clabconst.TopoFile:     topoFile,
		},
		Workload: &clabtypes.LabRuntimeWorkload{Namespace: namespace},
	}
}

func TestScoperVerifiesWhatUsersCanEditOnTheirTopology(t *testing.T) {
	ctx := context.Background()
	users := fakeUsers{
		groups:     map[string][]string{"netops": {"carol"}, "other": {"bob"}},
		shared:     map[string]string{"/shared/team/team.clab.yml": "netops", "/shared/x/x.clab.yml": "other"},
		workspaces: map[string]string{"alice": "/home/alice/.clab", "bob": "/home/bob/.clab", "carol": "/home/carol/.clab"},
	}
	scoper, _ := testScoper(t, users)
	for _, deploy := range [][3]string{
		{"alice", "lab1", "/home/alice/.clab/lab1/lab1.clab.yml"},
		{"bob", "lab1", "/home/bob/.clab/lab1/lab1.clab.yml"},
		{"carol", "team", "/shared/team/team.clab.yml"},
	} {
		_, err := scoper.PrepareDeploy(ctx, deploy[0], deploy[1], deploy[2])
		require.NoError(t, err)
	}

	containers := []clabruntime.GenericContainer{
		// 0: as deployed.
		labNode("c9s-alice-lab1", "lab1", "alice", "/home/alice/.clab/lab1/lab1.clab.yml"),
		// 1: bob claims alice's lab directory and her ownership on his own Topology.
		labNode("c9s-bob-lab1", "lab1", "alice", "/home/alice/.clab/lab1/lab1.clab.yml"),
		// 2: bob points his own lab at a shared lab's directory.
		labNode("c9s-bob-lab1", "lab1", "bob", "/shared/team/team.clab.yml"),
		// 3: the shared lab as deployed, listed as one of its members.
		labNode("c9s-shared-team", "team", "carol", "/shared/team/team.clab.yml"),
		// 4: the shared lab pointed at another group's shared directory.
		labNode("c9s-shared-team", "team", "carol", "/shared/x/x.clab.yml"),
		// 5: a namespace the server did not provision.
		labNode("rogue", "lab9", "alice", "/home/alice/.clab/lab1/lab1.clab.yml"),
		// 6: a relative path, and 7: a lab without a recorded file.
		labNode("c9s-bob-lab1", "lab1", "bob", "lab1.clab.yml"),
		labNode("c9s-bob-lab1", "lab1", "bob", "k8s://c9s-bob-lab1/topologies/lab1"),
		// 8: a record without a workload is left alone.
		{Labels: map[string]string{clabconst.Owner: "x", clabconst.TopoFile: "/etc/passwd"}},
	}
	require.NoError(t, scoper.VerifyLabRecords(ctx, containers))

	type record struct{ owner, file string }
	got := make([]record, 0, len(containers))
	for _, container := range containers {
		got = append(got, record{container.Labels[clabconst.Owner], container.Labels[clabconst.TopoFile]})
	}
	require.Equal(t, []record{
		{"alice", "/home/alice/.clab/lab1/lab1.clab.yml"},
		{"bob", "k8s://c9s-bob-lab1/topologies/lab1"},
		{"bob", "k8s://c9s-bob-lab1/topologies/lab1"},
		{"carol", "/shared/team/team.clab.yml"},
		{"carol", "k8s://c9s-shared-team/topologies/team"},
		{"alice", "k8s://rogue/topologies/lab9"},
		{"bob", "k8s://c9s-bob-lab1/topologies/lab1"},
		{"bob", "k8s://c9s-bob-lab1/topologies/lab1"},
		{"x", "/etc/passwd"},
	}, got)
}

// TestServiceListsVerifiedLabRecords checks that the service lets the scoper correct what a
// user wrote on the Topology before any handler sees it.
func TestServiceListsVerifiedLabRecords(t *testing.T) {
	previous := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previous })
	config.AppConfig.ClabRuntime = config.RuntimeC9s
	runtime := fakec9s.Install(t)
	current, err := user.Current()
	require.NoError(t, err)
	me := current.Username
	workspace := t.TempDir()
	scoper, _ := testScoper(t, fakeUsers{
		superusers: map[string]bool{"root": true},
		workspaces: map[string]string{me: workspace},
	})
	svc := clab.NewService()
	svc.SetLabScoper(scoper)
	ctx := context.Background()

	topology := filepath.Join(workspace, "demo", "demo.clab.yml")
	require.NoError(t, os.MkdirAll(filepath.Dir(topology), 0o755))
	require.NoError(t, os.WriteFile(topology, []byte("name: demo\ntopology:\n  nodes:\n    n1: {kind: linux, image: alpine}\n"), 0o644))
	_, err = svc.Deploy(ctx, clab.DeployOptions{TopoPath: topology, LabName: "demo", Username: me})
	require.NoError(t, err)
	namespace := NamespaceName(DefaultNamespaceTemplate, me, "demo")

	containers, err := svc.ListContainers(ctx, clab.ListOptions{Username: me, LabName: "demo"})
	require.NoError(t, err)
	require.Len(t, containers, 1)
	require.Equal(t, topology, containers[0].Labels[clabconst.TopoFile], "the file the lab was deployed from")
	require.Equal(t, me, containers[0].Labels[clabconst.Owner])

	// The user edits the Topology's owner label and topology file annotation.
	state := runtime.Lab(namespace, "demo")
	require.NotNil(t, state)
	state.Owner = "mallory"
	state.TopologyPath = "/etc/shadow"
	for _, opts := range []clab.ListOptions{{Username: me, LabName: "demo"}, {Username: me}, {Username: "root"}} {
		containers, err = svc.ListContainers(ctx, opts)
		require.NoError(t, err)
		require.Len(t, containers, 1)
		require.Equal(t, "k8s://"+namespace+"/topologies/demo", containers[0].Labels[clabconst.TopoFile], "listed as %+v", opts)
		require.Equal(t, me, containers[0].Labels[clabconst.Owner], "listed as %+v", opts)
	}
}

package kube

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"testing"

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

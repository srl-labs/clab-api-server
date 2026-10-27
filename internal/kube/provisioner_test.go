package kube

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNamespaceNames(t *testing.T) {
	require.Equal(t, "c9s-alice-lab1", NamespaceName(DefaultNamespaceTemplate, "alice", "lab1"))
	require.Equal(t, "c9s-j-doe-my-lab", NamespaceName(DefaultNamespaceTemplate, "J.Doe", "My_Lab"))
	require.Equal(t, "c9s-shared-lab1", SharedNamespaceName("lab1"))

	long := NamespaceName(DefaultNamespaceTemplate, strings.Repeat("u", 40), strings.Repeat("l", 40))
	require.Empty(t, validation.IsDNS1123Label(long), long)
	require.Len(t, long, validation.DNS1123LabelMaxLength)
	other := NamespaceName(DefaultNamespaceTemplate, strings.Repeat("u", 40), strings.Repeat("l", 39)+"m")
	require.NotEqual(t, long, other, "long names stay unique")

	// Names stay readable, so two labs can render alike ("a-b"/"x" and "a"/"b-x");
	// EnsureLabNamespace refuses the second one instead of sharing the namespace.
	require.Equal(t, NamespaceName(DefaultNamespaceTemplate, "a-b", "x"), NamespaceName(DefaultNamespaceTemplate, "a", "b-x"))

	numeric := NamespaceName("{user}-{lab}", "1000", "lab")
	require.Empty(t, validation.IsDNS1123Label(numeric), numeric)
	require.True(t, strings.HasPrefix(numeric, "n-"), numeric)
}

func TestLabelValues(t *testing.T) {
	require.Equal(t, "alice", LabelValue("alice"))
	value := LabelValue("machine$")
	require.Empty(t, validation.IsValidLabelValue(value), value)
	require.NotEqual(t, LabelValue("machine$"), LabelValue("machine%"))
}

func TestIdentityMapping(t *testing.T) {
	identity := Identity("clab:", "alice", false)
	require.Equal(t, clablabruntime.Identity{User: "clab:alice", Groups: []string{"clab:users"}}, identity)

	identity = Identity("clab:", "root", true, "netops", "")
	require.Equal(t, "clab:root", identity.User)
	require.Equal(t, []string{"clab:users", "clab:admins", "clab:shared-netops"}, identity.Groups)

	require.Equal(t, "lab:bob", Identity("lab:", "bob", false).User)
}

func TestParseSecretRef(t *testing.T) {
	ref, err := ParseSecretRef("regcred", "clab-api-server")
	require.NoError(t, err)
	require.Equal(t, &SecretRef{Namespace: "clab-api-server", Name: "regcred"}, ref)
	ref, err = ParseSecretRef("infra/regcred", "x")
	require.NoError(t, err)
	require.Equal(t, &SecretRef{Namespace: "infra", Name: "regcred"}, ref)
	ref, err = ParseSecretRef("", "x")
	require.NoError(t, err)
	require.Nil(t, ref)
	_, err = ParseSecretRef("a/b/c", "x")
	require.Error(t, err)
}

func TestLoadQuota(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "quota.yaml")
	require.NoError(t, os.WriteFile(path, []byte("apiVersion: v1\nkind: ResourceQuota\nspec:\n  hard:\n    pods: \"10\"\n    requests.cpu: \"8\"\n"), 0o600))
	quota, err := LoadQuota(path)
	require.NoError(t, err)
	require.Equal(t, DefaultQuotaName, quota.Name)
	require.True(t, quota.Spec.Hard.Pods().Equal(resource.MustParse("10")))

	require.NoError(t, os.WriteFile(path, []byte("kind: LimitRange\nspec:\n  hard:\n    pods: \"1\"\n"), 0o600))
	_, err = LoadQuota(path)
	require.Error(t, err)
	require.NoError(t, os.WriteFile(path, []byte("kind: ResourceQuota\nspec: {}\n"), 0o600))
	_, err = LoadQuota(path)
	require.ErrorContains(t, err, "no spec.hard")
	require.NoError(t, os.WriteFile(path, []byte("kind: ResourceQuota\nspec:\n  hard: {pods: \"1\"}\n  typo: 1\n"), 0o600))
	_, err = LoadQuota(path)
	require.Error(t, err, "unknown fields are refused")
	quota, err = LoadQuota("")
	require.NoError(t, err)
	require.Nil(t, quota)
}

// testProvisioner returns a provisioner on a fake clientset; impersonated reads use the same
// fake and are recorded.
func testProvisioner(t *testing.T, settings Settings, objects ...metav1.Object) (*Provisioner, *fake.Clientset, *[]clablabruntime.Identity) {
	t.Helper()
	if settings.UserPrefix == "" {
		settings.UserPrefix = DefaultUserPrefix
	}
	if settings.NamespaceTemplate == "" {
		settings.NamespaceTemplate = DefaultNamespaceTemplate
	}
	client := fake.NewClientset()
	for _, object := range objects {
		switch typed := object.(type) {
		case *corev1.Secret:
			_, err := client.CoreV1().Secrets(typed.Namespace).Create(context.Background(), typed, metav1.CreateOptions{})
			require.NoError(t, err)
		case *corev1.Namespace:
			_, err := client.CoreV1().Namespaces().Create(context.Background(), typed, metav1.CreateOptions{})
			require.NoError(t, err)
		}
	}
	var impersonated []clablabruntime.Identity
	provisioner := NewProvisioner(client, nil, settings)
	provisioner.asUser = func(identity clablabruntime.Identity) (kubernetes.Interface, error) {
		impersonated = append(impersonated, identity)
		return client, nil
	}
	return provisioner, client, &impersonated
}

func TestEnsureLabNamespaceProvisionsEverything(t *testing.T) {
	ctx := context.Background()
	quota := &corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: "lab-quota"},
		Spec: corev1.ResourceQuotaSpec{Hard: corev1.ResourceList{corev1.ResourcePods: resource.MustParse("10")}}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "regcred", Namespace: "clab-api-server"},
		Type: corev1.SecretTypeDockerConfigJson, Data: map[string][]byte{".dockerconfigjson": []byte("{}")}}
	provisioner, client, _ := testProvisioner(t, Settings{Quota: quota, PullSecret: &SecretRef{Namespace: "clab-api-server", Name: "regcred"}}, secret)

	namespace, err := provisioner.EnsureLabNamespace(ctx, LabNamespace{Owner: "alice", Lab: "lab1"})
	require.NoError(t, err)
	require.Equal(t, "c9s-alice-lab1", namespace.Name)

	object, err := client.CoreV1().Namespaces().Get(ctx, "c9s-alice-lab1", metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"containerlab.dev/runtime":           "clabernetes",
		"app.kubernetes.io/managed-by":       "clab-api-server",
		"clab-owner":                         "alice",
		"clab-lab":                           "lab1",
		"pod-security.kubernetes.io/enforce": "privileged",
	}, object.Labels)

	editor, err := client.RbacV1().RoleBindings("c9s-alice-lab1").Get(ctx, "clab-lab-editor", metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "clabernetes-lab-editor"}, editor.RoleRef)
	require.Equal(t, []rbacv1.Subject{{Kind: "User", APIGroup: "rbac.authorization.k8s.io", Name: "clab:alice"}}, editor.Subjects)

	access, err := client.RbacV1().RoleBindings("c9s-alice-lab1").Get(ctx, "clab-lab-access", metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "clab-lab-access"}, access.RoleRef)
	require.Equal(t, editor.Subjects, access.Subjects)

	_, err = client.CoreV1().ResourceQuotas("c9s-alice-lab1").Get(ctx, "lab-quota", metav1.GetOptions{})
	require.NoError(t, err)
	copied, err := client.CoreV1().Secrets("c9s-alice-lab1").Get(ctx, "regcred", metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, corev1.SecretTypeDockerConfigJson, copied.Type)
	require.Equal(t, secret.Data, copied.Data)

	// A redeploy finds everything in place.
	again, err := provisioner.EnsureLabNamespace(ctx, LabNamespace{Owner: "alice", Lab: "lab1"})
	require.NoError(t, err)
	require.Equal(t, namespace, again)
}

func TestEnsureLabNamespaceRefusesForeignNamespaces(t *testing.T) {
	ctx := context.Background()
	foreign := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "c9s-alice-lab1"}}
	provisioner, _, _ := testProvisioner(t, Settings{}, foreign)
	_, err := provisioner.EnsureLabNamespace(ctx, LabNamespace{Owner: "alice", Lab: "lab1"})
	require.ErrorIs(t, err, ErrNotProvisioned)

	provisioner, _, _ = testProvisioner(t, Settings{})
	_, err = provisioner.EnsureLabNamespace(ctx, LabNamespace{Owner: "a-b", Lab: "x"})
	require.NoError(t, err)
	_, err = provisioner.EnsureLabNamespace(ctx, LabNamespace{Owner: "a", Lab: "b-x"})
	require.ErrorIs(t, err, ErrNamespaceTaken, "a lab that renders to another lab's namespace is refused")

	taken := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "c9s-bob-lab1", Labels: map[string]string{
		LabelRuntime: RuntimeValue, LabelManagedBy: ManagedByValue, LabelOwner: "mallory", LabelLab: "lab1"}}}
	provisioner, _, _ = testProvisioner(t, Settings{}, taken)
	_, err = provisioner.EnsureLabNamespace(ctx, LabNamespace{Owner: "bob", Lab: "lab1"})
	require.ErrorIs(t, err, ErrNamespaceTaken)
}

func TestEnsureSharedLabNamespaceBindsTheGroup(t *testing.T) {
	ctx := context.Background()
	provisioner, client, _ := testProvisioner(t, Settings{})
	namespace, err := provisioner.EnsureLabNamespace(ctx, LabNamespace{Owner: "alice", Lab: "team", SharedGroup: "netops"})
	require.NoError(t, err)
	require.Equal(t, "c9s-shared-team", namespace.Name)
	editor, err := client.RbacV1().RoleBindings("c9s-shared-team").Get(ctx, "clab-lab-editor", metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, []rbacv1.Subject{{Kind: "Group", APIGroup: "rbac.authorization.k8s.io", Name: "clab:shared-netops"}}, editor.Subjects)

	// Another member redeploys the same shared lab.
	again, err := provisioner.EnsureLabNamespace(ctx, LabNamespace{Owner: "bob", Lab: "team", SharedGroup: "netops"})
	require.NoError(t, err)
	require.Equal(t, "alice", again.Owner)

	shared, err := provisioner.SharedWith(ctx, "netops")
	require.NoError(t, err)
	require.Len(t, shared, 1)
}

func TestReleaseLabNamespace(t *testing.T) {
	ctx := context.Background()
	alice := Identity(DefaultUserPrefix, "alice", false)
	provisioner, client, impersonated := testProvisioner(t, Settings{})
	_, err := provisioner.EnsureLabNamespace(ctx, LabNamespace{Owner: "alice", Lab: "lab1"})
	require.NoError(t, err)

	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "lab1-n1", Namespace: "c9s-alice-lab1"}}
	_, err = client.CoreV1().PersistentVolumeClaims("c9s-alice-lab1").Create(ctx, claim, metav1.CreateOptions{})
	require.NoError(t, err)

	released, err := provisioner.ReleaseLabNamespace(ctx, "c9s-alice-lab1", alice, false)
	require.NoError(t, err)
	require.False(t, released, "a plain destroy keeps the namespace with the retained storage")
	require.Equal(t, []clablabruntime.Identity{alice}, *impersonated, "storage is read as the user")
	_, err = client.CoreV1().Namespaces().Get(ctx, "c9s-alice-lab1", metav1.GetOptions{})
	require.NoError(t, err)

	require.NoError(t, client.CoreV1().PersistentVolumeClaims("c9s-alice-lab1").Delete(ctx, "lab1-n1", metav1.DeleteOptions{}))
	released, err = provisioner.ReleaseLabNamespace(ctx, "c9s-alice-lab1", alice, false)
	require.NoError(t, err)
	require.True(t, released, "without storage the namespace goes")

	_, err = provisioner.EnsureLabNamespace(ctx, LabNamespace{Owner: "alice", Lab: "lab2"})
	require.NoError(t, err)
	_, err = client.CoreV1().PersistentVolumeClaims("c9s-alice-lab2").Create(ctx,
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: "c9s-alice-lab2"}}, metav1.CreateOptions{})
	require.NoError(t, err)
	released, err = provisioner.ReleaseLabNamespace(ctx, "c9s-alice-lab2", alice, true)
	require.NoError(t, err)
	require.True(t, released, "cleanup deletes the namespace")

	_, err = client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}}, metav1.CreateOptions{})
	require.NoError(t, err)
	released, err = provisioner.ReleaseLabNamespace(ctx, "kube-system", alice, true)
	require.NoError(t, err)
	require.False(t, released, "namespaces the server did not create are never deleted")

	released, err = provisioner.ReleaseLabNamespace(ctx, "missing", alice, true)
	require.NoError(t, err)
	require.False(t, released)
}

func TestReleaseLabNamespaceReportsForbiddenStorageReads(t *testing.T) {
	ctx := context.Background()
	provisioner, _, _ := testProvisioner(t, Settings{})
	_, err := provisioner.EnsureLabNamespace(ctx, LabNamespace{Owner: "alice", Lab: "lab1"})
	require.NoError(t, err)
	provisioner.asUser = func(clablabruntime.Identity) (kubernetes.Interface, error) {
		return nil, errors.New("impersonation refused")
	}
	_, err = provisioner.ReleaseLabNamespace(ctx, "c9s-alice-lab1", Identity("clab:", "alice", false), false)
	require.ErrorContains(t, err, "impersonation refused")
}

func TestListingByOwnerAndLab(t *testing.T) {
	ctx := context.Background()
	provisioner, _, _ := testProvisioner(t, Settings{})
	for _, target := range []LabNamespace{
		{Owner: "alice", Lab: "lab1"}, {Owner: "alice", Lab: "lab2"},
		{Owner: "bob", Lab: "lab1"}, {Owner: "alice", Lab: "team", SharedGroup: "netops"},
	} {
		_, err := provisioner.EnsureLabNamespace(ctx, target)
		require.NoError(t, err)
	}
	own, err := provisioner.OwnedBy(ctx, "alice")
	require.NoError(t, err)
	require.Equal(t, []string{"c9s-alice-lab1", "c9s-alice-lab2"}, namespaceNames(own), "shared labs are not the deployer's own")

	labs, err := provisioner.FindLab(ctx, "lab1")
	require.NoError(t, err)
	require.Equal(t, []string{"c9s-alice-lab1", "c9s-bob-lab1"}, namespaceNames(labs))
}

func namespaceNames(namespaces []LabNamespace) []string {
	names := make([]string, 0, len(namespaces))
	for _, namespace := range namespaces {
		names = append(names, namespace.Name)
	}
	return names
}

func TestCheckRoles(t *testing.T) {
	ctx := context.Background()
	client := fake.NewClientset()
	require.ErrorContains(t, CheckRoles(ctx, client), "clabernetes-lab-editor")
	_, err := client.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: EditorRole}}, metav1.CreateOptions{})
	require.NoError(t, err)
	require.ErrorContains(t, CheckRoles(ctx, client), "provisioner-rbac.yaml")
	_, err = client.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: AccessRole}}, metav1.CreateOptions{})
	require.NoError(t, err)
	require.NoError(t, CheckRoles(ctx, client))
}

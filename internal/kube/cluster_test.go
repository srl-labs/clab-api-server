package kube

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func nodeCRD(withRunState bool) *unstructured.Unstructured {
	specProperties := map[string]any{"definition": map[string]any{"type": "object"}}
	if withRunState {
		specProperties["runState"] = map[string]any{"type": "string"}
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1",
		"kind":       "CustomResourceDefinition",
		"metadata":   map[string]any{"name": NodeCRDName},
		"spec": map[string]any{
			"versions": []any{map[string]any{
				"name": "v1alpha1",
				"schema": map[string]any{"openAPIV3Schema": map[string]any{
					"properties": map[string]any{"spec": map[string]any{"properties": specProperties}},
				}},
			}},
		},
	}}
}

func dynamicClient(objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{crdGVR: "CustomResourceDefinitionList"}, objects...)
}

func TestCheckClabernetes(t *testing.T) {
	ctx := context.Background()
	require.NoError(t, CheckClabernetes(ctx, dynamicClient(nodeCRD(true))))

	err := CheckClabernetes(ctx, dynamicClient(nodeCRD(false)))
	require.ErrorContains(t, err, "too old")
	require.ErrorContains(t, err, "runState")

	err = CheckClabernetes(ctx, dynamicClient())
	require.ErrorContains(t, err, "not installed")
}

// allowOnly answers SelfSubjectAccessReviews: allowed when allow returns true.
func allowOnly(allow func(*authorizationv1.ResourceAttributes) bool) *fake.Clientset {
	client := fake.NewClientset()
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		review.Status.Allowed = allow(review.Spec.ResourceAttributes)
		return true, review, nil
	})
	return client
}

func TestCheckPermissionsListsEveryDenial(t *testing.T) {
	ctx := context.Background()
	permissions := ServerIdentityPermissions("")
	require.NoError(t, CheckPermissions(ctx, allowOnly(func(*authorizationv1.ResourceAttributes) bool { return true }), permissions))

	err := CheckPermissions(ctx, allowOnly(func(attrs *authorizationv1.ResourceAttributes) bool {
		return attrs.Subresource != "exec" && attrs.Resource != "namespaces"
	}), permissions)
	require.Error(t, err)
	require.Contains(t, err.Error(), "create pods/exec cluster-wide (exec and terminals)")
	require.Contains(t, err.Error(), "create namespaces cluster-wide")
	require.Contains(t, err.Error(), "delete namespaces cluster-wide")
	require.NotContains(t, err.Error(), "portforward")
}

func TestServerIdentityPermissionsInFixedNamespace(t *testing.T) {
	for _, permission := range ServerIdentityPermissions("labs") {
		require.NotEqual(t, "namespaces", permission.Resource, "a fixed namespace needs no namespace rights")
		if permission.Resource != "customresourcedefinitions" {
			require.Equal(t, "labs", permission.Namespace, permission.String())
		}
	}
}

func TestCheckStartup(t *testing.T) {
	ctx := context.Background()
	allowAll := allowOnly(func(*authorizationv1.ResourceAttributes) bool { return true })
	require.NoError(t, CheckStartup(ctx, &Clients{Kube: allowAll, Dynamic: dynamicClient(nodeCRD(true))}, ServerIdentityPermissions("")))

	err := CheckStartup(ctx, &Clients{Kube: allowAll, Dynamic: dynamicClient(nodeCRD(false))}, ServerIdentityPermissions(""))
	require.ErrorIs(t, err, ErrStartup)

	denyAll := allowOnly(func(*authorizationv1.ResourceAttributes) bool { return false })
	err = CheckStartup(ctx, &Clients{Kube: denyAll, Dynamic: dynamicClient(nodeCRD(true))}, ServerIdentityPermissions(""))
	require.ErrorIs(t, err, ErrStartup)
	require.ErrorContains(t, err, "lacks permissions")
}

func TestMetricsProbeCachesTheAnswer(t *testing.T) {
	client := fake.NewClientset()
	discovery := client.Discovery().(*fakediscovery.FakeDiscovery)
	now := time.Unix(1000, 0)
	probe := NewMetricsProbe(discovery, time.Minute)
	probe.now = func() time.Time { return now }

	require.False(t, probe.Available())

	discovery.Resources = []*metav1.APIResourceList{{
		GroupVersion: "metrics.k8s.io/v1beta1",
		APIResources: []metav1.APIResource{{Name: "pods"}, {Name: "nodes"}},
	}}
	require.False(t, probe.Available(), "the answer is cached")
	now = now.Add(2 * time.Minute)
	require.True(t, probe.Available())
}

func TestRestConfigHonoursKubeconfigAndContext(t *testing.T) {
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(kubeconfig, []byte(strings.TrimSpace(`
apiVersion: v1
kind: Config
clusters:
- name: one
  cluster: {server: "https://one.example:6443"}
- name: two
  cluster: {server: "https://two.example:6443"}
users:
- name: u
  user: {token: t}
contexts:
- name: one
  context: {cluster: one, user: u}
- name: two
  context: {cluster: two, user: u}
current-context: one
`)), 0o600))

	config, err := RestConfig(ConnectionSettings{Kubeconfig: kubeconfig})
	require.NoError(t, err)
	require.Equal(t, "https://one.example:6443", config.Host)

	config, err = RestConfig(ConnectionSettings{Kubeconfig: kubeconfig, Context: "two"})
	require.NoError(t, err)
	require.Equal(t, "https://two.example:6443", config.Host)

	_, err = RestConfig(ConnectionSettings{Kubeconfig: kubeconfig, Context: "missing"})
	require.Error(t, err)
}

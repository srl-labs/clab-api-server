// Package kube holds the server's own Kubernetes calls for CLAB_RUNTIME=c9s: loading the
// cluster connection, the startup checks and (later) namespace provisioning. Lab
// operations themselves go through the containerlab library.
package kube

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// MinClabernetesFeature names what the server needs from clabernetes: the node run state
// (Node.spec.runState) that node start and stop rely on.
const MinClabernetesFeature = "clabernetes with node run state (Node.spec.runState, clabernetes 0.11 or later)"

// ConnectionSettings select the cluster, like containerlab's CLAB_KUBECONFIG and
// CLAB_KUBE_CONTEXT. Without a kubeconfig the default loading rules apply: KUBECONFIG,
// ~/.kube/config, and in a Pod the in-cluster ServiceAccount.
type ConnectionSettings struct {
	Kubeconfig string
	Context    string
}

// RestConfig loads the server's own cluster connection.
func RestConfig(settings ConnectionSettings) (*rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if settings.Kubeconfig != "" {
		rules.ExplicitPath = settings.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if settings.Context != "" {
		overrides.CurrentContext = settings.Context
	}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load the Kubernetes connection (CLAB_KUBECONFIG, CLAB_KUBE_CONTEXT or the in-cluster ServiceAccount): %w", err)
	}
	return config, nil
}

// Clients are the server's own Kubernetes clients.
type Clients struct {
	Kube      kubernetes.Interface
	Dynamic   dynamic.Interface
	Discovery discovery.DiscoveryInterface
	// Config is the rest config the clients were built from; nil with injected clients.
	Config *rest.Config
}

// NewClients builds the server's clients from a rest config.
func NewClients(config *rest.Config) (*Clients, error) {
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}
	dyn, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes dynamic client: %w", err)
	}
	return &Clients{Kube: kube, Dynamic: dyn, Discovery: kube.Discovery(), Config: config}, nil
}

var crdGVR = schema.GroupVersionResource{
	Group:    "apiextensions.k8s.io",
	Version:  "v1",
	Resource: "customresourcedefinitions",
}

// NodeCRDName is the clabernetes Node CRD.
const NodeCRDName = "nodes.c9s.run"

// CheckClabernetes verifies that clabernetes is installed and supports node run state:
// the nodes.c9s.run CRD has spec.runState in its v1alpha1 schema.
func CheckClabernetes(ctx context.Context, dyn dynamic.Interface) error {
	crd, err := dyn.Resource(crdGVR).Get(ctx, NodeCRDName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("clabernetes is not installed: CRD %s not found; install %s", NodeCRDName, MinClabernetesFeature)
	}
	if err != nil {
		return fmt.Errorf("failed to read CRD %s: %w", NodeCRDName, err)
	}
	if !nodeCRDHasRunState(crd) {
		return fmt.Errorf("clabernetes is too old: CRD %s has no spec.runState; install %s", NodeCRDName, MinClabernetesFeature)
	}
	return nil
}

func nodeCRDHasRunState(crd *unstructured.Unstructured) bool {
	versions, _, _ := unstructured.NestedSlice(crd.Object, "spec", "versions")
	for _, raw := range versions {
		version, ok := raw.(map[string]any)
		if !ok || version["name"] != "v1alpha1" {
			continue
		}
		_, found, _ := unstructured.NestedMap(version,
			"schema", "openAPIV3Schema", "properties", "spec", "properties", "runState")
		return found
	}
	return false
}

// Permission is one access the server needs, checked with a SelfSubjectAccessReview.
type Permission struct {
	Verb        string
	Group       string
	Resource    string
	Subresource string
	Name        string
	// Namespace limits the check to a namespace; empty checks cluster-wide access.
	Namespace string
	// Why explains what the permission is for, in the startup error.
	Why string
}

func (p Permission) String() string {
	resource := p.Resource
	if p.Subresource != "" {
		resource += "/" + p.Subresource
	}
	if p.Group != "" {
		resource += "." + p.Group
	}
	target := resource
	if p.Name != "" {
		target += " " + p.Name
	}
	scope := "cluster-wide"
	if p.Namespace != "" {
		scope = "in namespace " + p.Namespace
	}
	return fmt.Sprintf("%s %s %s", p.Verb, target, scope)
}

// CheckPermissions runs a SelfSubjectAccessReview for every permission and reports all
// that are denied in one error.
func CheckPermissions(ctx context.Context, kube kubernetes.Interface, permissions []Permission) error {
	var denied []string
	for _, permission := range permissions {
		review := &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:        permission.Verb,
					Group:       permission.Group,
					Resource:    permission.Resource,
					Subresource: permission.Subresource,
					Name:        permission.Name,
					Namespace:   permission.Namespace,
				},
			},
		}
		result, err := kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to check permission %q: %w", permission, err)
		}
		if !result.Status.Allowed {
			line := permission.String()
			if permission.Why != "" {
				line += " (" + permission.Why + ")"
			}
			denied = append(denied, line)
		}
	}
	if len(denied) != 0 {
		return fmt.Errorf("the server's Kubernetes identity lacks permissions:\n  - %s", strings.Join(denied, "\n  - "))
	}
	return nil
}

// metricsGroupVersion is the resource metrics API node stats come from.
const metricsGroupVersion = "metrics.k8s.io/v1beta1"

// MetricsProbe reports whether the cluster serves the resource metrics API, caching the
// answer for a while so /health stays cheap.
type MetricsProbe struct {
	discovery discovery.DiscoveryInterface
	ttl       time.Duration
	now       func() time.Time

	mu        sync.Mutex
	checkedAt time.Time
	available bool
}

// NewMetricsProbe returns a probe that asks discovery at most once per ttl.
func NewMetricsProbe(d discovery.DiscoveryInterface, ttl time.Duration) *MetricsProbe {
	return &MetricsProbe{discovery: d, ttl: ttl, now: time.Now}
}

// Available reports whether metrics.k8s.io pods are served.
func (p *MetricsProbe) Available() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.checkedAt.IsZero() && p.now().Sub(p.checkedAt) < p.ttl {
		return p.available
	}
	p.available = metricsServed(p.discovery)
	p.checkedAt = p.now()
	return p.available
}

func metricsServed(d discovery.DiscoveryInterface) bool {
	resources, err := d.ServerResourcesForGroupVersion(metricsGroupVersion)
	if err != nil || resources == nil {
		return false
	}
	for _, resource := range resources.APIResources {
		if resource.Name == "pods" {
			return true
		}
	}
	return false
}

// ErrStartup wraps every reason the server refuses to start with CLAB_RUNTIME=c9s.
var ErrStartup = errors.New("c9s startup check failed")

// ServerIdentityPermissions are the permissions the server needs when it runs every lab
// call with its own identity. namespace is CLAB_KUBE_NAMESPACE (fixed namespace mode) or
// empty when every lab gets its own namespace, which containerlab then creates.
func ServerIdentityPermissions(namespace string) []Permission {
	permissions := []Permission{
		{Verb: "get", Group: "apiextensions.k8s.io", Resource: "customresourcedefinitions", Name: NodeCRDName, Why: "clabernetes version check"},
		{Verb: "create", Group: "c9s.run", Resource: "topologies", Namespace: namespace, Why: "deploy labs"},
		{Verb: "patch", Group: "c9s.run", Resource: "nodes", Namespace: namespace, Why: "start and stop nodes"},
		{Verb: "create", Resource: "pods", Subresource: "exec", Namespace: namespace, Why: "exec and terminals"},
		{Verb: "create", Resource: "pods", Subresource: "portforward", Namespace: namespace, Why: "SSH and browser ports"},
		{Verb: "get", Resource: "pods", Subresource: "log", Namespace: namespace, Why: "node logs"},
	}
	if namespace == "" {
		permissions = append(permissions,
			Permission{Verb: "create", Resource: "namespaces", Why: "one namespace per lab"},
			Permission{Verb: "delete", Resource: "namespaces", Why: "destroy --cleanup"})
	}
	return permissions
}

// CheckStartup runs the startup checks: every permission, then clabernetes support.
func CheckStartup(ctx context.Context, clients *Clients, permissions []Permission) error {
	if err := CheckPermissions(ctx, clients.Kube, permissions); err != nil {
		return fmt.Errorf("%w: %w", ErrStartup, err)
	}
	if err := CheckClabernetes(ctx, clients.Dynamic); err != nil {
		return fmt.Errorf("%w: %w", ErrStartup, err)
	}
	return nil
}

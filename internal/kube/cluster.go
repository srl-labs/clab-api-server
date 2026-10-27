// Package kube holds the server's own Kubernetes calls for CLAB_RUNTIME=c9s: loading the
// cluster connection and the startup checks. Lab
// operations themselves go through the containerlab library.
package kube

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	clabcore "github.com/srl-labs/containerlab/core"
	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	clabruntime "github.com/srl-labs/containerlab/runtime"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

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

// DefaultNamespace is the namespace of the server's own connection: the kubeconfig
// context's namespace, the ServiceAccount's namespace in a Pod, or "default".
func DefaultNamespace(settings ConnectionSettings) string {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if settings.Kubeconfig != "" {
		rules.ExplicitPath = settings.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if settings.Context != "" {
		overrides.CurrentContext = settings.Context
	}
	namespace, _, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).Namespace()
	if err != nil || namespace == "" {
		return "default"
	}
	return namespace
}

// Clients are the server's own Kubernetes clients.
type Clients struct {
	Kube      kubernetes.Interface
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
	return &Clients{Kube: kube, Discovery: kube.Discovery(), Config: config}, nil
}

// SupportCheck asks the lab runtime whether the cluster's clabernetes is recent enough.
type SupportCheck func(ctx context.Context) error

// CheckLabRuntimeSupport runs containerlab's clabernetes release check with the server's
// own connection: the published OpenAPI schema of nodes.c9s.run must have spec.runState.
// Every authenticated identity may read that document, so it needs no extra rights.
func CheckLabRuntimeSupport(ctx context.Context) error {
	lab, err := clabcore.NewContainerLab(clabcore.WithRuntime(clablabruntime.ClabernetesRuntimeName,
		&clabruntime.RuntimeConfig{Timeout: time.Minute}))
	if err != nil {
		return fmt.Errorf("initializing the c9s lab runtime: %w", err)
	}
	return lab.CheckLabRuntimeSupport(ctx)
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

// CheckStartup runs the startup checks: every permission, then clabernetes support.
func CheckStartup(ctx context.Context, clients *Clients, permissions []Permission, support SupportCheck) error {
	if err := CheckPermissions(ctx, clients.Kube, permissions); err != nil {
		return fmt.Errorf("%w: %w", ErrStartup, err)
	}
	if err := support(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrStartup, err)
	}
	return nil
}

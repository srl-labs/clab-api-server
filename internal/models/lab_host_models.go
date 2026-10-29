// internal/models/lab_host_models.go
package models

// LabHostResponse describes the runtime the server runs labs with, so clients can show
// where a user's labs go.
type LabHostResponse struct {
	// Runtime is the lab runtime: docker, podman or c9s.
	Runtime string `json:"runtime" example:"c9s" enums:"docker,podman,c9s"`
	// DefaultTimeout is containerlab's timeout of a deploy, redeploy, apply or destroy that
	// passes no `timeout`, as a Go duration: 10m on c9s, 5m with Docker and Podman.
	DefaultTimeout string `json:"defaultTimeout" example:"10m"`
	// C9s describes the Kubernetes cluster and deploy defaults; only set for c9s.
	C9s *C9sLabHost `json:"c9s,omitempty"`
}

// C9sLabHost is the Kubernetes cluster and the deploy defaults of a c9s server. It names
// them only: no cluster address, credentials or file paths.
type C9sLabHost struct {
	// Context is the kubeconfig context the server uses; empty with the in-cluster
	// ServiceAccount.
	Context string `json:"context" example:"c9s-provisioner"`
	// Cluster is the cluster name of that context; "in-cluster" for the Pod's ServiceAccount.
	Cluster string `json:"cluster" example:"c9s"`
	// NamespacePattern is the namespace of the signed-in user's labs, with {lab} left in
	// (CLAB_KUBE_NAMESPACE_TEMPLATE). Names too long for a namespace are cut and get a hash.
	NamespacePattern string `json:"namespacePattern" example:"c9s-alice-{lab}"`
	// SharedNamespacePattern is the namespace of labs in the shared workspace, with {lab} left in.
	SharedNamespacePattern string `json:"sharedNamespacePattern" example:"c9s-shared-{lab}"`
	// ExposeType is the Service type of lab nodes (CLAB_C9S_EXPOSE_TYPE).
	ExposeType string `json:"exposeType" example:"None" enums:"None,ClusterIP,Headless,LoadBalancer"`
	// Persistence reports whether node storage outlives Pod replacement and destroy
	// (CLAB_C9S_PERSISTENCE).
	Persistence bool `json:"persistence" example:"true"`
	// ImagePullSecret is the name of the image pull secret device Pods reference
	// (CLAB_C9S_IMAGE_PULL_SECRET); empty when unset.
	ImagePullSecret string `json:"imagePullSecret" example:"regcred"`
	// LabQuota reports whether every lab namespace gets a ResourceQuota (CLAB_KUBE_LAB_QUOTA).
	LabQuota bool `json:"labQuota" example:"false"`
	// Metrics reports whether the cluster serves the resource metrics API (metrics.k8s.io)
	// node stats come from.
	Metrics bool `json:"metrics" example:"true"`
}

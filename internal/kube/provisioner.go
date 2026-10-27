package kube

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

// Labels and annotations of lab namespaces the server provisions.
const (
	LabelRuntime     = "containerlab.dev/runtime"
	RuntimeValue     = "clabernetes"
	LabelOwner       = "clab-owner"
	LabelLab         = "clab-lab"
	LabelSharedGroup = "clab-shared-group"
	LabelPodSecurity = "pod-security.kubernetes.io/enforce"
	// LabelManagedBy marks namespaces the API server created; it only deletes those.
	LabelManagedBy = "app.kubernetes.io/managed-by"
	ManagedByValue = "clab-api-server"

	AnnotationOwner       = "containerlab.dev/owner"
	AnnotationLab         = "containerlab.dev/lab"
	AnnotationSharedGroup = "containerlab.dev/shared-group"

	// EditorRole is the clabernetes ClusterRole lab users are bound to in their namespace.
	EditorRole = "clabernetes-lab-editor"
	// AccessRole is the ClusterRole, shipped with the server's RBAC manifest, that adds what
	// containerlab reads besides EditorRole: the lab's namespace object, which it reads
	// before it deploys into the namespace. Bound in a namespace, it grants get on that
	// namespace only.
	AccessRole = "clab-lab-access"
	// editorBinding and accessBinding bind the roles in a lab namespace.
	editorBinding = "clab-lab-editor"
	accessBinding = "clab-lab-access"
	// DefaultQuotaName names the ResourceQuota from CLAB_KUBE_LAB_QUOTA without a name.
	DefaultQuotaName = "clab-lab-quota"
)

var (
	// ErrNamespaceTaken reports a namespace that exists but belongs to another lab.
	ErrNamespaceTaken = errors.New("namespace belongs to another lab")
	// ErrNotProvisioned reports a namespace the server did not create.
	ErrNotProvisioned = errors.New("namespace was not created by clab-api-server")
)

// Settings configure identities and lab namespaces.
type Settings struct {
	// UserPrefix prefixes Kubernetes user and group names (CLAB_KUBE_USER_PREFIX).
	UserPrefix string
	// NamespaceTemplate renders lab namespaces (CLAB_KUBE_NAMESPACE_TEMPLATE).
	NamespaceTemplate string
	// Quota is created in every new lab namespace (CLAB_KUBE_LAB_QUOTA); nil for none.
	Quota *corev1.ResourceQuota
	// PullSecret is copied into every lab namespace when set (CLAB_C9S_IMAGE_PULL_SECRET).
	PullSecret *SecretRef
}

// SecretRef names a Secret.
type SecretRef struct {
	Namespace string
	Name      string
}

// ParseSecretRef reads "<namespace>/<name>" or "<name>", which lives in defaultNamespace.
func ParseSecretRef(value, defaultNamespace string) (*SecretRef, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	namespace, name, found := strings.Cut(value, "/")
	if !found {
		namespace, name = defaultNamespace, value
	}
	if namespace == "" || name == "" || strings.Contains(name, "/") {
		return nil, fmt.Errorf("image pull secret %q: use <namespace>/<name> or a name in namespace %q", value, defaultNamespace)
	}
	return &SecretRef{Namespace: namespace, Name: name}, nil
}

// LoadQuota reads a ResourceQuota manifest (YAML or JSON).
func LoadQuota(path string) (*corev1.ResourceQuota, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the lab quota: %w", err)
	}
	quota := &corev1.ResourceQuota{}
	if err := yaml.UnmarshalStrict(data, quota); err != nil {
		return nil, fmt.Errorf("parsing the lab quota %s: %w", path, err)
	}
	if quota.Kind != "" && quota.Kind != "ResourceQuota" {
		return nil, fmt.Errorf("the lab quota %s is a %s, not a ResourceQuota", path, quota.Kind)
	}
	if len(quota.Spec.Hard) == 0 {
		return nil, fmt.Errorf("the lab quota %s sets no spec.hard limits", path)
	}
	if quota.Name == "" {
		quota.Name = DefaultQuotaName
	}
	return quota, nil
}

// LabNamespace is a lab namespace the server provisioned.
type LabNamespace struct {
	Name  string
	Owner string
	Lab   string
	// SharedGroup is the Linux group of a shared lab; empty for a user's own lab.
	SharedGroup string
}

// Provisioner creates and removes lab namespaces with the server's own identity, and
// reads lab storage as the lab's user.
type Provisioner struct {
	client   kubernetes.Interface
	settings Settings
	// asUser returns a client that impersonates an identity.
	asUser func(clablabruntime.Identity) (kubernetes.Interface, error)
}

// NewProvisioner returns a provisioner. base is the server's rest config, from which
// impersonating clients are built.
func NewProvisioner(client kubernetes.Interface, base *rest.Config, settings Settings) *Provisioner {
	return &Provisioner{
		client:   client,
		settings: settings,
		asUser: func(identity clablabruntime.Identity) (kubernetes.Interface, error) {
			if base == nil {
				return nil, fmt.Errorf("no cluster connection to impersonate %s with", identity.User)
			}
			config := rest.CopyConfig(base)
			config.Impersonate = rest.ImpersonationConfig{UserName: identity.User, Groups: identity.Groups}
			return kubernetes.NewForConfig(config)
		},
	}
}

// Settings returns the provisioner's settings.
func (p *Provisioner) Settings() Settings { return p.settings }

// NamespaceFor returns the namespace of a lab: the template for a user's lab, or the
// shared namespace for a lab in the shared workspace.
func (p *Provisioner) NamespaceFor(owner, lab, sharedGroup string) string {
	if sharedGroup != "" {
		return SharedNamespaceName(lab)
	}
	return NamespaceName(p.settings.NamespaceTemplate, owner, lab)
}

func labNamespaceFromObject(namespace *corev1.Namespace) LabNamespace {
	annotations := namespace.Annotations
	owner := annotations[AnnotationOwner]
	if owner == "" {
		owner = namespace.Labels[LabelOwner]
	}
	lab := annotations[AnnotationLab]
	if lab == "" {
		lab = namespace.Labels[LabelLab]
	}
	group := annotations[AnnotationSharedGroup]
	if group == "" {
		group = namespace.Labels[LabelSharedGroup]
	}
	return LabNamespace{Name: namespace.Name, Owner: owner, Lab: lab, SharedGroup: group}
}

func isProvisioned(namespace *corev1.Namespace) bool {
	return namespace.Labels[LabelManagedBy] == ManagedByValue && namespace.Labels[LabelRuntime] == RuntimeValue
}

// listNamespaces lists provisioned lab namespaces that match the extra labels.
func (p *Provisioner) listNamespaces(ctx context.Context, extra labels.Set) ([]LabNamespace, error) {
	selector := labels.Set{LabelManagedBy: ManagedByValue, LabelRuntime: RuntimeValue}
	for key, value := range extra {
		selector[key] = value
	}
	list, err := p.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, fmt.Errorf("listing lab namespaces: %w", err)
	}
	result := make([]LabNamespace, 0, len(list.Items))
	for idx := range list.Items {
		if list.Items[idx].DeletionTimestamp != nil {
			continue
		}
		result = append(result, labNamespaceFromObject(&list.Items[idx]))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

// FindLab returns every provisioned namespace of a lab name, of any owner.
func (p *Provisioner) FindLab(ctx context.Context, lab string) ([]LabNamespace, error) {
	return p.listNamespaces(ctx, labels.Set{LabelLab: LabelValue(lab)})
}

// OwnedBy returns the namespaces of a user's own labs.
func (p *Provisioner) OwnedBy(ctx context.Context, owner string) ([]LabNamespace, error) {
	namespaces, err := p.listNamespaces(ctx, labels.Set{LabelOwner: LabelValue(owner)})
	if err != nil {
		return nil, err
	}
	own := namespaces[:0]
	for _, namespace := range namespaces {
		if namespace.SharedGroup == "" && namespace.Owner == owner {
			own = append(own, namespace)
		}
	}
	return own, nil
}

// SharedWith returns the namespaces of shared labs of a Linux group.
func (p *Provisioner) SharedWith(ctx context.Context, group string) ([]LabNamespace, error) {
	namespaces, err := p.listNamespaces(ctx, labels.Set{LabelSharedGroup: LabelValue(group)})
	if err != nil {
		return nil, err
	}
	shared := namespaces[:0]
	for _, namespace := range namespaces {
		if namespace.SharedGroup == group {
			shared = append(shared, namespace)
		}
	}
	return shared, nil
}

// subjects are who the lab's RoleBindings bind: the owner, or the group of a shared lab.
func (p *Provisioner) subjects(target LabNamespace) []rbacv1.Subject {
	if target.SharedGroup != "" {
		return []rbacv1.Subject{{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName,
			Name: SharedGroup(p.settings.UserPrefix, target.SharedGroup)}}
	}
	return []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName,
		Name: UserName(p.settings.UserPrefix, target.Owner)}}
}

// EnsureLabNamespace creates the lab's namespace with everything the lab's users need,
// or checks and completes an existing one: the editor RoleBinding, read access to the
// namespace object, the optional quota and the copied image pull secret.
func (p *Provisioner) EnsureLabNamespace(ctx context.Context, target LabNamespace) (LabNamespace, error) {
	target.Name = p.NamespaceFor(target.Owner, target.Lab, target.SharedGroup)
	namespaces := p.client.CoreV1().Namespaces()

	existing, err := namespaces.Get(ctx, target.Name, metav1.GetOptions{})
	switch {
	case err == nil:
		found := labNamespaceFromObject(existing)
		if !isProvisioned(existing) {
			return LabNamespace{}, fmt.Errorf("%w: %s", ErrNotProvisioned, target.Name)
		}
		if found.Lab != target.Lab || found.SharedGroup != target.SharedGroup ||
			(target.SharedGroup == "" && found.Owner != target.Owner) {
			return LabNamespace{}, fmt.Errorf("%w: %s holds lab %q of %q", ErrNamespaceTaken, target.Name, found.Lab, found.Owner)
		}
		if existing.DeletionTimestamp != nil {
			return LabNamespace{}, fmt.Errorf("namespace %s of lab %q is still being deleted; try again shortly", target.Name, target.Lab)
		}
		target = found
	case apierrors.IsNotFound(err):
		object := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name: target.Name,
			Labels: map[string]string{
				LabelRuntime:     RuntimeValue,
				LabelManagedBy:   ManagedByValue,
				LabelOwner:       LabelValue(target.Owner),
				LabelLab:         LabelValue(target.Lab),
				LabelPodSecurity: "privileged",
			},
			Annotations: map[string]string{AnnotationOwner: target.Owner, AnnotationLab: target.Lab},
		}}
		if target.SharedGroup != "" {
			object.Labels[LabelSharedGroup] = LabelValue(target.SharedGroup)
			object.Annotations[AnnotationSharedGroup] = target.SharedGroup
		}
		if _, err := namespaces.Create(ctx, object, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return LabNamespace{}, fmt.Errorf("creating namespace %s: %w", target.Name, err)
		} else if apierrors.IsAlreadyExists(err) {
			// Created concurrently: check it like an existing one.
			return p.EnsureLabNamespace(ctx, target)
		}
	default:
		return LabNamespace{}, fmt.Errorf("reading namespace %s: %w", target.Name, err)
	}

	if err := p.ensureAccess(ctx, target); err != nil {
		return LabNamespace{}, err
	}
	if err := p.ensureQuota(ctx, target.Name); err != nil {
		return LabNamespace{}, err
	}
	if err := p.ensurePullSecret(ctx, target.Name); err != nil {
		return LabNamespace{}, err
	}
	return target, nil
}

func (p *Provisioner) ensureAccess(ctx context.Context, target LabNamespace) error {
	rbac := p.client.RbacV1()
	subjects := p.subjects(target)
	for _, binding := range []*rbacv1.RoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Name: editorBinding, Namespace: target.Name},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: EditorRole},
			Subjects:   subjects,
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: accessBinding, Namespace: target.Name},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: AccessRole},
			Subjects:   subjects,
		},
	} {
		if _, err := rbac.RoleBindings(target.Name).Create(ctx, binding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("binding %s in %s: %w", binding.RoleRef.Name, target.Name, err)
		}
	}
	return nil
}

func (p *Provisioner) ensureQuota(ctx context.Context, namespace string) error {
	if p.settings.Quota == nil {
		return nil
	}
	quota := p.settings.Quota.DeepCopy()
	quota.Namespace = namespace
	quota.ResourceVersion = ""
	if _, err := p.client.CoreV1().ResourceQuotas(namespace).Create(ctx, quota, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("creating quota %s/%s: %w", namespace, quota.Name, err)
	}
	return nil
}

func (p *Provisioner) ensurePullSecret(ctx context.Context, namespace string) error {
	source := p.settings.PullSecret
	if source == nil || source.Namespace == namespace {
		return nil
	}
	secret, err := p.client.CoreV1().Secrets(source.Namespace).Get(ctx, source.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("reading image pull secret %s/%s: %w", source.Namespace, source.Name, err)
	}
	copied := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: source.Name, Namespace: namespace,
			Labels: map[string]string{LabelManagedBy: ManagedByValue},
		},
		Type: secret.Type,
		Data: secret.Data,
	}
	if _, err := p.client.CoreV1().Secrets(namespace).Create(ctx, copied, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("copying image pull secret into %s: %w", namespace, err)
	}
	return nil
}

// ReleaseLabNamespace deletes a lab's namespace after containerlab destroyed the lab: with
// cleanup always, otherwise only when no persistent storage remains, because a plain
// destroy keeps the claims (the saved configuration) for the next deploy. The claims are
// read as the user, whose RoleBinding allows it. It reports whether the namespace went.
func (p *Provisioner) ReleaseLabNamespace(ctx context.Context, namespace string, identity clablabruntime.Identity, cleanup bool) (bool, error) {
	existing, err := p.client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading namespace %s: %w", namespace, err)
	}
	if !isProvisioned(existing) {
		return false, nil
	}

	if !cleanup {
		client, err := p.asUser(identity)
		if err != nil {
			return false, err
		}
		claims, err := client.CoreV1().PersistentVolumeClaims(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, fmt.Errorf("listing the storage of namespace %s: %w", namespace, err)
		}
		if len(claims.Items) != 0 {
			return false, nil
		}
	}

	err = p.client.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("deleting namespace %s: %w", namespace, err)
	}
	return true, nil
}

// ProvisionerPermissions are the permissions the server needs to provision lab namespaces
// and to act as users. pullSecret is the source of the copied image pull secret, if any.
func ProvisionerPermissions(prefix string, pullSecret *SecretRef) []Permission {
	permissions := []Permission{
		{Verb: "create", Resource: "namespaces", Why: "create lab namespaces"},
		{Verb: "get", Resource: "namespaces", Why: "check lab namespaces"},
		{Verb: "list", Resource: "namespaces", Why: "list the labs of a user"},
		{Verb: "delete", Resource: "namespaces", Why: "delete lab namespaces"},
		{Verb: "create", Group: "rbac.authorization.k8s.io", Resource: "rolebindings", Why: "bind lab users in their namespace"},
		{Verb: "bind", Group: "rbac.authorization.k8s.io", Resource: "clusterroles", Name: EditorRole, Why: "bind " + EditorRole},
		{Verb: "bind", Group: "rbac.authorization.k8s.io", Resource: "clusterroles", Name: AccessRole, Why: "bind " + AccessRole},
		{Verb: "get", Group: "rbac.authorization.k8s.io", Resource: "clusterroles", Name: EditorRole, Why: "check that " + EditorRole + " exists"},
		{Verb: "get", Group: "rbac.authorization.k8s.io", Resource: "clusterroles", Name: AccessRole, Why: "check that " + AccessRole + " exists"},
		{Verb: "impersonate", Resource: "users", Name: UserName(prefix, "probe"), Why: "act as the signed-in user"},
		{Verb: "impersonate", Resource: "groups", Name: UsersGroup(prefix), Why: "act as the signed-in user"},
		{Verb: "impersonate", Resource: "groups", Name: AdminsGroup(prefix), Why: "act as a superuser"},
		{Verb: "create", Resource: "resourcequotas", Why: "lab quotas"},
	}
	if pullSecret != nil {
		permissions = append(permissions,
			Permission{Verb: "get", Resource: "secrets", Name: pullSecret.Name, Namespace: pullSecret.Namespace, Why: "read the image pull secret"},
			Permission{Verb: "create", Resource: "secrets", Why: "copy the image pull secret into lab namespaces"})
	}
	return permissions
}

// CheckRoles verifies that the ClusterRoles lab namespaces bind exist; a RoleBinding to a
// missing role would leave every lab user without access.
func CheckRoles(ctx context.Context, client kubernetes.Interface) error {
	for _, role := range []string{EditorRole, AccessRole} {
		_, err := client.RbacV1().ClusterRoles().Get(ctx, role, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			hint := "install clabernetes with its lab roles (labRoles.enabled)"
			if role == AccessRole {
				hint = "apply the server's RBAC manifest (docs/kubernetes/provisioner-rbac.yaml)"
			}
			return fmt.Errorf("ClusterRole %s not found: %s", role, hint)
		}
		if err != nil {
			return fmt.Errorf("reading ClusterRole %s: %w", role, err)
		}
	}
	return nil
}

// internal/config/runtime.go
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Lab runtimes the server supports, as CLAB_RUNTIME spells them.
const (
	RuntimeDocker = "docker"
	RuntimePodman = "podman"
	RuntimeC9s    = clablabruntime.ClabernetesRuntimeName
)

// normalizeRuntimeConfig validates CLAB_RUNTIME and the Kubernetes settings it uses.
func normalizeRuntimeConfig(cfg *Config) error {
	runtime := strings.ToLower(strings.TrimSpace(cfg.ClabRuntime))
	if runtime == "" {
		runtime = RuntimeDocker
	}
	switch runtime {
	case RuntimeDocker, RuntimePodman, RuntimeC9s:
	default:
		return fmt.Errorf("CLAB_RUNTIME %q is not supported; use %s, %s or %s",
			cfg.ClabRuntime, RuntimeDocker, RuntimePodman, RuntimeC9s)
	}
	cfg.ClabRuntime = runtime

	cfg.ClabKubeconfig = strings.TrimSpace(cfg.ClabKubeconfig)
	if cfg.ClabKubeconfig != "" && !filepath.IsAbs(cfg.ClabKubeconfig) {
		return fmt.Errorf("CLAB_KUBECONFIG must be an absolute path")
	}
	cfg.ClabKubeContext = strings.TrimSpace(cfg.ClabKubeContext)
	cfg.ClabKubeNamespace = strings.TrimSpace(cfg.ClabKubeNamespace)
	if cfg.ClabKubeNamespace != "" && runtime == RuntimeC9s {
		return fmt.Errorf("CLAB_KUBE_NAMESPACE cannot be used with CLAB_RUNTIME=c9s: every lab gets its own namespace (CLAB_KUBE_NAMESPACE_TEMPLATE)")
	}

	cfg.ClabKubeUserPrefix = strings.TrimSpace(cfg.ClabKubeUserPrefix)
	if runtime == RuntimeC9s && cfg.ClabKubeUserPrefix == "" {
		return fmt.Errorf("CLAB_KUBE_USER_PREFIX must not be empty: it keeps API users apart from the cluster's own users")
	}
	cfg.ClabKubeNamespaceTemplate = strings.TrimSpace(cfg.ClabKubeNamespaceTemplate)
	if runtime == RuntimeC9s {
		if err := validateNamespaceTemplate(cfg.ClabKubeNamespaceTemplate); err != nil {
			return fmt.Errorf("CLAB_KUBE_NAMESPACE_TEMPLATE: %w", err)
		}
	}
	cfg.ClabKubeLabQuota = strings.TrimSpace(cfg.ClabKubeLabQuota)
	if cfg.ClabKubeLabQuota != "" && !filepath.IsAbs(cfg.ClabKubeLabQuota) {
		return fmt.Errorf("CLAB_KUBE_LAB_QUOTA must be an absolute path")
	}

	exposeType, err := clablabruntime.NormalizeExposeType(strings.TrimSpace(cfg.ClabC9sExposeType))
	if err != nil {
		return fmt.Errorf("CLAB_C9S_EXPOSE_TYPE: %w", err)
	}
	cfg.ClabC9sExposeType = exposeType

	cfg.ClabC9sImagePullSecret = strings.TrimSpace(cfg.ClabC9sImagePullSecret)
	if cfg.ClabC9sImagePullSecret != "" {
		// "<namespace>/<name>" names the secret the server copies into lab namespaces.
		namespace, name, qualified := strings.Cut(cfg.ClabC9sImagePullSecret, "/")
		if !qualified {
			name, namespace = namespace, ""
		}
		if errs := validation.IsDNS1123Subdomain(name); len(errs) != 0 {
			return fmt.Errorf("CLAB_C9S_IMAGE_PULL_SECRET %q is not a valid secret name: %s",
				cfg.ClabC9sImagePullSecret, errs[0])
		}
		if qualified {
			if errs := validation.IsDNS1123Label(namespace); len(errs) != 0 {
				return fmt.Errorf("CLAB_C9S_IMAGE_PULL_SECRET %q has an invalid namespace: %s",
					cfg.ClabC9sImagePullSecret, errs[0])
			}
		}
	}

	return nil
}

// IsLabRuntime reports whether CLAB_RUNTIME selects a lab runtime (c9s) rather than a
// local container runtime.
func (c Config) IsLabRuntime() bool {
	return c.ClabRuntime == RuntimeC9s
}

// NamespaceMode reports how c9s labs are placed in namespaces: always "per-lab", every lab
// in its own namespace. It is empty for other runtimes.
func (c Config) NamespaceMode() string {
	if !c.IsLabRuntime() {
		return ""
	}
	return "per-lab"
}

// PullSecretName is the name of the image pull secret device Pods reference.
func (c Config) PullSecretName() string {
	if _, name, qualified := strings.Cut(c.ClabC9sImagePullSecret, "/"); qualified {
		return name
	}
	return c.ClabC9sImagePullSecret
}

// validateNamespaceTemplate checks that a namespace template gives every lab of every user
// its own namespace: it needs {user} and {lab}, and otherwise lowercase letters, digits
// and dashes.
func validateNamespaceTemplate(template string) error {
	if !strings.Contains(template, "{lab}") || !strings.Contains(template, "{user}") {
		return fmt.Errorf("%q must contain {user} and {lab}", template)
	}
	rest := strings.NewReplacer("{user}", "", "{lab}", "").Replace(template)
	for _, r := range rest {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return fmt.Errorf("%q may only hold lowercase letters, digits and dashes besides {user} and {lab}", template)
		}
	}
	return nil
}

// ExportLabRuntimeEnv hands the Kubernetes settings to containerlab, which reads them
// from the process environment. Unset settings are removed so a stale value from the
// server's own environment cannot select another cluster or namespace.
func ExportLabRuntimeEnv(cfg Config) {
	if !cfg.IsLabRuntime() {
		return
	}
	setOrUnset("CLAB_KUBECONFIG", cfg.ClabKubeconfig)
	setOrUnset("CLAB_KUBE_CONTEXT", cfg.ClabKubeContext)
	// Every lab names its namespace on each call; a global override would merge them.
	setOrUnset("CLAB_KUBE_NAMESPACE", "")
}

func setOrUnset(key, value string) {
	if value == "" {
		_ = os.Unsetenv(key)
		return
	}
	_ = os.Setenv(key, value)
}

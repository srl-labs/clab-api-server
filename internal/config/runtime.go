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
	if cfg.ClabKubeNamespace != "" {
		if errs := validation.IsDNS1123Label(cfg.ClabKubeNamespace); len(errs) != 0 {
			return fmt.Errorf("CLAB_KUBE_NAMESPACE %q is not a valid namespace name: %s",
				cfg.ClabKubeNamespace, errs[0])
		}
	}

	exposeType, err := clablabruntime.NormalizeExposeType(strings.TrimSpace(cfg.ClabC9sExposeType))
	if err != nil {
		return fmt.Errorf("CLAB_C9S_EXPOSE_TYPE: %w", err)
	}
	cfg.ClabC9sExposeType = exposeType

	cfg.ClabC9sImagePullSecret = strings.TrimSpace(cfg.ClabC9sImagePullSecret)
	if cfg.ClabC9sImagePullSecret != "" {
		if errs := validation.IsDNS1123Subdomain(cfg.ClabC9sImagePullSecret); len(errs) != 0 {
			return fmt.Errorf("CLAB_C9S_IMAGE_PULL_SECRET %q is not a valid secret name: %s",
				cfg.ClabC9sImagePullSecret, errs[0])
		}
	}

	return nil
}

// IsLabRuntime reports whether CLAB_RUNTIME selects a lab runtime (c9s) rather than a
// local container runtime.
func (c Config) IsLabRuntime() bool {
	return c.ClabRuntime == RuntimeC9s
}

// NamespaceMode reports how c9s labs are placed in namespaces: "fixed" when every lab
// shares CLAB_KUBE_NAMESPACE, "per-lab" otherwise. It is empty for other runtimes.
func (c Config) NamespaceMode() string {
	if !c.IsLabRuntime() {
		return ""
	}
	if c.ClabKubeNamespace != "" {
		return "fixed"
	}
	return "per-lab"
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
	setOrUnset("CLAB_KUBE_NAMESPACE", cfg.ClabKubeNamespace)
}

func setOrUnset(key, value string) {
	if value == "" {
		_ = os.Unsetenv(key)
		return
	}
	_ = os.Setenv(key, value)
}

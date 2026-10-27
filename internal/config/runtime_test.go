package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func loadTestEnv(t *testing.T, content string) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.env")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	previous := AppConfig
	t.Cleanup(func() {
		AppConfig = previous
		viper.Reset()
	})
	viper.Reset()
	return LoadConfig(path)
}

func TestLoadConfigLabRuntimeDefaults(t *testing.T) {
	require.NoError(t, loadTestEnv(t, "CLAB_RUNTIME=C9S\n"))
	require.Equal(t, RuntimeC9s, AppConfig.ClabRuntime)
	require.True(t, AppConfig.IsLabRuntime())
	require.Equal(t, "None", AppConfig.ClabC9sExposeType)
	require.True(t, AppConfig.ClabC9sPersistence)
	require.Empty(t, AppConfig.ClabC9sImagePullSecret)
	require.Equal(t, "per-lab", AppConfig.NamespaceMode())
}

func TestLoadConfigLabRuntimeSettings(t *testing.T) {
	require.NoError(t, loadTestEnv(t, `CLAB_RUNTIME=c9s
CLAB_KUBECONFIG=/etc/clab/kubeconfig
CLAB_KUBE_CONTEXT=lab
CLAB_KUBE_NAMESPACE=labs
CLAB_C9S_EXPOSE_TYPE=loadbalancer
CLAB_C9S_PERSISTENCE=false
CLAB_C9S_IMAGE_PULL_SECRET=regcred
`))
	require.Equal(t, "/etc/clab/kubeconfig", AppConfig.ClabKubeconfig)
	require.Equal(t, "lab", AppConfig.ClabKubeContext)
	require.Equal(t, "LoadBalancer", AppConfig.ClabC9sExposeType)
	require.False(t, AppConfig.ClabC9sPersistence)
	require.Equal(t, "regcred", AppConfig.ClabC9sImagePullSecret)
	require.Equal(t, "fixed", AppConfig.NamespaceMode())
}

func TestLoadConfigRejectsInvalidRuntimeSettings(t *testing.T) {
	for name, env := range map[string]string{
		"runtime":     "CLAB_RUNTIME=kubernetes\n",
		"kubeconfig":  "CLAB_RUNTIME=c9s\nCLAB_KUBECONFIG=relative/kubeconfig\n",
		"namespace":   "CLAB_RUNTIME=c9s\nCLAB_KUBE_NAMESPACE=Not_A_Namespace\n",
		"expose type": "CLAB_RUNTIME=c9s\nCLAB_C9S_EXPOSE_TYPE=NodePort\n",
		"pull secret": "CLAB_RUNTIME=c9s\nCLAB_C9S_IMAGE_PULL_SECRET=Bad Secret\n",
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, loadTestEnv(t, env))
		})
	}
}

func TestDockerHasNoNamespaceMode(t *testing.T) {
	require.NoError(t, loadTestEnv(t, "CLAB_RUNTIME=docker\nCLAB_KUBE_NAMESPACE=labs\n"))
	require.False(t, AppConfig.IsLabRuntime())
	require.Empty(t, AppConfig.NamespaceMode())
}

func TestExportLabRuntimeEnv(t *testing.T) {
	t.Setenv("CLAB_KUBECONFIG", "/stale")
	t.Setenv("CLAB_KUBE_CONTEXT", "stale")
	t.Setenv("CLAB_KUBE_NAMESPACE", "stale")

	ExportLabRuntimeEnv(Config{ClabRuntime: RuntimeDocker, ClabKubeconfig: "/x"})
	require.Equal(t, "/stale", os.Getenv("CLAB_KUBECONFIG"), "docker leaves the environment alone")

	ExportLabRuntimeEnv(Config{ClabRuntime: RuntimeC9s, ClabKubeconfig: "/etc/kubeconfig", ClabKubeContext: "lab"})
	require.Equal(t, "/etc/kubeconfig", os.Getenv("CLAB_KUBECONFIG"))
	require.Equal(t, "lab", os.Getenv("CLAB_KUBE_CONTEXT"))
	_, set := os.LookupEnv("CLAB_KUBE_NAMESPACE")
	require.False(t, set, "an unset namespace must not leave a stale override behind")
}

func TestScrubProcessEnvKeepsKubernetesSettings(t *testing.T) {
	t.Setenv("CLAB_KUBECONFIG", "/etc/kubeconfig")
	t.Setenv("JWT_SECRET", "secret")
	t.Cleanup(viper.Reset)
	removed := ScrubProcessEnv()
	require.Contains(t, removed, "JWT_SECRET")
	require.NotContains(t, removed, "CLAB_KUBECONFIG")
	require.Equal(t, "/etc/kubeconfig", os.Getenv("CLAB_KUBECONFIG"))
}

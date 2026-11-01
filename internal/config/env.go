// internal/config/env.go
package config

import (
	"os"
	"reflect"
	"sort"

	"github.com/spf13/viper"
)

// passthroughEnvKeys are configuration keys that containerlab also reads from
// the process environment. Their values are not sensitive, so they stay set.
var passthroughEnvKeys = map[string]bool{
	"CLAB_RUNTIME":        true,
	"CLAB_KUBECONFIG":     true,
	"CLAB_KUBE_CONTEXT":   true,
	"CLAB_KUBE_NAMESPACE": true,
}

// EnvKeys returns the environment variable names the server reads its
// configuration from, derived from the Config struct tags.
func EnvKeys() []string {
	t := reflect.TypeFor[Config]()
	keys := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		if key := t.Field(i).Tag.Get("mapstructure"); key != "" && key != "-" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

// ScrubProcessEnv removes the server's configuration variables from the process
// environment and returns the names it removed. containerlab expands ${VAR}
// references in user-supplied topologies from the process environment, so
// leaving values such as JWT_SECRET there would let any API user read them
// back. Values already loaded stay available through AppConfig and viper.
// Subprocesses started afterwards no longer inherit these variables.
func ScrubProcessEnv() []string {
	var removed []string
	for _, key := range EnvKeys() {
		if passthroughEnvKeys[key] {
			continue
		}
		if _, ok := os.LookupEnv(key); !ok {
			continue
		}
		// Pin the resolved value so viper lookups keep working once the
		// variable is gone from the environment.
		viper.Set(key, viper.Get(key))
		_ = os.Unsetenv(key)
		removed = append(removed, key)
	}
	return removed
}

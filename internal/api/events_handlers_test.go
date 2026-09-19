package api

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEventAccessUsesRuntimeLabelsAfterContainerRemoval(t *testing.T) {
	root := t.TempDir()
	setTestSharedLabsRoot(t, root)
	for _, tc := range []struct {
		name, owner, path string
		allowed           bool
	}{
		{"shared destroyed lab", "alice", filepath.Join(root, "demo/demo.clab.yml"), true},
		{"own destroyed lab", "bob", "/home/bob/.clab/demo.clab.yml", true},
		{"private replacement with same name", "alice", "/home/alice/.clab/demo.clab.yml", false},
		{"shared prefix collision", "alice", root + "-private/demo.clab.yml", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, err := json.Marshal(map[string]any{
				"type": "container", "action": "destroy",
				"attributes": map[string]string{"containerlab": "demo", "clab-owner": tc.owner, "clab-topo-file": tc.path},
			})
			require.NoError(t, err)
			require.Equal(t, tc.allowed, canAccessEventLine("bob", string(line), func(string) bool {
				t.Fatal("runtime labels must not depend on a live container or stale lab-name cache")
				return false
			}))
		})
	}
}

func TestEventAccessFallsBackForUnlabelledInterfaceEvents(t *testing.T) {
	line := `{"type":"interface","action":"update","attributes":{"lab":"demo","name":"clab-demo-n1"}}`
	require.True(t, canAccessEventLine("bob", line, func(lab string) bool { return lab == "demo" }))
	require.False(t, canAccessEventLine("bob", line, func(string) bool { return false }))
	for _, invalid := range []string{"not JSON", `{}`, `{"attributes":{"name":"host"}}`} {
		require.False(t, canAccessEventLine("bob", invalid, func(string) bool { return true }))
	}
}

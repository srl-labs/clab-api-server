package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestLabPathScope(t *testing.T) (labPathScope, string, string) {
	t.Helper()
	workspace := filepath.Join(t.TempDir(), "ws")
	topoDir := filepath.Join(workspace, "lab1")
	require.NoError(t, os.MkdirAll(topoDir, 0o750))
	scope := newLabPathScope(filepath.Join(topoDir, "lab1.clab.yml"), labPathRoot{path: workspace, uid: 1000, gid: 1000}, "")
	return scope, workspace, topoDir
}

func TestLabPathResolveInsideWorkspace(t *testing.T) {
	scope, workspace, topoDir := newTestLabPathScope(t)
	realWorkspace, err := filepath.EvalSymlinks(workspace)
	require.NoError(t, err)

	for _, tc := range []struct {
		raw, wantRel string
	}{
		{"snapshots", "lab1/snapshots"},
		{"./snapshots/new/deeper", "lab1/snapshots/new/deeper"},
		{"../other", "other"},
		{"..", "."},
		{filepath.Join(topoDir, "abs"), "lab1/abs"},
		{"  snapshots  ", "lab1/snapshots"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			resolved, err := scope.resolve(tc.raw)
			require.NoError(t, err)
			require.Equal(t, tc.wantRel, resolved.display())
			require.Equal(t, realWorkspace, resolved.Root)
			require.True(t, strings.HasPrefix(resolved.Path, realWorkspace))
			require.Equal(t, 1000, resolved.UID)
			require.False(t, resolved.Shared)
		})
	}
}

func TestLabPathResolveRejectsEscapes(t *testing.T) {
	scope, workspace, topoDir := newTestLabPathScope(t)
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "shadow"), []byte("secret"), 0o600))

	// Symlinks inside the workspace that point outside of it.
	require.NoError(t, os.Symlink(outside, filepath.Join(topoDir, "escape-dir")))
	require.NoError(t, os.Symlink(filepath.Join(outside, "shadow"), filepath.Join(topoDir, "escape-file.tar")))
	require.NoError(t, os.Symlink(filepath.Join(outside, "missing"), filepath.Join(topoDir, "dangling")))

	for _, raw := range []string{
		"",
		"   ",
		"../..",
		"../../etc",
		"../../../../../../etc/shadow",
		"/etc/shadow",
		outside,
		workspace + "-sibling/file",
		"escape-dir",
		"escape-dir/new/sub",
		"escape-file.tar",
		"dangling",
		"dangling/below",
		"bad\x00name",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := scope.resolve(raw)
			require.Error(t, err)
		})
	}
}

func TestLabPathResolveAllowsSymlinksThatStayInside(t *testing.T) {
	scope, workspace, topoDir := newTestLabPathScope(t)
	target := filepath.Join(workspace, "store")
	require.NoError(t, os.MkdirAll(target, 0o750))
	require.NoError(t, os.Symlink(target, filepath.Join(topoDir, "link")))

	resolved, err := scope.resolve("link/snap")
	require.NoError(t, err)
	require.Equal(t, "store/snap", resolved.display())
}

func TestLabPathScopeBaseDir(t *testing.T) {
	workspace := t.TempDir()
	root := labPathRoot{path: workspace, uid: -1, gid: -1}

	// Topology outside the workspace (e.g. downloaded from a URL): relative to workspace root.
	scope := newLabPathScope(filepath.Join(t.TempDir(), "remote.clab.yml"), root, "")
	require.Equal(t, workspace, scope.baseDir)
	resolved, err := scope.resolve("snapshots")
	require.NoError(t, err)
	require.Equal(t, "snapshots", resolved.display())

	// No topology at all.
	scope = newLabPathScope("", root, "")
	require.Equal(t, workspace, scope.baseDir)
}

func TestLabPathSharedRoot(t *testing.T) {
	workspace := t.TempDir()
	shared := t.TempDir()
	topoDir := filepath.Join(shared, "demo")
	require.NoError(t, os.MkdirAll(topoDir, 0o750))
	require.NoError(t, os.Symlink(filepath.Join(shared, "demo"), filepath.Join(shared, "alias")))

	scope := newLabPathScope(filepath.Join(topoDir, "demo.clab.yml"), labPathRoot{path: workspace, uid: 1000, gid: 1000}, shared)
	resolved, err := scope.resolve("snapshots")
	require.NoError(t, err)
	require.True(t, resolved.Shared)
	require.Equal(t, -1, resolved.UID)
	require.Equal(t, "@shared/demo/snapshots", resolved.display())

	// Shared paths must not contain symlinks, even ones that stay inside.
	_, err = scope.resolve(filepath.Join(shared, "alias", "snapshots"))
	require.Error(t, err)

	// The user's own workspace stays allowed for shared labs.
	resolved, err = scope.resolve(filepath.Join(workspace, "mine"))
	require.NoError(t, err)
	require.False(t, resolved.Shared)
	require.Equal(t, "mine", resolved.display())

	// Labs outside the shared root cannot reach it.
	privateScope := newLabPathScope(filepath.Join(workspace, "lab", "lab.clab.yml"), labPathRoot{path: workspace}, shared)
	_, err = privateScope.resolve(filepath.Join(shared, "demo"))
	require.ErrorIs(t, err, errLabPathOutsideRoots)
}

func TestResolvedLabPathDisplayChild(t *testing.T) {
	scope, _, _ := newTestLabPathScope(t)
	resolved, err := scope.resolve("snapshots")
	require.NoError(t, err)
	require.Equal(t, "lab1/snapshots/r1.tar", resolved.displayChild(filepath.Join(resolved.Path, "r1.tar")))
	require.Equal(t, "/elsewhere/x", resolved.displayChild("/elsewhere/x"))
}

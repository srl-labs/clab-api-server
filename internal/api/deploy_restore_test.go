package api

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/srl-labs/clab-api-server/internal/clab"
)

func TestParseRestoreValues(t *testing.T) {
	query, err := parseRestoreValues("snapshots", true, []string{"r1=snaps/r1.tar", " r2 = /abs/r2.tar"})
	require.NoError(t, err)
	require.Equal(t, "snapshots", query.all)
	require.Equal(t, []restoreNodeQuery{{node: "r1", path: "snaps/r1.tar"}, {node: "r2", path: " /abs/r2.tar"}}, query.nodes)

	query, err = parseRestoreValues("", false, nil)
	require.NoError(t, err)
	require.True(t, query.empty())

	for _, tc := range []struct {
		name    string
		all     string
		allSet  bool
		restore []string
	}{
		{"blank restoreAll", "  ", true, nil},
		{"empty restoreAll", "", true, nil},
		{"missing equals", "", false, []string{"r1"}},
		{"empty path", "", false, []string{"r1=  "}},
		{"empty node", "", false, []string{"=r1.tar"}},
		{"bad node", "", false, []string{"r1;rm=r1.tar"}},
		{"slash node", "", false, []string{"a/b=r1.tar"}},
		{"duplicate node", "", false, []string{"r1=a.tar", "r1=b.tar"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRestoreValues(tc.all, tc.allSet, tc.restore)
			require.Error(t, err)
		})
	}
}

func TestResolveRestoreSnapshots(t *testing.T) {
	scope, workspace, topoDir := newTestLabPathScope(t)
	realTopoDir, err := filepath.EvalSymlinks(topoDir)
	require.NoError(t, err)
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "shadow"), []byte("secret"), 0o600))

	snapDir := filepath.Join(topoDir, "snapshots")
	require.NoError(t, os.MkdirAll(filepath.Join(snapDir, "dir.tar"), 0o750))
	for _, name := range []string{"r1.tar", "r2.tar", "notes.txt", "bad;name.tar"} {
		require.NoError(t, os.WriteFile(filepath.Join(snapDir, name), []byte("x"), 0o640))
	}
	require.NoError(t, os.WriteFile(filepath.Join(workspace, "override.tar"), []byte("x"), 0o640))

	snapshots, err := scope.resolveRestoreSnapshots(restoreQuery{
		all:   "snapshots",
		nodes: []restoreNodeQuery{{node: "r2", path: "../override.tar"}, {node: "r3", path: "snapshots/r1.tar"}},
	})
	require.NoError(t, err)
	realWorkspace, err := filepath.EvalSymlinks(workspace)
	require.NoError(t, err)
	got := make([]string, 0, len(snapshots))
	for _, entry := range snapshots {
		require.True(t, filepath.IsAbs(entry.path.Path), entry.node)
		got = append(got, entry.node+"="+entry.path.Path)
	}
	require.Equal(t, []string{
		"r1=" + filepath.Join(realTopoDir, "snapshots", "r1.tar"),
		"r2=" + filepath.Join(realWorkspace, "override.tar"),
		"r3=" + filepath.Join(realTopoDir, "snapshots", "r1.tar"),
	}, got)

	// A symlink planted in the restoreAll directory must not reach host files.
	require.NoError(t, os.Symlink(filepath.Join(outside, "shadow"), filepath.Join(snapDir, "r9.tar")))
	_, err = scope.resolveRestoreSnapshots(restoreQuery{all: "snapshots"})
	require.Error(t, err)
	require.NoError(t, os.Remove(filepath.Join(snapDir, "r9.tar")))

	for _, tc := range []struct {
		name  string
		query restoreQuery
	}{
		{"missing dir", restoreQuery{all: "missing"}},
		{"dir is a file", restoreQuery{all: "snapshots/r1.tar"}},
		{"restoreAll outside", restoreQuery{all: outside}},
		{"file outside", restoreQuery{nodes: []restoreNodeQuery{{node: "r1", path: filepath.Join(outside, "shadow")}}}},
		{"dotdot escape", restoreQuery{nodes: []restoreNodeQuery{{node: "r1", path: "../../../etc/shadow"}}}},
		{"missing file", restoreQuery{nodes: []restoreNodeQuery{{node: "r1", path: "snapshots/none.tar"}}}},
		{"directory", restoreQuery{nodes: []restoreNodeQuery{{node: "r1", path: "snapshots"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := scope.resolveRestoreSnapshots(tc.query)
			require.Error(t, err)
		})
	}

	// A symlinked snapshot file that escapes the workspace is rejected.
	require.NoError(t, os.Symlink(filepath.Join(outside, "shadow"), filepath.Join(topoDir, "link.tar")))
	_, err = scope.resolveRestoreSnapshots(restoreQuery{nodes: []restoreNodeQuery{{node: "r1", path: "link.tar"}}})
	require.Error(t, err)
}

func TestOpenRestoreSnapshotsRejectsPathsSwappedAfterCheck(t *testing.T) {
	scope, _, topoDir := newTestLabPathScope(t)
	scope.reader = clab.FileReader{UID: os.Getuid(), GIDs: []int{os.Getgid()}}
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "r1.tar"), []byte("secret"), 0o600))
	snapDir := filepath.Join(topoDir, "snapshots")
	require.NoError(t, os.MkdirAll(snapDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(snapDir, "r1.tar"), []byte("snapshot"), 0o640))

	resolve := func() []restoreSnapshotPath {
		paths, err := scope.resolveRestoreSnapshots(restoreQuery{all: "snapshots"})
		require.NoError(t, err)
		require.Len(t, paths, 1)
		return paths
	}

	// The checked directory is replaced by a symlink before the file is opened.
	paths := resolve()
	require.NoError(t, os.Rename(snapDir, snapDir+".old"))
	require.NoError(t, os.Symlink(outside, snapDir))
	_, err := scope.openRestoreSnapshots(paths)
	require.Error(t, err)
	require.NoError(t, os.Remove(snapDir))
	require.NoError(t, os.Rename(snapDir+".old", snapDir))

	// The checked file is replaced by a symlink before it is opened.
	paths = resolve()
	snapshot := filepath.Join(snapDir, "r1.tar")
	require.NoError(t, os.Rename(snapshot, snapshot+".old"))
	require.NoError(t, os.Symlink(filepath.Join(outside, "r1.tar"), snapshot))
	_, err = scope.openRestoreSnapshots(paths)
	require.Error(t, err)
	require.NoError(t, os.Remove(snapshot))
	require.NoError(t, os.Rename(snapshot+".old", snapshot))

	// Once opened, the file stays the checked one whatever happens to the path.
	opened, err := scope.openRestoreSnapshots(resolve())
	require.NoError(t, err)
	defer closeRestoreSnapshots(opened)
	require.NoError(t, os.Rename(snapshot, snapshot+".old"))
	require.NoError(t, os.Symlink(filepath.Join(outside, "r1.tar"), snapshot))
	content, err := io.ReadAll(opened[0].File)
	require.NoError(t, err)
	require.Equal(t, "r1", opened[0].Node)
	require.Equal(t, "snapshot", string(content))
}

func TestOpenRestoreSnapshotsChecksWorkspaceReader(t *testing.T) {
	scope, _, topoDir := newTestLabPathScope(t)
	scope.reader = clab.FileReader{UID: os.Getuid() + 4242, GIDs: []int{os.Getgid() + 4242}}
	require.NoError(t, os.WriteFile(filepath.Join(topoDir, "r1.tar"), []byte("x"), 0o600))

	paths, err := scope.resolveRestoreSnapshots(restoreQuery{nodes: []restoreNodeQuery{{node: "r1", path: "r1.tar"}}})
	require.NoError(t, err)
	_, err = scope.openRestoreSnapshots(paths)
	require.ErrorContains(t, err, "not readable")
}

func TestDeployHandlersRejectInvalidRestoreQuery(t *testing.T) {
	router, _ := workspaceTestRouter(t)
	router.POST("/labs/:labName/deploy", DeployTopologyHandler)
	router.POST("/labs", DeployLabHandler)
	router.POST("/archive", DeployLabArchiveHandler)

	for _, query := range []string{
		"restoreAll=",
		"restoreAll=%20%20",
		"restore=r1",
		"restore=" + url.QueryEscape("r1;x=a.tar"),
		"restore=" + url.QueryEscape("r1=a.tar") + "&restore=" + url.QueryEscape("r1=b.tar"),
	} {
		t.Run(query, func(t *testing.T) {
			response := performWorkspaceRequest(router, http.MethodPost, "/labs/demo/deploy?"+query, nil)
			require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())

			response = performWorkspaceRequest(router, http.MethodPost, "/labs?"+query, []byte(`{"topologyContent":{"name":"demo"}}`))
			require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())

			response = performWorkspaceRequest(router, http.MethodPost, "/archive?labName=demo&"+query, nil)
			require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
		})
	}
}

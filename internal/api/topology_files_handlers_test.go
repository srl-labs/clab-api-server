package api

import (
	"encoding/json"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/srl-labs/clab-api-server/internal/models"
	"github.com/stretchr/testify/require"
)

func writeTopologyFixture(t *testing.T, root, path, content string) {
	t.Helper()
	absPath := filepath.Join(root, filepath.FromSlash(path))
	require.NoError(t, os.MkdirAll(filepath.Dir(absPath), 0750))
	require.NoError(t, os.WriteFile(absPath, []byte(content), 0640))
}

func TestListTopologyEntriesRecursive(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"flat.clab.yml":                                  "name: flat\n",
		"legacy/topology.clab.yaml":                      "name: original\n",
		"repo/repo.clab.yml":                             "name: repo\n",
		"repo/second.clab.yaml":                          "name: second-lab\n",
		"repo/labs/topology1.clab.yaml":                  "name: first-lab\n",
		"repo/labs/topology2.clab.yml":                   "name: second-nested-lab\n",
		"repo/labs/deep/topology3.clab.yaml":             "name: third-lab\n",
		"other/labs/topology1.clab.yaml":                 "name: first-lab\n",
		"repo/labs/topology1.clab.yaml.annotations.json": "{}",
		"repo/.git/hidden.clab.yml":                      "name: hidden\n",
		"repo/node_modules/hidden.clab.yml":              "name: hidden\n",
		"repo/.cache/hidden.clab.yml":                    "name: hidden\n",
		"repo/labs/clab-first-lab/topology-data.json":    "{}",
		"repo/labs/clab-first-lab/copy.clab.yml":         "name: hidden\n",
		"clab-examples/labs/valid.clab.yml":              "name: valid\n",
		"repo/labs/.tmp-example.clab.yml":                "name: hidden\n",
		"repo/labs/broken.clab.yml":                      "invalid: [",
	}
	for path, content := range files {
		writeTopologyFixture(t, root, path, content)
	}
	require.NoError(t, os.Symlink(filepath.Join(root, "repo", "labs"), filepath.Join(root, "linked")))
	require.NoError(t, os.Symlink(filepath.Join(root, "flat.clab.yml"), filepath.Join(root, "alias.clab.yml")))

	entries, err := listTopologyEntries(root)
	require.NoError(t, err)
	expected := map[string]string{
		"flat.clab.yml":                      "flat",
		"legacy/topology.clab.yaml":          "legacy",
		"repo/repo.clab.yml":                 "repo",
		"repo/second.clab.yaml":              "second-lab",
		"repo/labs/topology1.clab.yaml":      "first-lab",
		"repo/labs/topology2.clab.yml":       "second-nested-lab",
		"repo/labs/deep/topology3.clab.yaml": "third-lab",
		"other/labs/topology1.clab.yaml":     "first-lab",
		"clab-examples/labs/valid.clab.yml":  "valid",
		"repo/labs/broken.clab.yml":          "broken",
	}
	require.Len(t, entries, len(expected))
	for i, entry := range entries {
		require.Equal(t, filepath.Join(root, filepath.FromSlash(entry.YamlFileName)), entry.AbsolutePath)
		require.Equal(t, expected[entry.YamlFileName], entry.LabName, "%+v", entry)
		require.Equal(t, entry.YamlFileName+".annotations.json", entry.AnnotationsFileName)
		require.Equal(t, entry.YamlFileName == "repo/labs/topology1.clab.yaml", entry.HasAnnotations)
		require.Equal(t, "undeployed", entry.DeploymentState)
		if i > 0 {
			previous := entries[i-1]
			require.True(t, previous.LabName < entry.LabName || (previous.LabName == entry.LabName && previous.YamlFileName < entry.YamlFileName))
		}
	}
}

func TestListTopologyEntriesMissingRoot(t *testing.T) {
	entries, err := listTopologyEntries(filepath.Join(t.TempDir(), "missing"))
	require.NoError(t, err)
	require.NotNil(t, entries)
	require.Empty(t, entries)
}

func TestListTopologyEntriesKeepsDistinctPathsWithSameLabName(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"demo.clab.yml", "demo/demo.clab.yml", "repo/labs/demo.clab.yml", "repo/labs/demo.clab.yaml"} {
		writeTopologyFixture(t, root, path, "name: demo\n")
	}
	entries, err := listTopologyEntries(root)
	require.NoError(t, err)
	require.Len(t, entries, 4)
	for _, entry := range entries {
		require.Equal(t, "demo", entry.LabName)
	}
}

func TestDiscoveredTopologyFileOperations(t *testing.T) {
	router, root := workspaceTestRouter(t)
	router.GET("/topologies", ListTopologiesHandler)
	router.GET("/labs/:labName/file", GetTopologyFileHandler)
	router.PUT("/labs/:labName/file", PutTopologyFileHandler)
	router.HEAD("/labs/:labName/file", HeadTopologyFileHandler)
	router.POST("/labs/:labName/rename", RenameTopologyFileHandler)
	router.DELETE("/labs/:labName/file", DeleteTopologyFileHandler)
	path := "repo/labs/demo.clab.yaml"
	writeTopologyFixture(t, root, path, "name: demo\ntopology:\n  nodes: {}\n")
	// A legacy path with the same suffix must not shadow an explicit workspace path.
	writeTopologyFixture(t, root, "demo/"+path, "name: shadow\n")
	listed := performWorkspaceRequest(router, http.MethodGet, "/topologies", nil)
	require.Equal(t, http.StatusOK, listed.Code)
	var entries []models.TopologyEntry
	require.NoError(t, json.Unmarshal(listed.Body.Bytes(), &entries))
	var entry models.TopologyEntry
	for _, candidate := range entries {
		if candidate.YamlFileName == path {
			entry = candidate
		}
	}
	require.Equal(t, "demo", entry.LabName)
	endpoint := "/labs/" + entry.LabName + "/file"
	read := performWorkspaceRequest(router, http.MethodGet, endpoint+workspacePathQuery(entry.YamlFileName), nil)
	require.Equal(t, http.StatusOK, read.Code, read.Body.String())
	require.Contains(t, read.Body.String(), "name: demo")
	for _, documentPath := range []string{entry.YamlFileName, entry.AnnotationsFileName} {
		content := []byte("{\"name\":\"demo\",\"nodes\":{}}\n")
		put := performWorkspaceRequest(router, http.MethodPut, endpoint+workspacePathQuery(documentPath), content)
		require.Equal(t, http.StatusOK, put.Code, put.Body.String())
		onDisk, err := os.ReadFile(filepath.Join(root, documentPath))
		require.NoError(t, err)
		require.Equal(t, content, onDisk)
		head := performWorkspaceRequest(router, http.MethodHead, endpoint+workspacePathQuery(documentPath), nil)
		require.Equal(t, http.StatusOK, head.Code)
	}
	currentUser, err := user.Current()
	require.NoError(t, err)
	documents, _, err := resolveTopologyDocumentSet(currentUser.Username, entry.LabName, entry.YamlFileName)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(root, entry.YamlFileName), documents.yamlAbsPath)
	require.Equal(t, filepath.Join(root, entry.AnnotationsFileName), documents.annotationsAbsPath)

	tempPath := "repo/labs/.tmp-demo.clab.yaml"
	put := performWorkspaceRequest(router, http.MethodPut, endpoint+workspacePathQuery(tempPath), []byte("name: demo\n"))
	require.Equal(t, http.StatusOK, put.Code, put.Body.String())
	renameBody, err := json.Marshal(models.TopologyFileRenameRequest{OldPath: tempPath, NewPath: path})
	require.NoError(t, err)
	rename := performWorkspaceRequest(router, http.MethodPost, "/labs/demo/rename", renameBody)
	require.Equal(t, http.StatusOK, rename.Code, rename.Body.String())
	deleted := performWorkspaceRequest(router, http.MethodDelete, endpoint+workspacePathQuery(entry.AnnotationsFileName), nil)
	require.Equal(t, http.StatusOK, deleted.Code, deleted.Body.String())
	_, err = os.Stat(filepath.Join(root, entry.AnnotationsFileName))
	require.True(t, os.IsNotExist(err))
}

func TestResolveTopologyPathsPreservesLegacyAndRejectsEscapes(t *testing.T) {
	_, root := workspaceTestRouter(t)
	currentUser, err := user.Current()
	require.NoError(t, err)
	for _, path := range []string{"flat.clab.yml", "demo/demo.clab.yml", "demo/configs/startup.cfg", "repo/labs/nested.clab.yml"} {
		writeTopologyFixture(t, root, path, "name: demo\n")
	}
	for requested, expected := range map[string]string{
		"demo.clab.yml":                              "demo/demo.clab.yml",
		"configs/startup.cfg":                        "demo/configs/startup.cfg",
		"repo/labs/nested.clab.yml":                  "repo/labs/nested.clab.yml",
		"repo/labs/nested.clab.yml.annotations.json": "repo/labs/nested.clab.yml.annotations.json",
	} {
		resolved, _, _, _, err := resolveTopologyFilePath(currentUser.Username, "demo", requested)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(root, expected), resolved)
	}
	resolved, _, _, _, err := resolveTopologyFilePath(currentUser.Username, "flat", "flat.clab.yml")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(root, "flat.clab.yml"), resolved)

	outside := t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "repo", "escape")))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "linked")))
	for _, path := range []string{"../escape.clab.yml", "/tmp/escape.clab.yml", "repo/../../escape.clab.yml", "repo/escape/new.clab.yml", "linked/new.clab.yml"} {
		_, _, _, _, err := resolveTopologyFilePath(currentUser.Username, "demo", path)
		require.Error(t, err, path)
	}
}

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/go-git/go-git/v5/plumbing/transport/file"
	"github.com/stretchr/testify/require"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// Redirect GitHub requests to a local Git repository, exercising real clones
// without network access. Tests using this transport must not run in parallel.
type topologyImportTransport struct {
	transport.Transport
	endpoint *transport.Endpoint
	onClone  func()
}

func (r topologyImportTransport) NewUploadPackSession(_ *transport.Endpoint, auth transport.AuthMethod) (transport.UploadPackSession, error) {
	if r.onClone != nil {
		r.onClone()
	}
	return r.Transport.NewUploadPackSession(r.endpoint, auth)
}

func setupTopologyImportRemote(t *testing.T, onClone func()) {
	t.Helper()
	originDir := t.TempDir()
	origin, err := git.PlainInit(originDir, false)
	require.NoError(t, err)
	files := map[string]string{
		"topology.clab.yml":                  "name: original\ntopology:\n  nodes: {}\n",
		"topology.clab.yml.annotations.json": `{"nodes":{}}`,
		"configs/node.cfg":                   "original config\n",
		"broken.clab.yml/.keep":              "forces a canonical topology write error\n",
	}
	wt, err := origin.Worktree()
	require.NoError(t, err)
	for name, content := range files {
		path := filepath.Join(originDir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0750))
		require.NoError(t, os.WriteFile(path, []byte(content), 0640))
		_, err := wt.Add(name)
		require.NoError(t, err)
	}
	_, err = wt.Commit("Add topology", &git.CommitOptions{Author: &object.Signature{
		Name: "Test", Email: "test@example.invalid", When: time.Now(),
	}})
	require.NoError(t, err)
	endpoint, err := transport.NewEndpoint(originDir)
	require.NoError(t, err)
	previous := client.Protocols["https"]
	client.InstallProtocol("https", topologyImportTransport{file.DefaultClient, endpoint, onClone})
	t.Cleanup(func() { client.InstallProtocol("https", previous) })
}

func topologyImportRouter(t *testing.T, username string) *gin.Engine {
	t.Helper()
	previous := GetClabService()
	SetClabService(clab.NewService())
	t.Cleanup(func() { SetClabService(previous) })
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("username", username) })
	router.POST("/import", ImportTopologyFromURLHandler)
	return router
}

func importTopology(t *testing.T, router *gin.Engine, sourceURL, labName string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(models.ImportTopologyFromURLRequest{TopologySourceUrl: sourceURL})
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPost, "/import?labNameOverride="+labName, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func requireNoImportStagingDirectories(t *testing.T, tempRoot string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(tempRoot, "clab-topology-import-*"))
	require.NoError(t, err)
	require.Empty(t, matches, "import staging directories must be removed")
}

func TestImportTopologyPreservesExistingLab(t *testing.T) {
	for _, storage := range []string{"default", "configured"} {
		t.Run(storage, func(t *testing.T) {
			setupTopologyImportRemote(t, nil)
			usr, err := user.Current()
			require.NoError(t, err)
			labsRoot := ""
			if storage == "configured" {
				labsRoot = t.TempDir()
			}
			setTestClabLabsRoot(t, labsRoot)
			baseDir, err := getUserLabsBaseDirectory(usr.Username)
			require.NoError(t, err)
			_, baseErr := os.Stat(baseDir)
			require.NoError(t, os.MkdirAll(baseDir, 0750))
			if os.IsNotExist(baseErr) {
				t.Cleanup(func() { _ = os.Remove(baseDir) })
			}
			// Reserve unique lab names, including when testing the default home directory.
			firstDir, err := os.MkdirTemp(baseDir, "test-import-")
			require.NoError(t, err)
			require.NoError(t, os.Remove(firstDir))
			firstName := filepath.Base(firstDir)
			secondName := firstName + "-second"
			secondDir := filepath.Join(baseDir, secondName)
			require.NoDirExists(t, secondDir)
			t.Cleanup(func() {
				_ = os.RemoveAll(firstDir)
				_ = os.RemoveAll(secondDir)
			})
			tempRoot := t.TempDir()
			t.Setenv("TMPDIR", tempRoot)
			router := topologyImportRouter(t, usr.Username)
			sourceURL := "https://github.com/test/" + firstName + "/blob/master/topology.clab.yml"

			response := importTopology(t, router, sourceURL, "")
			require.Equal(t, http.StatusOK, response.Code, response.Body.String())
			firstTopology, err := os.ReadFile(filepath.Join(firstDir, firstName+".clab.yml"))
			require.NoError(t, err)
			require.Contains(t, string(firstTopology), "name: "+firstName)
			require.NoError(t, os.WriteFile(filepath.Join(firstDir, "local-only.txt"), []byte("keep me"), 0640))
			requireNoImportStagingDirectories(t, tempRoot)

			response = importTopology(t, router, sourceURL, secondName)
			require.Equal(t, http.StatusOK, response.Code, response.Body.String())
			preserved, err := os.ReadFile(filepath.Join(firstDir, firstName+".clab.yml"))
			require.NoError(t, err, "importing a second lab must preserve the first lab")
			require.Equal(t, firstTopology, preserved)
			require.FileExists(t, filepath.Join(firstDir, "local-only.txt"))
			require.NoFileExists(t, filepath.Join(secondDir, "local-only.txt"), "imports must use a fresh clone")
			secondTopology, err := os.ReadFile(filepath.Join(secondDir, secondName+".clab.yml"))
			require.NoError(t, err)
			require.Contains(t, string(secondTopology), "name: "+secondName)
			annotations, err := os.ReadFile(filepath.Join(secondDir, secondName+".clab.yml.annotations.json"))
			require.NoError(t, err)
			require.JSONEq(t, `{"nodes":{}}`, string(annotations))
			require.FileExists(t, filepath.Join(secondDir, "configs/node.cfg"))
			requireNoImportStagingDirectories(t, tempRoot)

			response = importTopology(t, router, sourceURL, firstName)
			require.Equal(t, http.StatusConflict, response.Code, response.Body.String())
		})
	}
}

func TestImportTopologyCleansStagingAfterFailure(t *testing.T) {
	for _, tc := range []struct{ name, fileName, labName, errorText string }{
		{"missing topology", "missing.clab.yml", "missing", "specified topology file not found"},
		{"canonical write", "topology.clab.yml", "broken", "Failed to write canonical topology file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupTopologyImportRemote(t, nil)
			usr, err := user.Current()
			require.NoError(t, err)
			setTestClabLabsRoot(t, t.TempDir())
			tempRoot := t.TempDir()
			t.Setenv("TMPDIR", tempRoot)
			router := topologyImportRouter(t, usr.Username)
			response := importTopology(t, router, "https://github.com/test/import-fixture/blob/master/"+tc.fileName, tc.labName)
			require.Equal(t, http.StatusInternalServerError, response.Code, response.Body.String())
			require.Contains(t, response.Body.String(), tc.errorText)
			requireNoImportStagingDirectories(t, tempRoot)
		})
	}
}

func TestCloneTopologySourceUsesExplicitDirectoryWithoutChangingCWD(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)
	setupTopologyImportRemote(t, func() {
		got, err := os.Getwd()
		require.NoError(t, err)
		require.Equal(t, cwd, got, "a clone must not change the server's working directory")
	})
	usr, err := user.Current()
	require.NoError(t, err)
	workDir := t.TempDir()
	cloned, err := clab.NewService().CloneTopologySource(clab.CloneTopologySourceOptions{
		SourceURL: "https://github.com/test/import-fixture/blob/master/topology.clab.yml",
		Username:  usr.Username, WorkDir: workDir,
	})
	require.NoError(t, err)
	require.Equal(t, filepath.Join(workDir, "import-fixture"), cloned.RepoDir)
	require.True(t, strings.HasPrefix(cloned.TopologyPath, cloned.RepoDir+string(filepath.Separator)))
	require.FileExists(t, cloned.TopologyPath)
}

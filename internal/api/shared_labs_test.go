package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
	"github.com/stretchr/testify/require"
)

func setTestSharedLabsRoot(t *testing.T, root string) {
	t.Helper()
	previous := config.AppConfig
	config.AppConfig.ClabSharedLabsRoot = root
	config.AppConfig.SuperuserGroup = ""
	t.Cleanup(func() { config.AppConfig = previous })
}

func TestSharedLabAccess(t *testing.T) {
	root := t.TempDir()
	setTestSharedLabsRoot(t, root)
	writeTopologyFixture(t, root, "demo/demo.clab.yml", "name: demo\n")
	require.NoError(t, os.Symlink(t.TempDir(), filepath.Join(root, "escape")))
	require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "missing"), filepath.Join(root, "dangling")))
	for _, tc := range []struct {
		name, path string
		allowed    bool
	}{
		{"shared", filepath.Join(root, "demo/demo.clab.yml"), true},
		{"missing topology", filepath.Join(root, "demo/missing.clab.yml"), true},
		{"private", filepath.Join(t.TempDir(), "private.clab.yml"), false},
		{"prefix collision", root + "-private/demo.clab.yml", false},
		{"relative", "demo.clab.yml", false},
		{"root", root, false},
		{"symlink escape", filepath.Join(root, "escape/private.clab.yml"), false},
		{"dangling symlink", filepath.Join(root, "dangling/private.clab.yml"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := &models.ClabContainerInfo{Owner: "alice", AbsLabPath: tc.path}
			require.Equal(t, tc.allowed, canAccessLab("bob", info))
			require.True(t, canAccessLab("alice", info))
		})
	}
	require.False(t, canAccessLab("bob", nil))
	config.AppConfig.ClabSharedLabsRoot = ""
	require.False(t, canAccessLab("bob", &models.ClabContainerInfo{Owner: "alice", AbsLabPath: filepath.Join(root, "demo/demo.clab.yml")}))
}

func TestSharedWorkspaceAndTopologyFiles(t *testing.T) {
	router, privateRoot := workspaceTestRouter(t)
	sharedRoot := t.TempDir()
	setTestSharedLabsRoot(t, sharedRoot)
	router.GET("/topologies", ListTopologiesHandler)
	router.GET("/labs/:labName/file", GetTopologyFileHandler)
	router.HEAD("/labs/:labName/file", HeadTopologyFileHandler)
	router.PUT("/labs/:labName/file", PutTopologyFileHandler)
	router.DELETE("/labs/:labName/file", DeleteTopologyFileHandler)
	router.POST("/labs/:labName/rename", RenameTopologyFileHandler)

	// The virtual mount is visible even before the user's private workspace exists.
	response := performWorkspaceRequest(router, http.MethodGet, "/tree", nil)
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `"path":"@shared"`)
	response = performWorkspaceRequest(router, http.MethodPost, "/directory", []byte(`{"path":"@shared/demo"}`))
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	path := "@shared/demo/demo.clab.yml"
	endpoint := "/labs/demo/file" + workspacePathQuery(path)
	response = performWorkspaceRequest(router, http.MethodPut, endpoint, []byte("name: demo\n"))
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.FileExists(t, filepath.Join(sharedRoot, "demo/demo.clab.yml"))
	require.NoDirExists(t, privateRoot)

	response = performWorkspaceRequest(router, http.MethodGet, "/tree"+workspacePathQuery("@shared/demo"), nil)
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `"path":"@shared/demo/demo.clab.yml"`)
	response = performWorkspaceRequest(router, http.MethodGet, "/topologies", nil)
	require.Equal(t, http.StatusOK, response.Code)
	var entries []models.TopologyEntry
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &entries))
	require.Len(t, entries, 1)
	require.Equal(t, path, entries[0].YamlFileName)

	for _, route := range []string{endpoint, "/file" + workspacePathQuery(path)} {
		response = performWorkspaceRequest(router, http.MethodGet, route, nil)
		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "name: demo\n", response.Body.String())
	}
	response = performWorkspaceRequest(router, http.MethodHead, endpoint, nil)
	require.Equal(t, http.StatusOK, response.Code)
	require.Empty(t, response.Body.String())
	require.NotEmpty(t, response.Header().Get(topologyRevisionHeader))
	currentUser, err := user.Current()
	require.NoError(t, err)
	docs, _, err := resolveTopologyDocumentSet(currentUser.Username, "demo", path)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(sharedRoot, "demo/demo.clab.yml"), docs.yamlAbsPath)

	response = performWorkspaceRequest(router, http.MethodPost, "/labs/demo/rename", []byte(`{"oldPath":"@shared/demo/demo.clab.yml","newPath":"@shared/demo/renamed.clab.yml"}`))
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	response = performWorkspaceRequest(router, http.MethodDelete, "/labs/demo/file"+workspacePathQuery("@shared/demo/renamed.clab.yml"), nil)
	require.Equal(t, http.StatusOK, response.Code)
	require.NoFileExists(t, filepath.Join(sharedRoot, "demo/renamed.clab.yml"))
}

func TestSharedWorkspaceRejectsEscapesAndCrossWorkspaceMoves(t *testing.T) {
	router, privateRoot := workspaceTestRouter(t)
	root := t.TempDir()
	setTestSharedLabsRoot(t, root)
	writeTopologyFixture(t, privateRoot, "secret.txt", "private")
	writeTopologyFixture(t, root, "demo.clab.yml", "name: demo\n")
	require.NoError(t, os.Symlink(privateRoot, filepath.Join(root, "escape")))
	// Document helpers remain rooted even if a path becomes a symlink after
	// the request's initial authorization check.
	_, err := readLabTopologyDocFile(filepath.Join(root, "escape/secret.txt"))
	require.Error(t, err)
	require.Error(t, writeLabTopologyDocFile(filepath.Join(root, "escape/secret.txt"), "", "demo", []byte("overwritten")))
	currentUser, err := user.Current()
	require.NoError(t, err)
	for _, path := range []string{"@shared/../secret.txt", "@shared/escape/secret.txt", "@shared/escape/new.txt", "x/../@shared/demo.clab.yml"} {
		for _, method := range []string{http.MethodGet, http.MethodPut} {
			response := performWorkspaceRequest(router, method, "/file"+workspacePathQuery(path), []byte("overwritten"))
			require.Equal(t, http.StatusBadRequest, response.Code, "%s %s: %s", method, path, response.Body.String())
		}
		_, _, _, _, err := resolveTopologyFilePath(currentUser.Username, "demo", path)
		require.Error(t, err, path)
	}
	for _, body := range []string{
		`{"oldPath":"@shared/demo.clab.yml","newPath":"private.clab.yml"}`,
		`{"oldPath":"secret.txt","newPath":"@shared/secret.txt"}`,
	} {
		response := performWorkspaceRequest(router, http.MethodPost, "/rename", []byte(body))
		require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
	}
	response := performWorkspaceRequest(router, http.MethodDelete, "/file?recursive=true"+"&path=@shared", nil)
	require.Equal(t, http.StatusBadRequest, response.Code)
	secret, err := os.ReadFile(filepath.Join(privateRoot, "secret.txt"))
	require.NoError(t, err)
	require.Equal(t, "private", string(secret))
	config.AppConfig.ClabSharedLabsRoot = ""
	response = performWorkspaceRequest(router, http.MethodGet, "/tree?path=@shared", nil)
	require.Equal(t, http.StatusBadRequest, response.Code)
}

func TestSharedWorkspaceEvents(t *testing.T) {
	router, _ := workspaceTestRouter(t)
	root := t.TempDir()
	setTestSharedLabsRoot(t, root)
	server := httptest.NewServer(router)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/events", nil)
	require.NoError(t, err)
	response, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	writeTopologyFixture(t, root, "demo.clab.yml", "name: demo\n")
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}
		var event models.WorkspaceFileEventResponse
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &event))
		require.Equal(t, "@shared/demo.clab.yml", event.Path)
		require.Equal(t, "@shared", event.ParentPath)
		return
	}
	t.Fatal("shared workspace event was not delivered")
}

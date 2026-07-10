package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

func setTestClabLabsRoot(t *testing.T, root string) {
	t.Helper()
	previous := config.AppConfig.ClabLabsRoot
	config.AppConfig.ClabLabsRoot = ""
	t.Setenv("CLAB_LABS_ROOT", root)
	t.Cleanup(func() {
		config.AppConfig.ClabLabsRoot = previous
	})
}

func workspaceTestRouter(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	workspaceRoot := filepath.Join(t.TempDir(), "shared")
	setTestClabLabsRoot(t, workspaceRoot)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", currentUser.Username)
		c.Next()
	})
	router.GET("/tree", ListWorkspaceTreeHandler)
	router.GET("/events", StreamWorkspaceEventsHandler)
	router.GET("/file", GetWorkspaceFileHandler)
	router.PUT("/file", PutWorkspaceFileHandler)
	router.DELETE("/file", DeleteWorkspaceFileHandler)
	router.POST("/rename", RenameWorkspaceFileHandler)
	router.POST("/directory", CreateWorkspaceDirectoryHandler)

	return router, filepath.Join(workspaceRoot, currentUser.Username)
}

func TestGetLabDirectoryInfoUsesClabLabsRoot(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	labsRoot := filepath.Join(t.TempDir(), "labs")
	setTestClabLabsRoot(t, labsRoot)

	labDir, _, _, err := getLabDirectoryInfo(currentUser.Username, "demo")
	if err != nil {
		t.Fatalf("getLabDirectoryInfo returned error: %v", err)
	}

	expected := filepath.Join(labsRoot, currentUser.Username, "demo")
	if labDir != expected {
		t.Fatalf("lab dir = %q, want %q", labDir, expected)
	}
}

func TestGetLabDirectoryInfoUsesRootClabLabsRoot(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	setTestClabLabsRoot(t, string(filepath.Separator))

	labDir, _, _, err := getLabDirectoryInfo(currentUser.Username, "demo")
	if err != nil {
		t.Fatalf("getLabDirectoryInfo returned error: %v", err)
	}

	expected := filepath.Join(string(filepath.Separator), currentUser.Username, "demo")
	if labDir != expected {
		t.Fatalf("lab dir = %q, want %q", labDir, expected)
	}
}

func TestEnsureUserLabsBaseDirectoryRejectsClabLabsRootItself(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	labsRoot := filepath.Join(t.TempDir(), "labs")
	setTestClabLabsRoot(t, labsRoot)

	_, uid, gid, err := getUserLabsBaseDirectoryInfo(currentUser.Username)
	if err != nil {
		t.Fatalf("getUserLabsBaseDirectoryInfo returned error: %v", err)
	}

	if err := ensureUserLabsBaseDirectory(labsRoot, uid, gid); err == nil {
		t.Fatal("expected CLAB_LABS_ROOT itself to be rejected as a user labs directory")
	}
}

func TestGetLabDirectoryInfoRejectsRelativeClabLabsRoot(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	setTestClabLabsRoot(t, "relative/labs")

	if _, _, _, err := getLabDirectoryInfo(currentUser.Username, "demo"); err == nil {
		t.Fatal("expected relative CLAB_LABS_ROOT to be rejected")
	}
}

func TestGetLabDirectoryInfoRejectsTildeClabLabsRoot(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	setTestClabLabsRoot(t, "~/labs")

	if _, _, _, err := getLabDirectoryInfo(currentUser.Username, "demo"); err == nil {
		t.Fatal("expected tilde CLAB_LABS_ROOT to be rejected")
	}
}

func TestWorkspaceEventsStreamExternalDelete(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fsnotify event behavior differs on Windows")
	}
	router, workspaceRoot := workspaceTestRouter(t)
	deletedDir := filepath.Join(workspaceRoot, "deleted-outside")
	if err := os.MkdirAll(deletedDir, 0750); err != nil {
		t.Fatalf("mkdir watched dir: %v", err)
	}

	server := httptest.NewServer(router)
	defer server.Close()

	response, err := http.Get(server.URL + "/events")
	if err != nil {
		t.Fatalf("open workspace event stream: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("events status = %d", response.StatusCode)
	}

	reader := bufio.NewReader(response.Body)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read stream prelude: %v", err)
	}

	events := make(chan models.WorkspaceFileEventResponse, 8)
	go func() {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) == "" {
				continue
			}
			var event models.WorkspaceFileEventResponse
			if err := json.Unmarshal([]byte(line), &event); err == nil {
				events <- event
			}
		}
	}()

	if err := os.RemoveAll(deletedDir); err != nil {
		t.Fatalf("external delete: %v", err)
	}

	timeout := time.After(3 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Type == "workspace-file" && event.Path == "deleted-outside" && event.Action == "delete" {
				return
			}
		case <-timeout:
			t.Fatal("timed out waiting for workspace delete event")
		}
	}
}

func performWorkspaceRequest(router http.Handler, method, target string, body []byte) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	router.ServeHTTP(recorder, request)
	return recorder
}

func workspacePathQuery(pathValue string) string {
	return "?path=" + url.QueryEscape(pathValue)
}

func TestWorkspaceFileLifecycle(t *testing.T) {
	router, workspaceRoot := workspaceTestRouter(t)

	put := performWorkspaceRequest(router, http.MethodPut, "/file"+workspacePathQuery("lab1/config.txt"), []byte("hello\n"))
	if put.Code != http.StatusBadRequest {
		t.Fatalf("put before parent directory status = %d, want 400", put.Code)
	}

	mkdirBody := []byte(`{"path":"lab1"}`)
	mkdir := performWorkspaceRequest(router, http.MethodPost, "/directory", mkdirBody)
	if mkdir.Code != http.StatusOK {
		t.Fatalf("mkdir status = %d, body = %s", mkdir.Code, mkdir.Body.String())
	}

	put = performWorkspaceRequest(router, http.MethodPut, "/file"+workspacePathQuery("lab1/config.txt"), []byte("hello\n"))
	if put.Code != http.StatusOK {
		t.Fatalf("put status = %d, body = %s", put.Code, put.Body.String())
	}

	rootTree := performWorkspaceRequest(router, http.MethodGet, "/tree", nil)
	if rootTree.Code != http.StatusOK {
		t.Fatalf("root tree status = %d, body = %s", rootTree.Code, rootTree.Body.String())
	}
	var rootEntries []models.WorkspaceFileEntry
	if err := json.Unmarshal(rootTree.Body.Bytes(), &rootEntries); err != nil {
		t.Fatalf("parse root tree: %v", err)
	}
	if len(rootEntries) != 1 || rootEntries[0].Path != "lab1" || rootEntries[0].Kind != "directory" || !rootEntries[0].HasChildren {
		t.Fatalf("unexpected root entries: %#v", rootEntries)
	}

	labTree := performWorkspaceRequest(router, http.MethodGet, "/tree"+workspacePathQuery("lab1"), nil)
	if labTree.Code != http.StatusOK {
		t.Fatalf("lab tree status = %d, body = %s", labTree.Code, labTree.Body.String())
	}
	var labEntries []models.WorkspaceFileEntry
	if err := json.Unmarshal(labTree.Body.Bytes(), &labEntries); err != nil {
		t.Fatalf("parse lab tree: %v", err)
	}
	if len(labEntries) != 1 || labEntries[0].Path != "lab1/config.txt" || labEntries[0].Kind != "file" {
		t.Fatalf("unexpected lab entries: %#v", labEntries)
	}

	get := performWorkspaceRequest(router, http.MethodGet, "/file"+workspacePathQuery("lab1/config.txt"), nil)
	if get.Code != http.StatusOK || get.Body.String() != "hello\n" {
		t.Fatalf("get status/body = %d/%q", get.Code, get.Body.String())
	}

	renameBody := []byte(`{"oldPath":"lab1/config.txt","newPath":"lab1/config.bak"}`)
	rename := performWorkspaceRequest(router, http.MethodPost, "/rename", renameBody)
	if rename.Code != http.StatusOK {
		t.Fatalf("rename status = %d, body = %s", rename.Code, rename.Body.String())
	}
	if _, err := os.Stat(filepath.Join(workspaceRoot, "lab1", "config.bak")); err != nil {
		t.Fatalf("renamed file missing: %v", err)
	}

	deleteFile := performWorkspaceRequest(router, http.MethodDelete, "/file"+workspacePathQuery("lab1/config.bak"), nil)
	if deleteFile.Code != http.StatusOK {
		t.Fatalf("delete file status = %d, body = %s", deleteFile.Code, deleteFile.Body.String())
	}
	deleteDir := performWorkspaceRequest(router, http.MethodDelete, "/file"+workspacePathQuery("lab1"), nil)
	if deleteDir.Code != http.StatusOK {
		t.Fatalf("delete dir status = %d, body = %s", deleteDir.Code, deleteDir.Body.String())
	}
}

func TestWorkspaceFileRejectsTraversalAndSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on Windows")
	}
	router, workspaceRoot := workspaceTestRouter(t)

	traversal := performWorkspaceRequest(router, http.MethodGet, "/file"+workspacePathQuery("../secret"), nil)
	if traversal.Code != http.StatusBadRequest {
		t.Fatalf("traversal status = %d, want 400", traversal.Code)
	}

	if err := os.MkdirAll(workspaceRoot, 0750); err != nil {
		t.Fatalf("mkdir workspace root: %v", err)
	}
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0640); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(workspaceRoot, "escape.txt")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	readEscape := performWorkspaceRequest(router, http.MethodGet, "/file"+workspacePathQuery("escape.txt"), nil)
	if readEscape.Code != http.StatusBadRequest {
		t.Fatalf("symlink read status = %d, want 400", readEscape.Code)
	}
}

func TestWorkspaceFileBlocksNonEmptyDirectoryDelete(t *testing.T) {
	router, workspaceRoot := workspaceTestRouter(t)

	mkdir := performWorkspaceRequest(router, http.MethodPost, "/directory", []byte(`{"path":"lab1"}`))
	if mkdir.Code != http.StatusOK {
		t.Fatalf("mkdir status = %d, body = %s", mkdir.Code, mkdir.Body.String())
	}
	put := performWorkspaceRequest(router, http.MethodPut, "/file"+workspacePathQuery("lab1/config.txt"), []byte("hello"))
	if put.Code != http.StatusOK {
		t.Fatalf("put status = %d, body = %s", put.Code, put.Body.String())
	}

	deleteDir := performWorkspaceRequest(router, http.MethodDelete, "/file"+workspacePathQuery("lab1"), nil)
	if deleteDir.Code != http.StatusBadRequest {
		t.Fatalf("non-empty dir delete status = %d, want 400", deleteDir.Code)
	}
	if _, err := os.Stat(filepath.Join(workspaceRoot, "lab1", "config.txt")); err != nil {
		t.Fatalf("non-recursive delete removed file: %v", err)
	}

	deleteRecursive := performWorkspaceRequest(router, http.MethodDelete, "/file"+workspacePathQuery("lab1")+"&recursive=true", nil)
	if deleteRecursive.Code != http.StatusOK {
		t.Fatalf("recursive dir delete status = %d, body = %s", deleteRecursive.Code, deleteRecursive.Body.String())
	}
	if _, err := os.Stat(filepath.Join(workspaceRoot, "lab1")); !os.IsNotExist(err) {
		t.Fatalf("recursive delete left directory, stat err = %v", err)
	}
}

func TestWorkspaceManagedTransactionEntriesAreHiddenAndReserved(t *testing.T) {
	router, workspaceRoot := workspaceTestRouter(t)
	backupDir := filepath.Join(workspaceRoot, managedArchiveBackupEntryPrefix+"demo-token")
	stagingDir := filepath.Join(workspaceRoot, managedArchiveEntryPrefix+"demo-token")
	visibleDir := filepath.Join(workspaceRoot, "visible")
	for _, dir := range []string{backupDir, stagingDir, visibleDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("create workspace directory %s: %v", dir, err)
		}
	}
	backupFile := filepath.Join(backupDir, "demo.clab.yml")
	if err := os.WriteFile(backupFile, []byte("name: old\n"), 0o640); err != nil {
		t.Fatalf("write backup marker: %v", err)
	}
	visibleFile := filepath.Join(visibleDir, "demo.clab.yml")
	if err := os.WriteFile(visibleFile, []byte("name: visible\n"), 0o640); err != nil {
		t.Fatalf("write visible topology: %v", err)
	}

	rootTree := performWorkspaceRequest(router, http.MethodGet, "/tree", nil)
	if rootTree.Code != http.StatusOK {
		t.Fatalf("root tree status = %d, body = %s", rootTree.Code, rootTree.Body.String())
	}
	var entries []models.WorkspaceFileEntry
	if err := json.Unmarshal(rootTree.Body.Bytes(), &entries); err != nil {
		t.Fatalf("decode root tree: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "visible" {
		t.Fatalf("managed transaction entries leaked through root listing: %#v", entries)
	}

	reservedBackupPath := managedArchiveBackupEntryPrefix + "demo-token/demo.clab.yml"
	reservedStagingPath := managedArchiveEntryPrefix + "demo-token/new.clab.yml"
	tests := []struct {
		name   string
		method string
		target string
		body   []byte
	}{
		{name: "list", method: http.MethodGet, target: "/tree" + workspacePathQuery(managedArchiveBackupEntryPrefix+"demo-token")},
		{name: "read", method: http.MethodGet, target: "/file" + workspacePathQuery(reservedBackupPath)},
		{name: "write", method: http.MethodPut, target: "/file" + workspacePathQuery(reservedStagingPath), body: []byte("name: changed\n")},
		{name: "delete", method: http.MethodDelete, target: "/file" + workspacePathQuery(managedArchiveBackupEntryPrefix+"demo-token") + "&recursive=true"},
		{name: "create directory", method: http.MethodPost, target: "/directory", body: []byte(`{"path":".archive-demo-token/nested"}`)},
		{name: "rename source", method: http.MethodPost, target: "/rename", body: []byte(`{"oldPath":".backup-demo-token/demo.clab.yml","newPath":"visible/stolen.clab.yml"}`)},
		{name: "rename destination", method: http.MethodPost, target: "/rename", body: []byte(`{"oldPath":"visible/demo.clab.yml","newPath":".backup-demo-token/replaced.clab.yml"}`)},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			response := performWorkspaceRequest(router, testCase.method, testCase.target, testCase.body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("reserved workspace operation status = %d, body = %s; want 400", response.Code, response.Body.String())
			}
		})
	}

	if content, err := os.ReadFile(backupFile); err != nil || string(content) != "name: old\n" {
		t.Fatalf("reserved backup changed through public workspace API: content=%q error=%v", content, err)
	}
	if content, err := os.ReadFile(visibleFile); err != nil || string(content) != "name: visible\n" {
		t.Fatalf("visible rename source changed after rejected destination: content=%q error=%v", content, err)
	}
}

func TestWorkspaceManagedTransactionEventsAreFiltered(t *testing.T) {
	rootPath := t.TempDir()
	backupDir := filepath.Join(rootPath, managedArchiveBackupEntryPrefix+"demo-token")
	stagingDir := filepath.Join(rootPath, managedArchiveEntryPrefix+"demo-token")
	visibleDir := filepath.Join(rootPath, "visible")
	for _, dir := range []string{backupDir, stagingDir, visibleDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("create event test directory %s: %v", dir, err)
		}
	}

	for _, reservedPath := range []string{
		backupDir,
		filepath.Join(backupDir, "demo.clab.yml"),
		stagingDir,
		filepath.Join(stagingDir, "demo.clab.yml"),
	} {
		if _, ok := buildWorkspaceFileEvent(rootPath, reservedPath, fsnotify.Create); ok {
			t.Fatalf("managed transaction event was exposed: %s", reservedPath)
		}
	}
	if event, ok := buildWorkspaceFileEvent(rootPath, visibleDir, fsnotify.Create); !ok || event.Path != "visible" {
		t.Fatalf("visible workspace event was filtered: event=%#v ok=%t", event, ok)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("create watcher: %v", err)
	}
	defer watcher.Close()
	watchedDirs := map[string]struct{}{}
	if err := addWorkspaceWatchDirs(watcher, watchedDirs, rootPath); err != nil {
		t.Fatalf("add workspace watch directories: %v", err)
	}
	if _, watched := watchedDirs[backupDir]; watched {
		t.Fatalf("reserved backup directory was watched: %s", backupDir)
	}
	if _, watched := watchedDirs[stagingDir]; watched {
		t.Fatalf("reserved staging directory was watched: %s", stagingDir)
	}
	if _, watched := watchedDirs[visibleDir]; !watched {
		t.Fatalf("visible workspace directory was not watched: %s", visibleDir)
	}
}

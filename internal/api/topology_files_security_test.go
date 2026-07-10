package api

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
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

	"github.com/gin-gonic/gin"
)

func topologySecurityTestRouter(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	labsRoot := filepath.Join(t.TempDir(), "labs")
	setTestClabLabsRoot(t, labsRoot)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", currentUser.Username)
		c.Next()
	})
	router.GET("/labs/:labName/file", GetTopologyFileHandler)
	router.HEAD("/labs/:labName/file", HeadTopologyFileHandler)
	router.PUT("/labs/:labName/file", PutTopologyFileHandler)
	router.DELETE("/labs/:labName/file", DeleteTopologyFileHandler)
	router.GET("/labs/:labName/yaml", GetRunningLabYamlHandler)
	router.PUT("/labs/:labName/yaml", PutRunningLabYamlHandler)

	return router, filepath.Join(labsRoot, currentUser.Username)
}

func TestRunningTopologyDocumentEndpointsRejectSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on Windows")
	}
	router, workspaceRoot := topologySecurityTestRouter(t)
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	cacheKey := currentUser.Username + "\x00demo"
	labTopologyInfoCache.Store(cacheKey, cachedLabInfo{
		expiresAt: time.Now().Add(time.Minute),
		exists:    false,
	})
	t.Cleanup(func() { labTopologyInfoCache.Delete(cacheKey) })

	labDir := filepath.Join(workspaceRoot, "demo")
	if err := os.MkdirAll(labDir, 0750); err != nil {
		t.Fatalf("mkdir lab: %v", err)
	}
	outsideFile := filepath.Join(t.TempDir(), "outside.clab.yml")
	if err := os.WriteFile(outsideFile, []byte("name: outside\n"), 0640); err != nil {
		t.Fatalf("write outside topology: %v", err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(labDir, "demo.clab.yml")); err != nil {
		t.Fatalf("create topology symlink: %v", err)
	}

	for _, method := range []string{http.MethodGet, http.MethodPut} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(method, "/labs/demo/yaml", bytes.NewBufferString("name: overwritten\n"))
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s running topology symlink status = %d, body = %s; want 400", method, recorder.Code, recorder.Body.String())
		}
	}

	content, err := os.ReadFile(outsideFile)
	if err != nil {
		t.Fatalf("read outside topology: %v", err)
	}
	if string(content) != "name: outside\n" {
		t.Fatalf("outside topology was modified through symlink: %q", content)
	}
}

func TestUIFileHelpersRejectSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on Windows")
	}
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	labsRoot := filepath.Join(t.TempDir(), "labs")
	setTestClabLabsRoot(t, labsRoot)
	workspaceRoot := filepath.Join(labsRoot, currentUser.Username)
	if err := os.MkdirAll(filepath.Join(workspaceRoot, "demo"), 0750); err != nil {
		t.Fatalf("mkdir workspace: %v", err)
	}

	outsideDir := t.TempDir()
	iconsDir := filepath.Join(workspaceRoot, "demo", ".clab-icons")
	if err := os.Symlink(outsideDir, iconsDir); err != nil {
		t.Fatalf("create icons symlink: %v", err)
	}
	_, uid, gid, err := getUserLabsBaseDirectoryInfo(currentUser.Username)
	if err != nil {
		t.Fatalf("resolve user identity: %v", err)
	}
	if err := writeOwnedFile(currentUser.Username, filepath.Join(iconsDir, "escape.svg"), []byte("<svg/>"), uid, gid); err == nil {
		t.Fatal("writeOwnedFile allowed an escaping icons directory symlink")
	}
	if _, err := os.Stat(filepath.Join(outsideDir, "escape.svg")); !os.IsNotExist(err) {
		t.Fatalf("UI file was written outside workspace, stat error: %v", err)
	}
	if _, err := listIconsFromDir(currentUser.Username, iconsDir, "workspace"); err == nil {
		t.Fatal("listIconsFromDir allowed an escaping icons directory symlink")
	}
}

func topologyFileRequest(router http.Handler, method, labName, path string, body []byte) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	requestPath := "/labs/" + labName + "/file?path=" + url.QueryEscape(path)
	request := httptest.NewRequest(method, requestPath, bytes.NewReader(body))
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestTopologyFileEndpointsRejectSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on Windows")
	}
	router, workspaceRoot := topologySecurityTestRouter(t)
	labDir := filepath.Join(workspaceRoot, "demo")
	if err := os.MkdirAll(labDir, 0750); err != nil {
		t.Fatalf("mkdir lab: %v", err)
	}

	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0640); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(labDir, "escape.txt")); err != nil {
		t.Fatalf("create file symlink: %v", err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(labDir, "escape-dir")); err != nil {
		t.Fatalf("create directory symlink: %v", err)
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		response := topologyFileRequest(router, method, "demo", "escape.txt", nil)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s symlink read status = %d, body = %s; want 400", method, response.Code, response.Body.String())
		}
	}

	writeResponse := topologyFileRequest(router, http.MethodPut, "demo", "escape.txt", []byte("overwritten"))
	if writeResponse.Code != http.StatusBadRequest {
		t.Fatalf("PUT file symlink status = %d, body = %s; want 400", writeResponse.Code, writeResponse.Body.String())
	}
	content, err := os.ReadFile(outsideFile)
	if err != nil {
		t.Fatalf("read outside file: %v", err)
	}
	if string(content) != "secret" {
		t.Fatalf("outside file was modified through symlink: %q", content)
	}

	directoryWrite := topologyFileRequest(router, http.MethodPut, "demo", "escape-dir/created.txt", []byte("escape"))
	if directoryWrite.Code != http.StatusBadRequest {
		t.Fatalf("PUT directory symlink status = %d, body = %s; want 400", directoryWrite.Code, directoryWrite.Body.String())
	}
	if _, err := os.Stat(filepath.Join(outsideDir, "created.txt")); !os.IsNotExist(err) {
		t.Fatalf("file was created outside workspace through directory symlink, stat error: %v", err)
	}
}

func TestTopologyFileDeleteRemovesEscapingSymlinkOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on Windows")
	}
	router, workspaceRoot := topologySecurityTestRouter(t)
	labDir := filepath.Join(workspaceRoot, "demo")
	if err := os.MkdirAll(labDir, 0750); err != nil {
		t.Fatalf("mkdir lab: %v", err)
	}

	outsideFile := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0640); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	symlinkPath := filepath.Join(labDir, "escape.txt")
	if err := os.Symlink(outsideFile, symlinkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	response := topologyFileRequest(router, http.MethodDelete, "demo", "escape.txt", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("DELETE symlink status = %d, body = %s; want 200", response.Code, response.Body.String())
	}
	if _, err := os.Lstat(symlinkPath); !os.IsNotExist(err) {
		t.Fatalf("symlink still exists after delete, stat error: %v", err)
	}
	if content, err := os.ReadFile(outsideFile); err != nil || string(content) != "secret" {
		t.Fatalf("outside file changed after deleting symlink: content=%q error=%v", content, err)
	}
}

func TestTopologyFileWriteRejectsSymlinkedLabDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on Windows")
	}
	router, workspaceRoot := topologySecurityTestRouter(t)
	if err := os.MkdirAll(workspaceRoot, 0o750); err != nil {
		t.Fatalf("mkdir workspace: %v", err)
	}
	outsideDir := t.TempDir()
	if err := os.Symlink(outsideDir, filepath.Join(workspaceRoot, "demo")); err != nil {
		t.Fatalf("create lab symlink: %v", err)
	}
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	_, uid, gid, err := getUserLabsBaseDirectoryInfo(currentUser.Username)
	if err != nil {
		t.Fatalf("resolve user identity: %v", err)
	}
	if err := ensureLabDirectory(filepath.Join(workspaceRoot, "demo"), uid, gid); err == nil {
		t.Fatal("ensureLabDirectory accepted a symlinked lab directory")
	}

	response := topologyFileRequest(router, http.MethodPut, "demo", "demo.clab.yml", []byte("name: demo\n"))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("PUT symlinked lab status = %d, body = %s; want 400", response.Code, response.Body.String())
	}
	if _, err := os.Stat(filepath.Join(outsideDir, "demo.clab.yml")); !os.IsNotExist(err) {
		t.Fatalf("topology escaped through symlinked lab directory: %v", err)
	}
}

func TestArchiveExtractionRejectsSpecialAndOversizedEntries(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	_, uid, gid, err := getUserLabsBaseDirectoryInfo(currentUser.Username)
	if err != nil {
		t.Fatalf("resolve user identity: %v", err)
	}

	t.Run("zip symlink", func(t *testing.T) {
		var archive bytes.Buffer
		writer := zip.NewWriter(&archive)
		header := &zip.FileHeader{Name: "escape"}
		header.SetMode(os.ModeSymlink | 0o777)
		entry, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatalf("create zip header: %v", err)
		}
		if _, err := entry.Write([]byte("../outside")); err != nil {
			t.Fatalf("write zip symlink: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close zip: %v", err)
		}

		reader := bytes.NewReader(archive.Bytes())
		if err := extractZip(reader, int64(reader.Len()), t.TempDir(), uid, gid); err == nil {
			t.Fatal("extractZip accepted a symbolic-link entry")
		}
	})

	t.Run("tar symlink", func(t *testing.T) {
		archive := buildTarGzForSecurityTest(t, &tar.Header{
			Name:     "escape",
			Typeflag: tar.TypeSymlink,
			Linkname: "../outside",
			Mode:     0o777,
		})
		if err := extractTarGz(bytes.NewReader(archive), t.TempDir(), uid, gid); err == nil {
			t.Fatal("extractTarGz accepted a symbolic-link entry")
		}
	})

	t.Run("tar uncompressed limit", func(t *testing.T) {
		archive := buildTarGzForSecurityTest(t, &tar.Header{
			Name:     "huge.bin",
			Typeflag: tar.TypeReg,
			Mode:     0o600,
			Size:     maxLabArchiveUncompressedBytes + 1,
		})
		err := extractTarGz(bytes.NewReader(archive), t.TempDir(), uid, gid)
		if !errors.Is(err, errLabArchiveLimit) {
			t.Fatalf("extractTarGz oversized error = %v, want archive limit", err)
		}
	})
}

func TestManagedArchiveTransactionCommitKeepsReplacement(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	labsRoot := filepath.Join(t.TempDir(), "labs")
	setTestClabLabsRoot(t, labsRoot)
	targetDir, uid, gid, err := getLabDirectoryInfo(currentUser.Username, "demo")
	if err != nil {
		t.Fatalf("resolve lab: %v", err)
	}
	if err := ensureLabDirectory(targetDir, uid, gid); err != nil {
		t.Fatalf("ensure old lab: %v", err)
	}
	oldTopology := filepath.Join(targetDir, "demo.clab.yml")
	if err := os.WriteFile(oldTopology, []byte("name: old\n"), 0o640); err != nil {
		t.Fatalf("write old topology: %v", err)
	}

	stagingDir, stagingEntry, _, _, err := createManagedLabStagingDirectory(currentUser.Username, "demo")
	if err != nil {
		t.Fatalf("create replacement staging: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stagingDir, "demo.clab.yml"), []byte("name: new\n"), 0o640); err != nil {
		t.Fatalf("write replacement topology: %v", err)
	}
	transaction, err := beginManagedLabDirectoryTransaction(currentUser.Username, "demo", stagingEntry)
	if err != nil {
		t.Fatalf("begin staging transaction: %v", err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatalf("commit staging transaction: %v", err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatalf("second commit should be idempotent: %v", err)
	}
	if content, err := os.ReadFile(oldTopology); err != nil || string(content) != "name: new\n" {
		t.Fatalf("replacement workspace content=%q error=%v", content, err)
	}
	assertNoManagedArchiveTransactionEntries(t, filepath.Dir(targetDir), "demo")
}

func TestManagedArchiveTransactionDeployFailureRestoresPreviousWorkspace(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	labsRoot := filepath.Join(t.TempDir(), "labs")
	setTestClabLabsRoot(t, labsRoot)
	targetDir, uid, gid, err := getLabDirectoryInfo(currentUser.Username, "demo")
	if err != nil {
		t.Fatalf("resolve lab: %v", err)
	}
	if err := ensureLabDirectory(targetDir, uid, gid); err != nil {
		t.Fatalf("ensure old lab: %v", err)
	}
	oldTopology := filepath.Join(targetDir, "demo.clab.yml")
	if err := os.WriteFile(oldTopology, []byte("name: old\n"), 0o640); err != nil {
		t.Fatalf("write old topology: %v", err)
	}

	stagingDir, stagingEntry, _, _, err := createManagedLabStagingDirectory(currentUser.Username, "demo")
	if err != nil {
		t.Fatalf("create replacement staging: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stagingDir, "demo.clab.yml"), []byte("name: rejected\n"), 0o640); err != nil {
		t.Fatalf("write replacement topology: %v", err)
	}
	transaction, err := beginManagedLabDirectoryTransaction(currentUser.Username, "demo", stagingEntry)
	if err != nil {
		t.Fatalf("begin staging transaction: %v", err)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatalf("rollback staging transaction: %v", err)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatalf("second rollback should be idempotent: %v", err)
	}
	if content, err := os.ReadFile(oldTopology); err != nil || string(content) != "name: old\n" {
		t.Fatalf("previous workspace was not restored: content=%q error=%v", content, err)
	}
	assertNoManagedArchiveTransactionEntries(t, filepath.Dir(targetDir), "demo")
}

func TestManagedArchiveTransactionFirstImportFailureRemovesWorkspace(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	labsRoot := filepath.Join(t.TempDir(), "labs")
	setTestClabLabsRoot(t, labsRoot)
	targetDir, _, _, err := getLabDirectoryInfo(currentUser.Username, "demo")
	if err != nil {
		t.Fatalf("resolve lab: %v", err)
	}

	stagingDir, stagingEntry, _, _, err := createManagedLabStagingDirectory(currentUser.Username, "demo")
	if err != nil {
		t.Fatalf("create initial staging: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stagingDir, "demo.clab.yml"), []byte("name: rejected\n"), 0o640); err != nil {
		t.Fatalf("write staged topology: %v", err)
	}
	transaction, err := beginManagedLabDirectoryTransaction(currentUser.Username, "demo", stagingEntry)
	if err != nil {
		t.Fatalf("begin staging transaction: %v", err)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatalf("rollback first import: %v", err)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatalf("second rollback should be idempotent: %v", err)
	}
	if _, err := os.Lstat(targetDir); !os.IsNotExist(err) {
		t.Fatalf("failed first-import workspace still exists: %v", err)
	}
	assertNoManagedArchiveTransactionEntries(t, filepath.Dir(targetDir), "demo")
}

func assertNoManagedArchiveTransactionEntries(t *testing.T, baseDir, labName string) {
	t.Helper()
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		t.Fatalf("read managed workspace: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".archive-"+labName+"-") ||
			strings.HasPrefix(entry.Name(), ".backup-"+labName+"-") {
			t.Fatalf("managed transaction entry was not cleaned up: %s", entry.Name())
		}
	}
}

func buildTarGzForSecurityTest(t *testing.T, header *tar.Header) []byte {
	t.Helper()
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(header); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if header.Size == 0 {
		if err := tarWriter.Close(); err != nil {
			t.Fatalf("close tar: %v", err)
		}
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return archive.Bytes()
}

package workspace

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/srl-labs/clab-api-server/internal/config"
)

func setLabsRoot(t *testing.T, root string) {
	t.Helper()
	previous := config.AppConfig.ClabLabsRoot
	config.AppConfig.ClabLabsRoot = root
	t.Cleanup(func() { config.AppConfig.ClabLabsRoot = previous })
}

func TestResolveUserStorageDefaultAndConfiguredRoot(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	t.Setenv(LabsRootEnv, "")
	setLabsRoot(t, "")

	storage, err := ResolveUserStorage(current.Username)
	if err != nil {
		t.Fatalf("ResolveUserStorage default: %v", err)
	}
	if want := filepath.Join(current.HomeDir, ".clab"); storage.BaseDir != want {
		t.Fatalf("default base dir = %q, want %q", storage.BaseDir, want)
	}

	configuredRoot := filepath.Join(t.TempDir(), "labs")
	config.AppConfig.ClabLabsRoot = configuredRoot
	storage, err = ResolveUserStorage(current.Username)
	if err != nil {
		t.Fatalf("ResolveUserStorage configured: %v", err)
	}
	if want := filepath.Join(configuredRoot, current.Username); storage.BaseDir != want {
		t.Fatalf("configured base dir = %q, want %q", storage.BaseDir, want)
	}
}

func TestConfiguredLabsRootRejectsRelativeAndTilde(t *testing.T) {
	for _, root := range []string{"relative/labs", "~/labs"} {
		t.Run(root, func(t *testing.T) {
			setLabsRoot(t, root)
			if _, err := ConfiguredLabsRoot(); err == nil {
				t.Fatalf("ConfiguredLabsRoot accepted %q", root)
			}
		})
	}
}

func TestResolveLabDirectoryRejectsTraversalAndNonNames(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	setLabsRoot(t, filepath.Join(t.TempDir(), "labs"))

	for _, labName := range []string{"", ".", "..", "../escape", "/tmp/escape", "nested/lab", `nested\lab`} {
		t.Run(labName, func(t *testing.T) {
			if _, _, err := ResolveLabDirectory(current.Username, labName); err == nil {
				t.Fatalf("ResolveLabDirectory accepted %q", labName)
			}
		})
	}

	targetDir, storage, err := ResolveLabDirectory(current.Username, "demo")
	if err != nil {
		t.Fatalf("ResolveLabDirectory valid name: %v", err)
	}
	if want := filepath.Join(storage.BaseDir, "demo"); targetDir != want {
		t.Fatalf("target dir = %q, want %q", targetDir, want)
	}
}

func TestEnsureUserStorageConfiguredRootModesAndOwnership(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	uid, err := strconv.Atoi(current.Uid)
	if err != nil {
		t.Fatalf("current UID: %v", err)
	}
	gid, err := strconv.Atoi(current.Gid)
	if err != nil {
		t.Fatalf("current GID: %v", err)
	}

	labsRoot := filepath.Join(t.TempDir(), "labs")
	baseDir := filepath.Join(labsRoot, current.Username)
	setLabsRoot(t, labsRoot)
	if err := os.MkdirAll(baseDir, 0o777); err != nil {
		t.Fatalf("create initial workspace: %v", err)
	}
	if err := os.Chmod(labsRoot, 0o700); err != nil {
		t.Fatalf("set initial labs root mode: %v", err)
	}
	if err := os.Chmod(baseDir, 0o777); err != nil {
		t.Fatalf("set initial user base mode: %v", err)
	}

	storage := UserStorage{Username: current.Username, BaseDir: baseDir, UID: uid, GID: gid}
	if err := EnsureUserStorage(storage); err != nil {
		t.Fatalf("EnsureUserStorage: %v", err)
	}

	assertDirectoryMode(t, labsRoot, 0o755)
	assertDirectoryMode(t, baseDir, 0o750)
	info, err := os.Stat(baseDir)
	if err != nil {
		t.Fatalf("stat user base: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("user base stat does not expose Unix ownership")
	}
	if int(stat.Uid) != uid || int(stat.Gid) != gid {
		t.Fatalf("user base ownership = %d:%d, want %d:%d", stat.Uid, stat.Gid, uid, gid)
	}
}

func TestEnsureUserBaseDirectoryRejectsConfiguredRootAndEscape(t *testing.T) {
	labsRoot := filepath.Join(t.TempDir(), "labs")
	setLabsRoot(t, labsRoot)
	for _, baseDir := range []string{labsRoot, filepath.Join(filepath.Dir(labsRoot), "outside")} {
		if err := EnsureUserBaseDirectory(baseDir, os.Getuid(), os.Getgid()); err == nil {
			t.Fatalf("EnsureUserBaseDirectory accepted %q", baseDir)
		}
	}
}

func TestEnsureUserBaseDirectoryDoesNotFollowFinalSymlink(t *testing.T) {
	labsRoot := filepath.Join(t.TempDir(), "labs")
	setLabsRoot(t, labsRoot)
	if err := os.MkdirAll(labsRoot, 0o755); err != nil {
		t.Fatalf("create labs root: %v", err)
	}

	outsideDir := t.TempDir()
	if err := os.Chmod(outsideDir, 0o700); err != nil {
		t.Fatalf("set outside mode: %v", err)
	}
	baseDir := filepath.Join(labsRoot, "attacker")
	if err := os.Symlink(outsideDir, baseDir); err != nil {
		t.Fatalf("create base symlink: %v", err)
	}

	if err := EnsureUserBaseDirectory(baseDir, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("EnsureUserBaseDirectory followed a final symlink")
	}
	assertDirectoryMode(t, outsideDir, 0o700)
}

func assertDirectoryMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode for %s = %04o, want %04o", path, got, want)
	}
}

package clab

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	clabnodes "github.com/srl-labs/containerlab/nodes"
)

type fakeConfigFileSaver struct {
	name string
	path string
}

func (n *fakeConfigFileSaver) GetShortName() string { return n.name }

func (n *fakeConfigFileSaver) SaveConfig(context.Context) (*clabnodes.SaveConfigResult, error) {
	return &clabnodes.SaveConfigResult{ConfigPath: n.path}, nil
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestTimestampedFileName(t *testing.T) {
	ts := time.Date(2026, 2, 6, 23, 59, 0, 0, time.UTC)
	for name, want := range map[string]string{
		"config.json":    "config-260206_235900.json",
		"startup-config": "startup-config-260206_235900",
		"a.b.cfg":        "a.b-260206_235900.cfg",
	} {
		if got := timestampedFileName(name, ts); got != want {
			t.Errorf("timestampedFileName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestCopyLabDirName(t *testing.T) {
	if got, err := copyLabDirName("/work/lab/clab-demo", "demo"); err != nil || got != "clab-demo" {
		t.Fatalf("copyLabDirName = %q, %v", got, err)
	}
	if got, err := copyLabDirName("", "demo"); err != nil || got != "clab-demo" {
		t.Fatalf("copyLabDirName fallback = %q, %v", got, err)
	}
	if _, err := copyLabDirName("", ""); err == nil {
		t.Fatal("expected error without lab dir and name")
	}
}

func TestSaveCopyLayout(t *testing.T) {
	work := t.TempDir()
	labDir := filepath.Join(work, "clab-demo")
	writeTestFile(t, filepath.Join(labDir, "leaf1", "config", "config.json"), `{"leaf":1}`)
	writeTestFile(t, filepath.Join(labDir, "leaf2", "startup-config"), "hostname leaf2\n")

	dstRoot := t.TempDir()
	copier, err := newSaveCopier(OutputDir{Root: dstRoot, Rel: filepath.Join("backups", "nested"), UID: -1, GID: -1}, labDir, "clab-demo")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = copier.Close() }()
	copier.now = func() time.Time { return time.Date(2026, 2, 6, 23, 59, 0, 0, time.UTC) }

	savers := []nodeConfigSaver{
		&fakeConfigFileSaver{name: "leaf1", path: filepath.Join(labDir, "leaf1", "config", "config.json")},
		&fakeConfigFileSaver{name: "leaf2", path: filepath.Join(labDir, "leaf2", "startup-config")},
		&fakeConfigFileSaver{name: "leaf3"}, // no host-visible config
	}
	var mu sync.Mutex
	var copied []string
	err = saveNodeConfigsThen(context.Background(), savers, func(node nodeConfigSaver, result *clabnodes.SaveConfigResult) error {
		mu.Lock()
		copied = append(copied, node.GetShortName())
		mu.Unlock()
		return copier.copy(node.GetShortName(), result)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(copied) != 3 {
		t.Fatalf("afterSave ran for %v, want all three nodes", copied)
	}

	wantDir := filepath.Join(dstRoot, "backups", "nested", "clab-demo")
	if copier.dir() != wantDir {
		t.Fatalf("copier.dir() = %q, want %q", copier.dir(), wantDir)
	}
	for _, tc := range []struct{ node, link, stamped, content string }{
		{"leaf1", "config.json", "config-260206_235900.json", `{"leaf":1}`},
		{"leaf2", "startup-config", "startup-config-260206_235900", "hostname leaf2\n"},
	} {
		nodeDir := filepath.Join(wantDir, tc.node)
		data, err := os.ReadFile(filepath.Join(nodeDir, tc.stamped))
		if err != nil || string(data) != tc.content {
			t.Fatalf("%s copy = %q, %v", tc.node, data, err)
		}
		target, err := os.Readlink(filepath.Join(nodeDir, tc.link))
		if err != nil || target != tc.stamped {
			t.Fatalf("%s link -> %q, %v; want %q", tc.node, target, err, tc.stamped)
		}
	}
	if _, err := os.Stat(filepath.Join(wantDir, "leaf3")); !os.IsNotExist(err) {
		t.Fatalf("node without saved config got a copy directory: %v", err)
	}

	// A second save updates the symlink to the newer copy.
	copier.now = func() time.Time { return time.Date(2026, 2, 7, 0, 0, 1, 0, time.UTC) }
	if err := copier.copy("leaf1", &clabnodes.SaveConfigResult{ConfigPath: filepath.Join(labDir, "leaf1", "config", "config.json")}); err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(filepath.Join(wantDir, "leaf1", "config.json"))
	if err != nil || target != "config-260207_000001.json" {
		t.Fatalf("updated link -> %q, %v", target, err)
	}
	if _, err := os.Stat(filepath.Join(wantDir, "leaf1", "config-260206_235900.json")); err != nil {
		t.Fatalf("older copy removed: %v", err)
	}
}

func TestSaveCopyRejectsSourcesOutsideLabDir(t *testing.T) {
	work := t.TempDir()
	labDir := filepath.Join(work, "clab-demo")
	secret := filepath.Join(t.TempDir(), "secret")
	writeTestFile(t, secret, "secret")
	writeTestFile(t, filepath.Join(work, "outside.cfg"), "outside")
	if err := os.MkdirAll(filepath.Join(labDir, "leaf1"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(labDir, "leaf1", "config.json")); err != nil {
		t.Fatal(err)
	}

	copier, err := newSaveCopier(OutputDir{Root: t.TempDir(), UID: -1, GID: -1}, labDir, "clab-demo")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = copier.Close() }()

	for _, path := range []string{
		filepath.Join(labDir, "leaf1", "config.json"), // symlink escaping the lab dir
		filepath.Join(work, "outside.cfg"),            // outside the lab dir
		filepath.Join(labDir, "..", "outside.cfg"),
	} {
		err := copier.copy("leaf1", &clabnodes.SaveConfigResult{ConfigPath: path})
		if err == nil {
			t.Fatalf("copy of %s succeeded, want rejection", path)
		}
	}
	if err := copier.copy("../leaf1", &clabnodes.SaveConfigResult{ConfigPath: filepath.Join(labDir, "x")}); err == nil {
		t.Fatal("copy with a path-like node name succeeded")
	}
}

func TestSaveCopyDestinationCannotEscapeThroughSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	labDir := filepath.Join(t.TempDir(), "clab-demo")
	if err := os.MkdirAll(labDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := newSaveCopier(OutputDir{Root: root, Rel: "escape", UID: -1, GID: -1}, labDir, "clab-demo"); err == nil {
		t.Fatal("copy destination through an escaping symlink was accepted")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatalf("files were created outside the root: %v", entries)
	}
}

func TestOutputDirValidation(t *testing.T) {
	for _, dir := range []OutputDir{
		{Root: "relative", UID: -1, GID: -1},
		{Root: t.TempDir(), Rel: "../up", UID: -1, GID: -1},
		{Root: t.TempDir(), Rel: "/abs", UID: -1, GID: -1},
	} {
		if root, err := openOutputRoot(dir); err == nil {
			_ = root.Close()
			t.Errorf("openOutputRoot(%+v) succeeded", dir)
		}
	}

	base := t.TempDir()
	writeTestFile(t, filepath.Join(base, "file"), "x")
	if root, err := openOutputRoot(OutputDir{Root: base, Rel: filepath.Join("file", "sub"), UID: -1, GID: -1}); err == nil {
		_ = root.Close()
		t.Fatal("output below a regular file was accepted")
	} else if !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("unexpected error: %v", err)
	}
}

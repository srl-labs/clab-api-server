package clab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	clabconstants "github.com/srl-labs/containerlab/constants"
	clabruntime "github.com/srl-labs/containerlab/runtime"
)

func TestReplaceLabHostsEntriesWritesReplacesAndRemovesBlock(t *testing.T) {
	tempDir := t.TempDir()
	hostsPath := filepath.Join(tempDir, "etc", "hosts")
	lockPath := filepath.Join(tempDir, "run", "lock", "clab-hosts.lock")
	if err := os.MkdirAll(filepath.Dir(hostsPath), 0o755); err != nil {
		t.Fatalf("create hosts directory: %v", err)
	}
	baseline := "127.0.0.1 localhost\n###### CLAB-other-START ######\n192.0.2.1 other\n###### CLAB-other-END ######\n"
	if err := os.WriteFile(hostsPath, []byte(baseline), 0o644); err != nil {
		t.Fatalf("seed hosts file: %v", err)
	}

	containers := []clabruntime.GenericContainer{
		{
			Names:  []string{"clab-demo-leaf1"},
			ID:     "1234567890abcdef",
			Labels: map[string]string{clabconstants.Containerlab: "demo", clabconstants.NodeKind: "cisco_n9kv"},
			NetworkSettings: clabruntime.GenericMgmtIPs{
				IPv4addr: "172.20.20.2",
				IPv6addr: "3fff:172:20:20::2",
			},
		},
	}
	if err := replaceLabHostsEntries(hostsPath, lockPath, "demo", containers); err != nil {
		t.Fatalf("write lab hosts entries: %v", err)
	}

	assertHostsContains(t, hostsPath,
		"###### CLAB-demo-START ######",
		"172.20.20.2\tclab-demo-leaf1 1234567890ab\t# Kind: cisco_n9kv",
		"3fff:172:20:20::2\tclab-demo-leaf1 1234567890ab\t# Kind: cisco_n9kv",
		"###### CLAB-other-START ######",
	)

	containers[0].NetworkSettings.IPv4addr = "172.20.20.9"
	if err := replaceLabHostsEntries(hostsPath, lockPath, "demo", containers); err != nil {
		t.Fatalf("replace lab hosts entries: %v", err)
	}
	content := readHostsFile(t, hostsPath)
	if strings.Contains(content, "172.20.20.2\tclab-demo-leaf1") {
		t.Fatalf("old lab entry remained after replacement:\n%s", content)
	}
	if strings.Count(content, "###### CLAB-demo-START ######") != 1 {
		t.Fatalf("expected one lab block after replacement:\n%s", content)
	}

	if err := removeLabHostsEntries(hostsPath, lockPath, "demo"); err != nil {
		t.Fatalf("remove lab hosts entries: %v", err)
	}
	content = readHostsFile(t, hostsPath)
	if strings.Contains(content, "CLAB-demo") || strings.Contains(content, "clab-demo-leaf1") {
		t.Fatalf("lab entries remained after removal:\n%s", content)
	}
	if !strings.Contains(content, "###### CLAB-other-START ######") {
		t.Fatalf("unrelated lab block was removed:\n%s", content)
	}
}

func TestReplaceLabHostsEntriesRejectsUnterminatedBlock(t *testing.T) {
	tempDir := t.TempDir()
	hostsPath := filepath.Join(tempDir, "hosts")
	lockPath := filepath.Join(tempDir, "hosts.lock")
	original := "127.0.0.1 localhost\n###### CLAB-demo-START ######\n192.0.2.1 broken\n"
	if err := os.WriteFile(hostsPath, []byte(original), 0o644); err != nil {
		t.Fatalf("seed hosts file: %v", err)
	}

	err := replaceLabHostsEntries(hostsPath, lockPath, "demo", nil)
	if err == nil {
		t.Fatal("expected unterminated block error")
	}
	if content := readHostsFile(t, hostsPath); content != original {
		t.Fatalf("hosts file changed after rejected update:\n%s", content)
	}
}

func TestHostsLockPathUsesSameRoot(t *testing.T) {
	got := hostsLockPath("/proc/1/root/etc/hosts")
	want := "/proc/1/root/run/lock/clab-hosts.lock"
	if got != want {
		t.Fatalf("hostsLockPath() = %q, want %q", got, want)
	}
}

func assertHostsContains(t *testing.T, path string, values ...string) {
	t.Helper()
	content := readHostsFile(t, path)
	for _, value := range values {
		if !strings.Contains(content, value) {
			t.Fatalf("hosts file does not contain %q:\n%s", value, content)
		}
	}
}

func readHostsFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read hosts file: %v", err)
	}
	return string(content)
}

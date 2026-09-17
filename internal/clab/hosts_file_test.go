package clab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	clabcore "github.com/srl-labs/containerlab/core"
	clabnodes "github.com/srl-labs/containerlab/nodes"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	clabtypes "github.com/srl-labs/containerlab/types"
)

type hostsTestRuntime struct {
	clabruntime.ContainerRuntime
	containers []clabruntime.GenericContainer
}

func (r *hostsTestRuntime) ListContainers(_ context.Context, filters []*clabtypes.GenericFilter) ([]clabruntime.GenericContainer, error) {
	var result []clabruntime.GenericContainer
	for _, container := range r.containers {
		if len(filters) == 1 && filters[0].FilterType == "name" && slices.Contains(container.Names, filters[0].Match) {
			result = append(result, container)
		}
	}
	return result, nil
}

func TestSyncHostsFilesPreservesDistributedSROSAliases(t *testing.T) {
	dir := t.TempDir()
	topoPath := filepath.Join(dir, "demo.clab.yml")
	topology := `name: demo
topology:
  nodes:
    sros:
      kind: nokia_srsim
      image: example.invalid/srsim:test
      type: sr-7
      components:
        - slot: A
          type: cpm5
        - slot: 1
          type: iom4-e
`
	if err := os.WriteFile(topoPath, []byte(topology), 0600); err != nil {
		t.Fatal(err)
	}
	lab, err := newContainerLab(clabcore.WithTopoPath(topoPath, nil))
	if err != nil {
		t.Fatal(err)
	}
	// Exercise Containerlab's actual SR OS hostname generation without booting a VM.
	lab.Nodes["sros"].WithRuntime(&hostsTestRuntime{containers: []clabruntime.GenericContainer{{
		Names: []string{"clab-demo-sros-1"},
		ID:    "1234567890abcdef",
		NetworkSettings: clabruntime.GenericMgmtIPs{
			IPv4addr: "172.20.20.2",
			IPv6addr: "3fff:172:20:20::2",
		},
	}, {
		Names: []string{"clab-demo-sros-a"},
		ID:    "abcdef1234567890",
	}}})
	entries, err := collectLabHostsEntries(context.Background(), lab.Nodes)
	if err != nil {
		t.Fatal(err)
	}
	localPath := filepath.Join(dir, "local-hosts")
	externalPath := filepath.Join(dir, "host-hosts")
	for _, path := range []string{localPath, externalPath} {
		if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := syncHostsFiles(localPath, externalPath, "demo", entries); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{localPath, externalPath} {
		assertHostsContains(t, path,
			"127.0.0.1 localhost",
			"172.20.20.2\tclab-demo-sros-a ",
			"172.20.20.2\tclab-demo-sros ",
			"3fff:172:20:20::2\tclab-demo-sros-a ",
			"3fff:172:20:20::2\tclab-demo-sros ",
		)
	}
}

type hostsTestNode struct {
	clabnodes.Node
	entries clabtypes.HostEntries
	err     error
}

func (n *hostsTestNode) GetHostsEntries(context.Context) (clabtypes.HostEntries, error) {
	return n.entries, n.err
}

func TestCollectLabHostsEntriesSkipsUndeployedNodes(t *testing.T) {
	entries, err := collectLabHostsEntries(context.Background(), map[string]clabnodes.Node{
		"missing": &hostsTestNode{err: fmt.Errorf("missing: %w", clabnodes.ErrContainersNotFound)},
		"running": &hostsTestNode{entries: clabtypes.HostEntries{
			clabtypes.NewHostEntry("192.0.2.1", "running", clabtypes.IpVersionV4),
		}},
	})
	if err != nil || len(entries) != 1 {
		t.Fatalf("collectLabHostsEntries = %v, %v; want one running node entry", entries, err)
	}
}

func TestCollectLabHostsEntriesReturnsRuntimeErrors(t *testing.T) {
	wantErr := errors.New("runtime unavailable")
	_, err := collectLabHostsEntries(context.Background(), map[string]clabnodes.Node{
		"leaf1": &hostsTestNode{err: wantErr},
	})
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "leaf1") {
		t.Fatalf("collectLabHostsEntries error = %v, want leaf1 runtime error", err)
	}
}

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

	entries := clabtypes.HostEntries{
		clabtypes.NewHostEntry("172.20.20.2", "clab-demo-leaf1", clabtypes.IpVersionV4).
			SetContainerID("1234567890abcdef").SetDescription("Kind: cisco_n9kv"),
		clabtypes.NewHostEntry("3fff:172:20:20::2", "clab-demo-leaf1", clabtypes.IpVersionV6).
			SetContainerID("1234567890abcdef").SetDescription("Kind: cisco_n9kv"),
	}
	if err := replaceLabHostsEntries(hostsPath, lockPath, "demo", entries); err != nil {
		t.Fatalf("write lab hosts entries: %v", err)
	}

	assertHostsContains(t, hostsPath,
		"###### CLAB-demo-START ######",
		"172.20.20.2\tclab-demo-leaf1 1234567890ab\t# Kind: cisco_n9kv",
		"3fff:172:20:20::2\tclab-demo-leaf1 1234567890ab\t# Kind: cisco_n9kv",
		"###### CLAB-other-START ######",
	)

	entries[0] = clabtypes.NewHostEntry("172.20.20.9", "clab-demo-leaf1", clabtypes.IpVersionV4)
	if err := replaceLabHostsEntries(hostsPath, lockPath, "demo", entries); err != nil {
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

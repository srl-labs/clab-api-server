package clab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	clabcore "github.com/srl-labs/containerlab/core"
	clabnodes "github.com/srl-labs/containerlab/nodes"
	clabtypes "github.com/srl-labs/containerlab/types"
	"golang.org/x/sys/unix"

	"github.com/srl-labs/clab-api-server/internal/config"
)

const localHostsFile = "/etc/hosts"

var hostsFileMu sync.Mutex

// collectLabHostsEntries uses node-specific entries, including logical aliases for
// distributed nodes whose management container has a different name.
func collectLabHostsEntries(ctx context.Context, nodes map[string]clabnodes.Node) (clabtypes.HostEntries, error) {
	var entries clabtypes.HostEntries
	for _, name := range slices.Sorted(maps.Keys(nodes)) {
		nodeEntries, err := nodes[name].GetHostsEntries(ctx)
		if errors.Is(err, clabnodes.ErrContainersNotFound) {
			// A topology can include nodes that have not been deployed yet.
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("getting hosts entries for node %q: %w", name, err)
		}
		entries.Merge(nodeEntries)
	}
	return entries, nil
}

func syncLabHostsFiles(ctx context.Context, lab *clabcore.CLab) error {
	entries, err := collectLabHostsEntries(ctx, lab.Nodes)
	if err != nil {
		return err
	}
	return syncHostsFiles(localHostsFile, strings.TrimSpace(config.AppConfig.ClabHostsFile), lab.Config.Name, entries)
}

func syncHostsFiles(localPath, externalPath, labName string, entries clabtypes.HostEntries) error {
	if err := replaceLabHostsEntries(localPath, hostsLockPath(localPath), labName, entries); err != nil {
		return fmt.Errorf("updating local hosts file: %w", err)
	}

	if externalPath == "" || sameFile(localPath, externalPath) {
		return nil
	}

	if err := replaceLabHostsEntries(externalPath, hostsLockPath(externalPath), labName, entries); err != nil {
		return fmt.Errorf("updating configured hosts file %q: %w", externalPath, err)
	}

	return nil
}

func removeLabHostsFiles(labName string) error {
	externalPath := strings.TrimSpace(config.AppConfig.ClabHostsFile)
	if externalPath == "" || sameFile(localHostsFile, externalPath) {
		return nil
	}

	if err := removeLabHostsEntries(externalPath, hostsLockPath(externalPath), labName); err != nil {
		return fmt.Errorf("updating configured hosts file %q: %w", externalPath, err)
	}

	return nil
}

func hostsLockPath(hostsPath string) string {
	cleanPath := filepath.Clean(hostsPath)
	if strings.HasSuffix(cleanPath, string(filepath.Separator)+"etc"+string(filepath.Separator)+"hosts") {
		root := strings.TrimSuffix(cleanPath, string(filepath.Separator)+"etc"+string(filepath.Separator)+"hosts")
		return filepath.Join(root, "run", "lock", "clab-hosts.lock")
	}

	return cleanPath + ".lock"
}

func sameFile(left, right string) bool {
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	return leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo)
}

func replaceLabHostsEntries(
	hostsPath,
	lockPath,
	labName string,
	entries clabtypes.HostEntries,
) error {
	block := buildLabHostsBlock(labName, entries)
	return updateLabHostsEntries(hostsPath, lockPath, labName, block)
}

func removeLabHostsEntries(hostsPath, lockPath, labName string) error {
	return updateLabHostsEntries(hostsPath, lockPath, labName, nil)
}

func updateLabHostsEntries(hostsPath, lockPath, labName string, replacement []byte) error {
	if strings.TrimSpace(labName) == "" {
		return fmt.Errorf("lab name is required")
	}

	return withHostsFileLock(lockPath, func() error {
		file, err := os.OpenFile(hostsPath, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer file.Close()

		current, err := os.ReadFile(hostsPath)
		if err != nil {
			return err
		}

		updated, err := replaceMarkedBlock(current, labName, replacement)
		if err != nil {
			return err
		}

		if bytes.Equal(current, updated) {
			return nil
		}
		if err := file.Truncate(0); err != nil {
			return err
		}
		if _, err := file.Seek(0, 0); err != nil {
			return err
		}
		if _, err := file.Write(updated); err != nil {
			return err
		}

		return file.Sync()
	})
}

func withHostsFileLock(lockPath string, fn func() error) error {
	hostsFileMu.Lock()
	defer hostsFileMu.Unlock()

	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return fmt.Errorf("creating hosts lock directory: %w", err)
	}

	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("opening hosts lock file: %w", err)
	}
	defer lock.Close()

	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("locking hosts file: %w", err)
	}

	return fn()
}

func replaceMarkedBlock(current []byte, labName string, replacement []byte) ([]byte, error) {
	startMarker := fmt.Sprintf("###### CLAB-%s-START ######", labName)
	endMarker := fmt.Sprintf("###### CLAB-%s-END ######", labName)
	lines := strings.SplitAfter(string(current), "\n")

	var output strings.Builder
	inBlock := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case !inBlock && trimmed == startMarker:
			inBlock = true
		case inBlock && trimmed == endMarker:
			inBlock = false
		case !inBlock:
			output.WriteString(line)
		}
	}
	if inBlock {
		return nil, fmt.Errorf("hosts file contains an unterminated block for lab %q", labName)
	}

	if len(replacement) == 0 {
		return []byte(output.String()), nil
	}
	if output.Len() > 0 && !strings.HasSuffix(output.String(), "\n") {
		output.WriteByte('\n')
	}
	output.Write(replacement)

	return []byte(output.String()), nil
}

func buildLabHostsBlock(labName string, entries clabtypes.HostEntries) []byte {
	var block strings.Builder
	fmt.Fprintf(&block, "###### CLAB-%s-START ######\n", labName)
	block.WriteString(entries.ToHostsConfig(clabtypes.IpVersionV4))
	block.WriteString(entries.ToHostsConfig(clabtypes.IpVersionV6))
	fmt.Fprintf(&block, "###### CLAB-%s-END ######\n", labName)

	return []byte(block.String())
}

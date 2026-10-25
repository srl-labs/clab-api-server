package clab

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"golang.org/x/sys/unix"

	"github.com/srl-labs/clab-api-server/internal/config"
)

// DefaultRestoreStagingDir holds the snapshot files that restored nodes mount.
const DefaultRestoreStagingDir = "/var/lib/clab-api-server/restore"

const restoreSnapshotSuffix = ".tar"

// RestoreSnapshot is an opened, checked snapshot file to restore one node from.
type RestoreSnapshot struct {
	Node string
	File *os.File
}

// Restore staging
//
// containerlab bind-mounts a restore snapshot into the node container by path
// when the container is created, long after the API checked that path. A user
// could swap a checked path in their workspace for a symbolic link in between
// and have the server mount any host file. The server therefore opens each
// snapshot once (OpenSnapshotFile), then hard-links that exact inode into
// <staging dir>/<lab>/<node>.tar and hands containerlab only that path. The
// staging directory and its ancestors cannot be changed by API users.
//
// When a hard link is not possible (another filesystem, mount boundary, file
// deleted after it was opened, ...) the opened file is copied instead, which
// uses as much disk space as the snapshot itself. Keep the staging directory on
// the same filesystem and mount as the lab workspaces to avoid copies.
//
// Staged files stay while the lab exists so a node restart still finds them.
// They are replaced by the next restore of the same node and removed when the
// lab (or the node, with a node filter) is destroyed.

type restoreStaging struct {
	dir string
	// link hard-links the opened file to name in dir; replaced in tests.
	link func(src *os.File, dir *os.File, name string) error
}

func newRestoreStaging(dir string) restoreStaging {
	return restoreStaging{dir: filepath.Clean(dir), link: linkOpenFile}
}

func configuredRestoreStaging() restoreStaging {
	dir := strings.TrimSpace(config.AppConfig.ClabRestoreStagingDir)
	if dir == "" {
		dir = DefaultRestoreStagingDir
	}
	return newRestoreStaging(dir)
}

// StageRestoreSnapshots stages the opened snapshots for labName and returns
// containerlab "node=/path" restore entries that point into the staging
// directory. Callers keep ownership of the files.
func StageRestoreSnapshots(labName string, snapshots []RestoreSnapshot) ([]string, error) {
	return configuredRestoreStaging().stage(labName, snapshots)
}

// removeStagedRestoreSnapshots drops staged snapshots of a destroyed lab, or of
// the given nodes only.
func removeStagedRestoreSnapshots(labName string, nodeNames []string) {
	if labName == "" {
		return
	}
	if err := configuredRestoreStaging().remove(labName, nodeNames); err != nil {
		log.Warn("Failed to remove staged restore snapshots", "lab", labName, "error", err)
	}
}

func (s restoreStaging) stage(labName string, snapshots []RestoreSnapshot) ([]string, error) {
	if len(snapshots) == 0 {
		return nil, nil
	}
	if !isPlainName(labName) {
		return nil, fmt.Errorf("invalid lab name %q", labName)
	}
	root, err := s.openRoot(true)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare restore staging directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	if err := root.Mkdir(labName, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("failed to create restore staging directory: %w", err)
	}
	labDir, err := root.Open(labName)
	if err != nil {
		return nil, fmt.Errorf("failed to open restore staging directory: %w", err)
	}
	defer func() { _ = labDir.Close() }()
	if info, err := labDir.Stat(); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("restore staging entry for lab %q is not a directory", labName)
	}

	sorted := slices.Clone(snapshots)
	slices.SortFunc(sorted, func(a, b RestoreSnapshot) int { return strings.Compare(a.Node, b.Node) })
	entries := make([]string, 0, len(sorted))
	for _, snapshot := range sorted {
		if !isPlainName(snapshot.Node) || snapshot.File == nil {
			return nil, fmt.Errorf("invalid restore snapshot for node %q", snapshot.Node)
		}
		if err := s.stageNode(root, labDir, labName, snapshot); err != nil {
			return nil, fmt.Errorf("failed to stage snapshot for node %q: %w", snapshot.Node, err)
		}
		entries = append(entries, snapshot.Node+"="+filepath.Join(s.dir, labName, snapshot.Node+restoreSnapshotSuffix))
	}
	return entries, nil
}

// stageNode places the opened snapshot at <lab>/<node>.tar, replacing an
// earlier one atomically.
func (s restoreStaging) stageNode(root *os.Root, labDir *os.File, labName string, snapshot RestoreSnapshot) error {
	tmpName := fmt.Sprintf(".%s.%d.tmp", snapshot.Node, time.Now().UnixNano())
	tmpRel := filepath.Join(labName, tmpName)
	finalRel := filepath.Join(labName, snapshot.Node+restoreSnapshotSuffix)

	method := "link"
	if linkErr := s.link(snapshot.File, labDir, tmpName); linkErr != nil {
		method = "copy"
		log.Info("Hard link of restore snapshot not possible, copying it",
			"node", snapshot.Node, "source", snapshot.File.Name(), "reason", linkErr)
		if err := copyOpenFile(root, tmpRel, snapshot.File); err != nil {
			return err
		}
	}
	if err := root.Rename(tmpRel, finalRel); err != nil {
		_ = root.Remove(tmpRel)
		return fmt.Errorf("failed to move staged snapshot into place: %w", err)
	}
	// rename does nothing when both names already link the same inode.
	if err := root.Remove(tmpRel); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to remove temporary staged snapshot: %w", err)
	}
	log.Debug("Staged restore snapshot", "lab", labName, "node", snapshot.Node,
		"source", snapshot.File.Name(), "method", method)
	return nil
}

// linkOpenFile hard-links the inode behind src as name in dir. Linking through
// /proc/self/fd uses the opened file, not a path a user could change.
func linkOpenFile(src *os.File, dir *os.File, name string) error {
	return unix.Linkat(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fd/%d", src.Fd()),
		int(dir.Fd()), name, unix.AT_SYMLINK_FOLLOW)
}

// copyOpenFile copies the opened file, up to its size when the copy starts, to
// rel below root.
func copyOpenFile(root *os.Root, rel string, src *os.File) error {
	info, err := src.Stat()
	if err != nil {
		return fmt.Errorf("failed to inspect snapshot: %w", err)
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to read snapshot: %w", err)
	}
	dst, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create staged snapshot: %w", err)
	}
	if _, err := io.CopyN(dst, src, info.Size()); err != nil {
		_ = dst.Close()
		_ = root.Remove(rel)
		return fmt.Errorf("failed to copy snapshot: %w", err)
	}
	if err := dst.Close(); err != nil {
		_ = root.Remove(rel)
		return fmt.Errorf("failed to write staged snapshot: %w", err)
	}
	return nil
}

func (s restoreStaging) remove(labName string, nodeNames []string) error {
	if !isPlainName(labName) {
		return fmt.Errorf("invalid lab name %q", labName)
	}
	root, err := s.openRoot(false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	if len(nodeNames) == 0 {
		return root.RemoveAll(labName)
	}
	for _, node := range nodeNames {
		if !isPlainName(node) {
			continue
		}
		rel := filepath.Join(labName, node+restoreSnapshotSuffix)
		if err := root.Remove(rel); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	// Drop the lab directory once its last snapshot is gone.
	if err := root.Remove(labName); err != nil && !errors.Is(err, fs.ErrNotExist) &&
		!errors.Is(err, unix.ENOTEMPTY) && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return nil
}

// openRoot opens the staging directory, creating it (mode 0700) when create is
// set. Only symbolic links that root alone can change are followed, every
// ancestor must be owned by root or
// the server account and must not be writable by others unless it is sticky,
// and the directory itself must be owned by the server account.
func (s restoreStaging) openRoot(create bool) (*os.Root, error) {
	euid := os.Geteuid()
	trusted := func(dir string, fd int) error {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return &os.PathError{Op: "stat", Path: dir, Err: err}
		}
		if st.Uid != 0 && int(st.Uid) != euid {
			return fmt.Errorf("%s must be owned by root", dir)
		}
		if st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0 {
			return fmt.Errorf("%s must not be writable by other users", dir)
		}
		return nil
	}
	var missing func(int, string) error
	if create {
		missing = func(parentFd int, name string) error {
			if err := unix.Mkdirat(parentFd, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
				return &os.PathError{Op: "mkdir", Path: name, Err: err}
			}
			return nil
		}
	}

	fd, err := walkNoFollow(s.dir, unix.O_RDONLY|unix.O_DIRECTORY, trusted, missing)
	if errors.Is(err, unix.ENOENT) && create {
		if mkErr := s.mkdirLast(trusted); mkErr != nil {
			return nil, mkErr
		}
		fd, err = walkNoFollow(s.dir, unix.O_RDONLY|unix.O_DIRECTORY, trusted, nil)
	}
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, fs.ErrNotExist
		}
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), s.dir)
	defer func() { _ = dir.Close() }()

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, &os.PathError{Op: "stat", Path: s.dir, Err: err}
	}
	if int(st.Uid) != euid {
		return nil, fmt.Errorf("%s must be owned by the server account", s.dir)
	}
	if st.Mode&0o777 != 0o700 {
		if err := unix.Fchmod(fd, 0o700); err != nil {
			return nil, &os.PathError{Op: "chmod", Path: s.dir, Err: err}
		}
	}
	return os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", dir.Fd()))
}

// mkdirLast creates the last component of the staging directory below its
// already existing, trusted parent.
func (s restoreStaging) mkdirLast(trusted func(string, int) error) error {
	parent := filepath.Dir(s.dir)
	fd, err := walkNoFollow(parent, unix.O_RDONLY|unix.O_DIRECTORY, trusted, nil)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := trusted(parent, fd); err != nil {
		return err
	}
	if err := unix.Mkdirat(fd, filepath.Base(s.dir), 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return &os.PathError{Op: "mkdir", Path: s.dir, Err: err}
	}
	return nil
}

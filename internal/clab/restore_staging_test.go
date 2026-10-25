package clab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func currentReader() FileReader {
	return FileReader{UID: os.Getuid(), GIDs: []int{os.Getgid()}}
}

// privateTempDir returns a temporary directory that, like its parent, only the
// test account can write to, independent of the umask.
func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, path := range []string{filepath.Dir(dir), dir} {
		require.NoError(t, os.Chmod(path, 0o700))
	}
	return dir
}

func newTestStaging(t *testing.T) restoreStaging {
	t.Helper()
	return newRestoreStaging(filepath.Join(privateTempDir(t), "state", "restore"))
}

func openTestSnapshot(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := OpenSnapshotFile(path, currentReader())
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func stagedPath(staging restoreStaging, lab, node string) string {
	return filepath.Join(staging.dir, lab, node+restoreSnapshotSuffix)
}

func requireNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, entry := range entries {
		require.False(t, strings.HasPrefix(entry.Name(), "."), "leftover temporary file %s", entry.Name())
	}
}

func TestStageRestoreSnapshotPinsOpenedFile(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "shadow")
	require.NoError(t, os.WriteFile(secret, []byte("secret"), 0o600))
	snapshot := filepath.Join(workspace, "r1.tar")
	require.NoError(t, os.WriteFile(snapshot, []byte("snapshot"), 0o640))

	file := openTestSnapshot(t, snapshot)
	// Swap the checked path for a symlink after it was opened.
	require.NoError(t, os.Rename(snapshot, snapshot+".old"))
	require.NoError(t, os.Symlink(secret, snapshot))

	staging := newTestStaging(t)
	entries, err := staging.stage("lab1", []RestoreSnapshot{{Node: "r1", File: file}})
	require.NoError(t, err)
	staged := stagedPath(staging, "lab1", "r1")
	require.Equal(t, []string{"r1=" + staged}, entries)

	content, err := os.ReadFile(staged)
	require.NoError(t, err)
	require.Equal(t, "snapshot", string(content))
	info, err := os.Lstat(staged)
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular())
	opened, err := file.Stat()
	require.NoError(t, err)
	require.True(t, os.SameFile(opened, info), "staged file should be a hard link to the opened inode")

	for _, dir := range []string{staging.dir, filepath.Dir(staged)} {
		info, err := os.Stat(dir)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o700), info.Mode().Perm(), dir)
	}
	requireNoTempFiles(t, filepath.Dir(staged))
}

func TestStageRestoreSnapshotFallsBackToCopy(t *testing.T) {
	workspace := t.TempDir()
	snapshot := filepath.Join(workspace, "r1.tar")
	require.NoError(t, os.WriteFile(snapshot, []byte("snapshot-data"), 0o640))
	file := openTestSnapshot(t, snapshot)

	staging := newTestStaging(t)
	staging.link = func(*os.File, *os.File, string) error { return unix.EXDEV }
	_, err := staging.stage("lab1", []RestoreSnapshot{{Node: "r1", File: file}})
	require.NoError(t, err)

	staged := stagedPath(staging, "lab1", "r1")
	content, err := os.ReadFile(staged)
	require.NoError(t, err)
	require.Equal(t, "snapshot-data", string(content))
	info, err := os.Stat(staged)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	opened, err := file.Stat()
	require.NoError(t, err)
	require.False(t, os.SameFile(opened, info))

	// Changing the source afterwards does not change the staged copy.
	require.NoError(t, os.WriteFile(snapshot, []byte("changed"), 0o640))
	content, err = os.ReadFile(staged)
	require.NoError(t, err)
	require.Equal(t, "snapshot-data", string(content))
	requireNoTempFiles(t, filepath.Dir(staged))
}

func TestStageRestoreSnapshotCopiesDeletedSource(t *testing.T) {
	workspace := t.TempDir()
	snapshot := filepath.Join(workspace, "r1.tar")
	require.NoError(t, os.WriteFile(snapshot, []byte("snapshot"), 0o640))
	file := openTestSnapshot(t, snapshot)
	// A file unlinked after it was opened cannot be hard-linked again.
	require.NoError(t, os.Remove(snapshot))

	staging := newTestStaging(t)
	_, err := staging.stage("lab1", []RestoreSnapshot{{Node: "r1", File: file}})
	require.NoError(t, err)
	staged := stagedPath(staging, "lab1", "r1")
	content, err := os.ReadFile(staged)
	require.NoError(t, err)
	require.Equal(t, "snapshot", string(content))
	info, err := os.Stat(staged)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "expected a copy")
}

func TestStageRestoreSnapshotReplacesEarlierOne(t *testing.T) {
	workspace := t.TempDir()
	first := filepath.Join(workspace, "first.tar")
	second := filepath.Join(workspace, "second.tar")
	require.NoError(t, os.WriteFile(first, []byte("first"), 0o640))
	require.NoError(t, os.WriteFile(second, []byte("second"), 0o640))
	staging := newTestStaging(t)

	_, err := staging.stage("lab1", []RestoreSnapshot{{Node: "r1", File: openTestSnapshot(t, first)}})
	require.NoError(t, err)
	// Staging the same inode again must not leave the temporary link behind.
	_, err = staging.stage("lab1", []RestoreSnapshot{{Node: "r1", File: openTestSnapshot(t, first)}})
	require.NoError(t, err)
	requireNoTempFiles(t, filepath.Join(staging.dir, "lab1"))

	_, err = staging.stage("lab1", []RestoreSnapshot{{Node: "r1", File: openTestSnapshot(t, second)}})
	require.NoError(t, err)
	content, err := os.ReadFile(stagedPath(staging, "lab1", "r1"))
	require.NoError(t, err)
	require.Equal(t, "second", string(content))
	requireNoTempFiles(t, filepath.Join(staging.dir, "lab1"))
}

func TestStageRestoreSnapshotsRejectsInvalidNames(t *testing.T) {
	workspace := t.TempDir()
	snapshot := filepath.Join(workspace, "r1.tar")
	require.NoError(t, os.WriteFile(snapshot, []byte("x"), 0o640))
	staging := newTestStaging(t)

	_, err := staging.stage("../lab", []RestoreSnapshot{{Node: "r1", File: openTestSnapshot(t, snapshot)}})
	require.Error(t, err)
	_, err = staging.stage("lab1", []RestoreSnapshot{{Node: "../r1", File: openTestSnapshot(t, snapshot)}})
	require.Error(t, err)
}

func TestRemoveStagedRestoreSnapshots(t *testing.T) {
	workspace := t.TempDir()
	snapshot := filepath.Join(workspace, "r1.tar")
	require.NoError(t, os.WriteFile(snapshot, []byte("x"), 0o640))
	staging := newTestStaging(t)

	// Nothing staged yet: removal is a no-op and does not create the directory.
	require.NoError(t, staging.remove("lab1", nil))
	_, err := os.Stat(staging.dir)
	require.True(t, os.IsNotExist(err))

	stageBoth := func() {
		_, err := staging.stage("lab1", []RestoreSnapshot{
			{Node: "r1", File: openTestSnapshot(t, snapshot)},
			{Node: "r2", File: openTestSnapshot(t, snapshot)},
		})
		require.NoError(t, err)
	}

	stageBoth()
	require.NoError(t, staging.remove("lab1", []string{"r1"}))
	_, err = os.Stat(stagedPath(staging, "lab1", "r1"))
	require.True(t, os.IsNotExist(err))
	_, err = os.Stat(stagedPath(staging, "lab1", "r2"))
	require.NoError(t, err)

	require.NoError(t, staging.remove("lab1", []string{"r2"}))
	_, err = os.Stat(filepath.Join(staging.dir, "lab1"))
	require.True(t, os.IsNotExist(err), "empty lab directory should be removed")

	stageBoth()
	require.NoError(t, staging.remove("lab1", nil))
	_, err = os.Stat(filepath.Join(staging.dir, "lab1"))
	require.True(t, os.IsNotExist(err))
	// The source snapshot is untouched.
	_, err = os.Stat(snapshot)
	require.NoError(t, err)
}

func TestRestoreStagingRootMustBeTrusted(t *testing.T) {
	base := privateTempDir(t)
	snapshot := filepath.Join(base, "r1.tar")
	require.NoError(t, os.WriteFile(snapshot, []byte("x"), 0o640))

	// A symlinked staging directory is rejected.
	target := filepath.Join(base, "target")
	require.NoError(t, os.Mkdir(target, 0o700))
	require.NoError(t, os.Symlink(target, filepath.Join(base, "link")))
	_, err := newRestoreStaging(filepath.Join(base, "link")).stage("lab1",
		[]RestoreSnapshot{{Node: "r1", File: openTestSnapshot(t, snapshot)}})
	require.Error(t, err)

	// So is one below a directory other users can write to.
	open := filepath.Join(base, "open")
	require.NoError(t, os.Mkdir(open, 0o700))
	require.NoError(t, os.Chmod(open, 0o777))
	_, err = newRestoreStaging(filepath.Join(open, "restore")).stage("lab1",
		[]RestoreSnapshot{{Node: "r1", File: openTestSnapshot(t, snapshot)}})
	require.Error(t, err)

	// An existing staging directory is tightened to 0700.
	loose := filepath.Join(base, "loose")
	require.NoError(t, os.Mkdir(loose, 0o700))
	require.NoError(t, os.Chmod(loose, 0o755))
	_, err = newRestoreStaging(loose).stage("lab1",
		[]RestoreSnapshot{{Node: "r1", File: openTestSnapshot(t, snapshot)}})
	require.NoError(t, err)
	info, err := os.Stat(loose)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), info.Mode().Perm())
}

func TestOpenSnapshotFileRejectsLinksAndSpecialFiles(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "shadow")
	require.NoError(t, os.WriteFile(secret, []byte("secret"), 0o600))

	// Final component is a symlink.
	require.NoError(t, os.Symlink(secret, filepath.Join(workspace, "link.tar")))
	_, err := OpenSnapshotFile(filepath.Join(workspace, "link.tar"), currentReader())
	require.ErrorIs(t, err, errPathChanged)

	// A directory component was swapped for a symlink to a directory holding
	// a file with the expected name.
	require.NoError(t, os.WriteFile(filepath.Join(outside, "r1.tar"), []byte("other"), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(workspace, "snapshots")))
	_, err = OpenSnapshotFile(filepath.Join(workspace, "snapshots", "r1.tar"), currentReader())
	require.ErrorIs(t, err, errPathChanged)

	// Not a regular file; a FIFO must not block the open.
	fifo := filepath.Join(workspace, "fifo.tar")
	require.NoError(t, unix.Mkfifo(fifo, 0o600))
	_, err = OpenSnapshotFile(fifo, currentReader())
	require.ErrorContains(t, err, "not a regular file")
	_, err = OpenSnapshotFile(workspace, currentReader())
	require.ErrorContains(t, err, "not a regular file")

	_, err = OpenSnapshotFile(filepath.Join(workspace, "missing.tar"), currentReader())
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = OpenSnapshotFile("relative.tar", currentReader())
	require.Error(t, err)
}

func TestOpenSnapshotFileChecksReader(t *testing.T) {
	workspace := t.TempDir()
	path := filepath.Join(workspace, "r1.tar")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
	stranger := FileReader{UID: os.Getuid() + 4242, GIDs: []int{os.Getgid() + 4242}}

	_, err := OpenSnapshotFile(path, stranger)
	require.ErrorContains(t, err, "not readable")

	require.NoError(t, os.Chmod(path, 0o640))
	_, err = OpenSnapshotFile(path, stranger)
	require.ErrorContains(t, err, "not readable")
	groupMember := FileReader{UID: stranger.UID, GIDs: []int{os.Getgid()}}
	file, err := OpenSnapshotFile(path, groupMember)
	require.NoError(t, err)
	_ = file.Close()

	require.NoError(t, os.Chmod(path, 0o604))
	file, err = OpenSnapshotFile(path, stranger)
	require.NoError(t, err)
	_ = file.Close()

	require.NoError(t, os.Chmod(path, 0o600))
	file, err = OpenSnapshotFile(path, FileReader{UID: -1})
	require.NoError(t, err)
	_ = file.Close()
}

func TestOpenOutputRootRejectsSwappedRoot(t *testing.T) {
	parent := t.TempDir()
	outside := t.TempDir()
	root := filepath.Join(parent, "workspace")
	require.NoError(t, os.Mkdir(root, 0o750))

	// The checked workspace root is replaced by a symlink before the write.
	require.NoError(t, os.Rename(root, root+".old"))
	require.NoError(t, os.Symlink(outside, root))
	_, err := openOutputRoot(OutputDir{Root: root, Rel: "snapshots", UID: -1, GID: -1})
	require.ErrorIs(t, err, errPathChanged)
	entries, err := os.ReadDir(outside)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestWalkFollowsOnlyTrustedLinks(t *testing.T) {
	// Links that only root can replace are followed; /proc/self is one on Linux
	// and lives in the root-owned, non-writable /proc.
	fd, err := walkNoFollow("/proc/self/status", unix.O_RDONLY, nil, nil)
	require.NoError(t, err)
	require.NoError(t, unix.Close(fd))
}

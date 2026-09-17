package clab

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChownTreePreservesSymlinkTargets(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to transfer ownership to another UID/GID")
	}
	root := t.TempDir()
	tree := filepath.Join(root, "clone")
	file := filepath.Join(tree, "configs/node.cfg")
	require.NoError(t, os.MkdirAll(filepath.Dir(file), 0750))
	require.NoError(t, os.WriteFile(file, []byte("config"), 0640))
	outsideDir := filepath.Join(root, "outside")
	require.NoError(t, os.Mkdir(outsideDir, 0750))
	outsideFile := filepath.Join(outsideDir, "keep.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("keep"), 0640))
	fileLink := filepath.Join(tree, "file-link")
	dirLink := filepath.Join(tree, "dir-link")
	danglingLink := filepath.Join(tree, "dangling-link")
	require.NoError(t, os.Symlink(outsideFile, fileLink))
	require.NoError(t, os.Symlink(outsideDir, dirLink))
	require.NoError(t, os.Symlink(filepath.Join(root, "missing"), danglingLink))

	const uid, gid = 65534, 65534
	require.NoError(t, chownTree(tree, uid, gid))
	for _, path := range []string{tree, filepath.Dir(file), file, fileLink, dirLink, danglingLink} {
		info, err := os.Lstat(path)
		require.NoError(t, err)
		stat := info.Sys().(*syscall.Stat_t)
		require.EqualValues(t, uid, stat.Uid, path)
		require.EqualValues(t, gid, stat.Gid, path)
	}
	for _, path := range []string{outsideDir, outsideFile} {
		info, err := os.Stat(path)
		require.NoError(t, err)
		stat := info.Sys().(*syscall.Stat_t)
		require.Zero(t, stat.Uid, "symlink target owner must be preserved: %s", path)
		require.EqualValues(t, os.Getegid(), stat.Gid, path)
	}
}

package clab

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// errPathChanged is returned when a component of a path that was resolved
// earlier is now a symbolic link or not a directory.
var errPathChanged = errors.New("path contains a symbolic link or changed while it was opened")

const walkDirFlags = unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// pathComponents splits an absolute path into its cleaned components.
func pathComponents(path string) ([]string, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return nil, fmt.Errorf("%q is not a valid absolute path", path)
	}
	rel := strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator))
	if rel == "" {
		return nil, nil
	}
	return strings.Split(rel, string(filepath.Separator)), nil
}

// maxTrustedLinkHops bounds how many trusted symbolic links a walk follows.
const maxTrustedLinkHops = 40

// walkNoFollow opens path one component at a time relative to the previous
// one. Symbolic links are only followed when the directory holding them can be
// changed by root alone (root-owned, not writable by group or others), such as
// an administrator's /home -> /data/home. Any other link fails the walk:
// callers pass symlink-resolved paths, so such a link means the path was
// swapped after it was checked. Directories are opened with walkDirFlags and
// the last component with lastFlags. visitDir, when set, runs for every
// directory walked through (not for the last component); missing, when set, is
// called for a missing directory component and may create it.
func walkNoFollow(
	path string,
	lastFlags int,
	visitDir func(dir string, fd int) error,
	missing func(parentFd int, name string) error,
) (int, error) {
	for hops := 0; ; hops++ {
		if hops > maxTrustedLinkHops {
			return -1, &os.PathError{Op: "open", Path: path, Err: unix.ELOOP}
		}
		fd, next, err := walkOnce(path, lastFlags, visitDir, missing)
		if next == "" {
			return fd, err
		}
		path = next
	}
}

// walkOnce walks path. When it meets a trusted symbolic link it returns the
// path with that link replaced by its target, to be walked again from "/".
func walkOnce(
	path string,
	lastFlags int,
	visitDir func(dir string, fd int) error,
	missing func(parentFd int, name string) error,
) (int, string, error) {
	parts, err := pathComponents(path)
	if err != nil {
		return -1, "", err
	}
	if len(parts) == 0 {
		return -1, "", fmt.Errorf("refusing to open the filesystem root")
	}
	fd, err := unix.Open(string(filepath.Separator), walkDirFlags, 0)
	if err != nil {
		return -1, "", &os.PathError{Op: "open", Path: string(filepath.Separator), Err: err}
	}
	current := string(filepath.Separator)
	for idx, part := range parts {
		if visitDir != nil {
			if err := visitDir(current, fd); err != nil {
				_ = unix.Close(fd)
				return -1, "", err
			}
		}
		flags := walkDirFlags
		last := idx == len(parts)-1
		if last {
			flags = lastFlags | unix.O_NOFOLLOW | unix.O_CLOEXEC
		}
		next, openErr := unix.Openat(fd, part, flags, 0)
		if errors.Is(openErr, unix.ENOENT) && !last && missing != nil {
			if err := missing(fd, part); err != nil {
				_ = unix.Close(fd)
				return -1, "", err
			}
			next, openErr = unix.Openat(fd, part, flags, 0)
		}
		if errors.Is(openErr, unix.ELOOP) || errors.Is(openErr, unix.ENOTDIR) {
			if target, ok := trustedLinkTarget(fd, part); ok {
				_ = unix.Close(fd)
				if !filepath.IsAbs(target) {
					target = filepath.Join(current, target)
				}
				return -1, filepath.Join(append([]string{target}, parts[idx+1:]...)...), nil
			}
		}
		_ = unix.Close(fd)
		current = filepath.Join(current, part)
		if openErr != nil {
			if errors.Is(openErr, unix.ELOOP) || errors.Is(openErr, unix.ENOTDIR) {
				return -1, "", &os.PathError{Op: "open", Path: current, Err: errPathChanged}
			}
			return -1, "", &os.PathError{Op: "open", Path: current, Err: openErr}
		}
		fd = next
	}
	return fd, "", nil
}

// trustedLinkTarget returns the target of the symbolic link name in dirFd when
// only root can replace that link.
func trustedLinkTarget(dirFd int, name string) (string, bool) {
	var link unix.Stat_t
	if err := unix.Fstatat(dirFd, name, &link, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return "", false
	}
	if link.Mode&unix.S_IFMT != unix.S_IFLNK {
		return "", false
	}
	var dir unix.Stat_t
	if err := unix.Fstat(dirFd, &dir); err != nil {
		return "", false
	}
	if dir.Uid != 0 || dir.Mode&0o022 != 0 {
		return "", false
	}
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(dirFd, name, buf)
	if err != nil || n <= 0 || n >= len(buf) {
		return "", false
	}
	return string(buf[:n]), true
}

// openDirNoFollow opens an existing absolute directory without following
// symbolic links in any component.
func openDirNoFollow(path string) (*os.File, error) {
	fd, err := walkNoFollow(path, unix.O_RDONLY|unix.O_DIRECTORY, nil, nil)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), filepath.Clean(path)), nil
}

// openRootNoFollow opens path as an os.Root without following symbolic links in
// any component of path itself. os.OpenRoot alone resolves links in the root
// path, so a user who can rename a parent directory could otherwise point the
// root somewhere else between validation and use.
func openRootNoFollow(path string) (*os.Root, error) {
	dir, err := openDirNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	return os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", dir.Fd()))
}

// FileReader identifies the account a file is opened on behalf of. A negative
// UID skips the access check, for files in server-managed locations.
type FileReader struct {
	UID  int
	GIDs []int
}

// canRead reports whether the account owns the file or may read it through its
// group or other permission bits.
func (r FileReader) canRead(st *unix.Stat_t) bool {
	if r.UID < 0 || int(st.Uid) == r.UID {
		return true
	}
	if st.Mode&0o004 != 0 {
		return true
	}
	if st.Mode&0o040 != 0 {
		for _, gid := range r.GIDs {
			if int(st.Gid) == gid {
				return true
			}
		}
	}
	return false
}

// OpenSnapshotFile opens a symlink-resolved snapshot path for reading. No
// component may be a symbolic link, the file must be a regular file and reader
// must own it or be allowed to read it. The returned file pins the inode that
// was checked, so later changes to the path do not change what is read.
func OpenSnapshotFile(path string, reader FileReader) (*os.File, error) {
	fd, err := walkNoFollow(path, unix.O_RDONLY|unix.O_NONBLOCK, nil, nil)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, fmt.Errorf("snapshot file does not exist: %w", fs.ErrNotExist)
		}
		return nil, fmt.Errorf("failed to open snapshot file: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed to inspect snapshot file: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("snapshot is not a regular file")
	}
	if !reader.canRead(&st) {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("snapshot file is not readable by you")
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed to open snapshot file: %w", err)
	}
	return os.NewFile(uintptr(fd), filepath.Clean(path)), nil
}

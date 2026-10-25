package clab

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// OutputDir is a directory below a confinement root that the server writes
// files into. All writes go through os.Root so symlinks cannot redirect them
// outside Root.
type OutputDir struct {
	// Root is an existing absolute directory that confines every write.
	Root string
	// Rel is the output directory relative to Root ("" for Root itself).
	Rel string
	// UID and GID own created files and directories; -1 keeps the server account.
	UID int
	GID int
}

// Path returns the absolute output directory path.
func (d OutputDir) Path() string {
	return filepath.Join(d.Root, d.Rel)
}

func (d OutputDir) validate() error {
	if strings.TrimSpace(d.Root) == "" || !filepath.IsAbs(d.Root) {
		return fmt.Errorf("output root must be an absolute path")
	}
	if d.Rel != "" {
		if filepath.IsAbs(d.Rel) || !filepath.IsLocal(d.Rel) {
			return fmt.Errorf("output directory must be relative to its root")
		}
	}
	return nil
}

func (d OutputDir) chowns() bool {
	return d.UID >= 0 && d.GID >= 0
}

// openOutputRoot opens the confinement root and creates the output directory.
// Root is symlink-resolved by the caller and is opened without following links,
// so a user who renames a parent directory cannot move the writes elsewhere.
func openOutputRoot(d OutputDir) (*os.Root, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	root, err := openRootNoFollow(d.Root)
	if err != nil {
		return nil, fmt.Errorf("failed to open output root: %w", err)
	}
	if err := mkdirAllInRoot(root, d.Rel, 0o750, d); err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

// mkdirAllInRoot creates rel and its missing parents below root. Directories it
// creates are chowned to the output owner; existing ones keep their owner.
func mkdirAllInRoot(root *os.Root, rel string, perm os.FileMode, owner OutputDir) error {
	rel = filepath.Clean(rel)
	if rel == "." || rel == "" {
		return nil
	}
	current := ""
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := root.Stat(current)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("%s exists and is not a directory", current)
			}
			continue
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("failed to inspect %s: %w", current, err)
		}
		if err := root.Mkdir(current, perm); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("failed to create directory %s: %w", current, err)
		}
		if err := lchownInRoot(root, current, owner); err != nil {
			return err
		}
	}
	return nil
}

func lchownInRoot(root *os.Root, name string, owner OutputDir) error {
	if !owner.chowns() {
		return nil
	}
	if err := root.Lchown(name, owner.UID, owner.GID); err != nil {
		return fmt.Errorf("failed to set ownership on %s: %w", name, err)
	}
	return nil
}

// isPlainName reports whether name can be used as a single path element.
func isPlainName(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !strings.ContainsRune(name, 0)
}

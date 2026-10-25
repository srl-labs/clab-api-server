package clab

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	clabnodes "github.com/srl-labs/containerlab/nodes"
)

// SaveResult describes the outcome of SaveConfig.
type SaveResult struct {
	// CopyDir is the absolute <copy>/<lab dir name> directory when a copy was requested.
	CopyDir string
}

// saveCopier mirrors containerlab's `save --copy`: every saved config is copied
// to <dst>/<lab dir name>/<node>/<file>-YYMMDD_HHMMSS.<ext> and a symlink with
// the original file name points at the newest copy.
type saveCopier struct {
	root   *os.Root
	dstRel string
	owner  OutputDir
	labDir string
	now    func() time.Time
}

// copyLabDirName returns the directory name containerlab uses below the copy destination.
func copyLabDirName(labDir, labName string) (string, error) {
	name := filepath.Base(filepath.Clean(labDir))
	if strings.TrimSpace(labDir) == "" || !isPlainName(name) {
		if strings.TrimSpace(labName) == "" {
			return "", fmt.Errorf("failed to resolve save copy destination: lab directory is empty")
		}
		name = "clab-" + labName
	}
	if !isPlainName(name) {
		return "", fmt.Errorf("invalid lab directory name %q", name)
	}
	return name, nil
}

// newSaveCopier prepares <dst>/<labDirName>. labDir is the lab directory that
// saved configs must come from.
func newSaveCopier(dst OutputDir, labDir, labDirName string) (*saveCopier, error) {
	if !isPlainName(labDirName) {
		return nil, fmt.Errorf("invalid lab directory name %q", labDirName)
	}
	if !filepath.IsAbs(labDir) {
		return nil, fmt.Errorf("lab directory must be an absolute path")
	}
	root, err := openOutputRoot(dst)
	if err != nil {
		return nil, err
	}
	dstRel := filepath.Join(dst.Rel, labDirName)
	if err := mkdirAllInRoot(root, dstRel, 0o750, dst); err != nil {
		_ = root.Close()
		return nil, err
	}
	return &saveCopier{
		root:   root,
		dstRel: dstRel,
		owner:  dst,
		labDir: filepath.Clean(labDir),
		now:    time.Now,
	}, nil
}

func (c *saveCopier) Close() error {
	return c.root.Close()
}

// dir returns the absolute <dst>/<labDirName> path.
func (c *saveCopier) dir() string {
	return filepath.Join(c.owner.Root, c.dstRel)
}

// copy copies one node's saved config. Nodes without a host-visible config are skipped.
func (c *saveCopier) copy(nodeName string, result *clabnodes.SaveConfigResult) error {
	if result == nil || strings.TrimSpace(result.ConfigPath) == "" {
		log.Debug("no saved config path reported, skipping copy", "node", nodeName)
		return nil
	}
	if !isPlainName(nodeName) {
		return fmt.Errorf("invalid node name %q", nodeName)
	}

	src, err := c.openSource(result.ConfigPath)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()

	nodeRel := filepath.Join(c.dstRel, nodeName)
	if err := mkdirAllInRoot(c.root, nodeRel, 0o750, c.owner); err != nil {
		return err
	}

	fileName := filepath.Base(result.ConfigPath)
	tsFileName := timestampedFileName(fileName, c.now())
	tsRel := filepath.Join(nodeRel, tsFileName)

	// Replace an earlier copy from the same second without following links.
	if err := c.root.Remove(tsRel); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to replace %s: %w", tsFileName, err)
	}
	dst, err := c.root.OpenFile(tsRel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", tsFileName, err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return fmt.Errorf("failed to copy saved config to %s: %w", tsFileName, err)
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("failed to write %s: %w", tsFileName, err)
	}
	if err := lchownInRoot(c.root, tsRel, c.owner); err != nil {
		return err
	}

	linkRel := filepath.Join(nodeRel, fileName)
	if err := c.root.Remove(linkRel); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to replace %s: %w", fileName, err)
	}
	if err := c.root.Symlink(tsFileName, linkRel); err != nil {
		return fmt.Errorf("failed to create symlink %s -> %s: %w", fileName, tsFileName, err)
	}
	if err := lchownInRoot(c.root, linkRel, c.owner); err != nil {
		return err
	}

	log.Info("copied saved config", "node", nodeName, "src", result.ConfigPath, "dst", filepath.Join(c.owner.Root, tsRel))
	return nil
}

// openSource opens a saved config inside the lab directory. Symlinks may not
// lead outside the lab directory, so a planted link cannot expose host files.
func (c *saveCopier) openSource(configPath string) (*os.File, error) {
	cleanPath := filepath.Clean(configPath)
	rel, err := filepath.Rel(c.labDir, cleanPath)
	if err != nil || !filepath.IsLocal(rel) {
		return nil, fmt.Errorf("saved config %q is outside the lab directory", configPath)
	}
	if info, err := os.Lstat(c.labDir); err != nil {
		return nil, fmt.Errorf("failed to inspect lab directory: %w", err)
	} else if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("lab directory %q must be a directory, not a symbolic link", c.labDir)
	}

	// Open without following links so the lab directory cannot be swapped
	// after the check above.
	labRoot, err := openRootNoFollow(c.labDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open lab directory: %w", err)
	}
	defer func() { _ = labRoot.Close() }()

	src, err := labRoot.Open(rel)
	if err != nil {
		return nil, fmt.Errorf("failed to open saved config %q: %w", configPath, err)
	}
	info, err := src.Stat()
	if err != nil {
		_ = src.Close()
		return nil, fmt.Errorf("failed to inspect saved config %q: %w", configPath, err)
	}
	if !info.Mode().IsRegular() {
		_ = src.Close()
		return nil, fmt.Errorf("saved config %q is not a regular file", configPath)
	}
	return src, nil
}

// timestampedFileName inserts a timestamp before the file extension, matching
// containerlab: "config.json" -> "config-260206_235900.json",
// "startup-config" -> "startup-config-260206_235900".
func timestampedFileName(name string, t time.Time) string {
	ts := t.UTC().Format("060102_150405")
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	return base + "-" + ts + ext
}

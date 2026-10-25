package api

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/srl-labs/clab-api-server/internal/clab"
)

// errLabPathOutsideRoots is returned when a lab path resolves outside every allowed root.
var errLabPathOutsideRoots = errors.New("path must be inside your workspace")

// labPathRoot is a directory lab paths may resolve into.
type labPathRoot struct {
	path   string
	uid    int
	gid    int
	shared bool
}

// labPathScope resolves user supplied "lab paths": paths relative to the
// directory of a lab's topology file, or absolute paths. Every resolved path
// must stay inside one of the roots after symlinks are resolved.
type labPathScope struct {
	baseDir string
	roots   []labPathRoot
	// reader is the account files are read for, e.g. restore snapshots.
	reader clab.FileReader
}

// resolvedLabPath is a confined lab path.
type resolvedLabPath struct {
	// Path is the absolute path with symlinks in its existing part resolved.
	Path string
	// Root is the symlink-resolved root that contains Path.
	Root string
	// Rel is Path relative to Root ("" for the root itself).
	Rel string
	// UID and GID own files the server creates below Root; -1 keeps the server account.
	UID    int
	GID    int
	Shared bool
}

// labPathScopeFor returns the scope for lab paths of a lab whose topology file is
// topoPath. Relative paths resolve against the topology directory, or against
// the user's workspace root when the topology is unknown or lies outside the
// allowed roots (e.g. a topology downloaded from a URL). The user's workspace is
// always allowed; the shared labs root is allowed for labs stored there.
func labPathScopeFor(username, topoPath string) (labPathScope, error) {
	workspaceRoot, uid, gid, err := getUserWorkspaceDirectory(username)
	if err != nil {
		return labPathScope{}, err
	}
	scope := newLabPathScope(topoPath, labPathRoot{path: workspaceRoot, uid: uid, gid: gid}, sharedLabsRoot())
	scope.reader.GIDs = userGroupIDs(username, gid)
	return scope, nil
}

// userGroupIDs returns the user's primary and supplementary group IDs.
func userGroupIDs(username string, primaryGID int) []int {
	gids := []int{primaryGID}
	usr, err := user.Lookup(username)
	if err != nil {
		return gids
	}
	groupIDs, err := usr.GroupIds()
	if err != nil {
		return gids
	}
	for _, raw := range groupIDs {
		if gid, convErr := strconv.Atoi(raw); convErr == nil && gid != primaryGID {
			gids = append(gids, gid)
		}
	}
	return gids
}

func newLabPathScope(topoPath string, workspace labPathRoot, sharedRoot string) labPathScope {
	scope := labPathScope{
		baseDir: workspace.path,
		roots:   []labPathRoot{workspace},
		reader:  clab.FileReader{UID: workspace.uid, GIDs: []int{workspace.gid}},
	}

	topoPath = strings.TrimSpace(topoPath)
	if topoPath == "" || !filepath.IsAbs(topoPath) {
		return scope
	}
	topoDir := filepath.Dir(filepath.Clean(topoPath))
	if sharedRoot != "" && pathIsInsideRoot(sharedRoot, topoDir) {
		scope.roots = append(scope.roots, labPathRoot{path: sharedRoot, uid: -1, gid: -1, shared: true})
	}
	for _, root := range scope.roots {
		if pathIsInsideRoot(root.path, topoDir) {
			scope.baseDir = topoDir
			break
		}
	}
	return scope
}

// resolve confines raw to the scope. Relative paths are joined with the scope's
// base directory. The deepest existing ancestor is resolved with EvalSymlinks so
// a symlink cannot point outside the roots; dangling symlinks are rejected.
func (s labPathScope) resolve(raw string) (resolvedLabPath, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return resolvedLabPath{}, fmt.Errorf("path must not be empty")
	}
	if strings.ContainsRune(trimmed, 0) {
		return resolvedLabPath{}, fmt.Errorf("path contains invalid characters")
	}

	candidate := filepath.FromSlash(trimmed)
	if !filepath.IsAbs(candidate) {
		if s.baseDir == "" {
			return resolvedLabPath{}, fmt.Errorf("relative paths are not supported here")
		}
		candidate = filepath.Join(s.baseDir, candidate)
	}
	candidate = filepath.Clean(candidate)

	realPath, err := resolveExistingPrefix(candidate)
	if err != nil {
		return resolvedLabPath{}, fmt.Errorf("failed to resolve path: %w", err)
	}

	for _, root := range s.roots {
		if strings.TrimSpace(root.path) == "" {
			continue
		}
		cleanRoot := filepath.Clean(root.path)
		realRoot, rootErr := resolveExistingPrefix(cleanRoot)
		if rootErr != nil {
			continue
		}
		if !pathIsInsideRoot(cleanRoot, candidate) && !pathIsInsideRoot(realRoot, candidate) {
			continue
		}
		if !pathIsInsideRoot(realRoot, realPath) {
			return resolvedLabPath{}, fmt.Errorf("path resolves outside your workspace through a symbolic link")
		}
		if root.shared {
			lexicalRoot := cleanRoot
			if !pathIsInsideRoot(cleanRoot, candidate) {
				lexicalRoot = realRoot
			}
			if err := validateNoSymlinks(lexicalRoot, candidate); err != nil {
				return resolvedLabPath{}, err
			}
		}
		rel, relErr := filepath.Rel(realRoot, realPath)
		if relErr != nil {
			return resolvedLabPath{}, fmt.Errorf("failed to resolve path: %w", relErr)
		}
		if rel == "." {
			rel = ""
		}
		return resolvedLabPath{
			Path:   realPath,
			Root:   realRoot,
			Rel:    rel,
			UID:    root.uid,
			GID:    root.gid,
			Shared: root.shared,
		}, nil
	}

	return resolvedLabPath{}, errLabPathOutsideRoots
}

// display returns the path clients should show: workspace-relative inside the
// user's workspace, "@shared/..." inside the shared root.
func (p resolvedLabPath) display() string {
	rel := filepath.ToSlash(p.Rel)
	if p.Shared {
		if rel == "" {
			return sharedWorkspaceName
		}
		return sharedWorkspaceName + "/" + rel
	}
	if rel == "" {
		return "."
	}
	return rel
}

// resolveExistingPrefix resolves symlinks in the deepest existing ancestor of
// path and appends the missing suffix. path must be absolute and clean.
func resolveExistingPrefix(path string) (string, error) {
	existing := path
	var missing []string
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			break
		}
		missing = append([]string{filepath.Base(existing)}, missing...)
		existing = parent
	}

	realExisting, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", err
	}
	return filepath.Join(append([]string{realExisting}, missing...)...), nil
}

// validateNoSymlinks rejects symlinks in any existing component of path below
// root, matching the policy for shared workspace paths.
func validateNoSymlinks(root, path string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	current := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("shared paths must not contain symbolic links")
		}
	}
	return nil
}

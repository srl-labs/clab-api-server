package api

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// sharedWorkspaceName is a virtual mount, never a symlink in a user's workspace.
const sharedWorkspaceName = "@shared"

func sharedLabsRoot() string {
	return config.AppConfig.ClabSharedLabsRoot
}

func sharedRootContains(path string) bool {
	return sharedLabsRoot() != "" && filepath.IsAbs(path) && pathIsInsideRoot(sharedLabsRoot(), path)
}

func isSharedWorkspacePath(path string) bool {
	path = strings.TrimSpace(path)
	return path == sharedWorkspaceName || strings.HasPrefix(path, sharedWorkspaceName+"/")
}

func sharedWorkspaceRelativePath(path string, allowRoot bool) (string, error) {
	path = strings.TrimSpace(path)
	if !isSharedWorkspacePath(path) {
		return "", fmt.Errorf("invalid shared workspace path")
	}
	return cleanWorkspacePath(strings.TrimPrefix(strings.TrimPrefix(path, sharedWorkspaceName), "/"), allowRoot)
}

// validateSharedPath rejects symlinks, including dangling ones, in every existing
// component. Missing suffixes are allowed so new files and stopped labs work.
func validateSharedPath(path string) error {
	root := sharedLabsRoot()
	if !sharedRootContains(path) {
		return fmt.Errorf("path is outside the shared workspace")
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	current := root
	parts := append([]string{"."}, strings.Split(rel, string(filepath.Separator))...)
	for _, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("shared topology paths must not contain symbolic links")
		}
	}
	return nil
}

func isSharedLabPath(path string) bool {
	return sharedLabsRoot() != "" && filepath.Clean(path) != sharedLabsRoot() && validateSharedPath(path) == nil
}

func canAccessLab(username string, info *models.ClabContainerInfo) bool {
	return info != nil && (info.Owner == username || isSuperuser(username) || isSharedLabPath(info.AbsLabPath))
}

func resolveSharedTopologyPath(username, path string) (string, string, int, int, error) {
	absPath, root, _, uid, gid, err := resolveWorkspacePath(username, path, false)
	if err != nil {
		return "", "", -1, -1, err
	}
	if err := validateSharedPath(absPath); err != nil {
		return "", "", -1, -1, err
	}
	return absPath, root, uid, gid, nil
}

func sharedWorkspaceEntries(rootPath, relativePath string, entries []models.WorkspaceFileEntry) []models.WorkspaceFileEntry {
	if sharedLabsRoot() == "" {
		return entries
	}
	if rootPath == sharedLabsRoot() {
		for i := range entries {
			entries[i].Path = sharedWorkspaceName + "/" + entries[i].Path
		}
	} else if relativePath == "" {
		entries = append([]models.WorkspaceFileEntry{{
			Name: sharedWorkspaceName, Path: sharedWorkspaceName,
			Kind: workspaceFileKindDirectory, HasChildren: true,
		}}, entries...)
	}
	return entries
}

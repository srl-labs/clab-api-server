package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/models"
)

const (
	workspaceFileKindDirectory      = "directory"
	workspaceFileKindFile           = "file"
	managedArchiveEntryPrefix       = ".archive-"
	managedArchiveBackupEntryPrefix = ".backup-"
)

func getUserWorkspaceDirectory(username string) (string, int, int, error) {
	sentinelDir, uid, gid, err := getLabDirectoryInfo(username, "__sentinel__")
	if err != nil {
		return "", -1, -1, fmt.Errorf("failed to resolve workspace directory: %w", err)
	}
	return filepath.Dir(sentinelDir), uid, gid, nil
}

func cleanWorkspacePath(rawPath string, allowRoot bool) (string, error) {
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" || trimmed == "." {
		if allowRoot {
			return "", nil
		}
		return "", fmt.Errorf("missing required path")
	}

	cleanPath := filepath.Clean(filepath.FromSlash(trimmed))
	if cleanPath == "." {
		if allowRoot {
			return "", nil
		}
		return "", fmt.Errorf("missing required path")
	}
	if cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) || filepath.IsAbs(cleanPath) {
		return "", fmt.Errorf("invalid file path")
	}
	if workspacePathUsesReservedManagedEntry(cleanPath) {
		return "", fmt.Errorf("path uses a reserved managed workspace entry")
	}
	return cleanPath, nil
}

func workspacePathUsesReservedManagedEntry(relativePath string) bool {
	cleanPath := filepath.Clean(filepath.FromSlash(strings.TrimSpace(relativePath)))
	if cleanPath == "" || cleanPath == "." {
		return false
	}
	firstComponent := strings.SplitN(cleanPath, string(filepath.Separator), 2)[0]
	return strings.HasPrefix(firstComponent, managedArchiveEntryPrefix) ||
		strings.HasPrefix(firstComponent, managedArchiveBackupEntryPrefix)
}

func pathIsInsideRoot(rootPath, targetPath string) bool {
	cleanRoot := filepath.Clean(rootPath)
	cleanTarget := filepath.Clean(targetPath)
	if cleanTarget == cleanRoot {
		return true
	}
	relPath, err := filepath.Rel(cleanRoot, cleanTarget)
	if err != nil {
		return false
	}
	return relPath != ".." && !strings.HasPrefix(relPath, ".."+string(filepath.Separator))
}

func resolveWorkspacePath(username, rawPath string, allowRoot bool) (absolutePath, rootPath, relativePath string, uid, gid int, err error) {
	rootPath, uid, gid, err = getUserWorkspaceDirectory(username)
	if err != nil {
		return "", "", "", -1, -1, err
	}

	relativePath, err = cleanWorkspacePath(rawPath, allowRoot)
	if err != nil {
		return "", "", "", -1, -1, err
	}

	absolutePath = filepath.Clean(filepath.Join(rootPath, relativePath))
	if !pathIsInsideRoot(rootPath, absolutePath) {
		return "", "", "", -1, -1, fmt.Errorf("resolved path escapes workspace directory")
	}

	return absolutePath, rootPath, relativePath, uid, gid, nil
}

func ensureWorkspaceRoot(rootPath string, uid, gid int) error {
	info, err := os.Lstat(rootPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("workspace directory must not be a symbolic link")
		}
		if !info.IsDir() {
			return fmt.Errorf("workspace path is not a directory")
		}
	}
	return ensureUserLabsBaseDirectory(rootPath, uid, gid)
}

func workspaceRelativePath(rootPath, absolutePath string) string {
	relPath, err := filepath.Rel(rootPath, absolutePath)
	if err != nil || relPath == "." {
		return ""
	}
	return filepath.ToSlash(relPath)
}

func workspaceRootName(relativePath string) string {
	if relativePath == "" {
		return "."
	}
	return relativePath
}

func workspaceParentPath(relativePath string) string {
	parent := filepath.Dir(relativePath)
	if parent == "." {
		return ""
	}
	return parent
}

func workspaceRootErrorIsBadPath(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrInvalid) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "path escapes") ||
		strings.Contains(message, "too many levels of symbolic links") ||
		strings.Contains(message, "symbolic link") ||
		strings.Contains(message, "not a directory")
}

func ensureWorkspaceParentExists(root *os.Root, relativePath string) error {
	parentPath := workspaceParentPath(relativePath)
	if parentPath == "" {
		return nil
	}
	info, err := root.Stat(parentPath)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("parent path is not a directory")
	}
	return nil
}

func workspaceRootDirectoryHasChildren(root *os.Root, relativePath string) bool {
	dir, err := root.Open(workspaceRootName(relativePath))
	if err != nil {
		return false
	}
	defer dir.Close()

	names, err := dir.Readdirnames(1)
	return err == nil && len(names) > 0
}

func workspaceQueryBool(c *gin.Context, key string) bool {
	switch strings.ToLower(strings.TrimSpace(c.Query(key))) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func workspaceEntryFromRootDirEntry(root *os.Root, parentPath string, entry os.DirEntry) (models.WorkspaceFileEntry, bool) {
	entryPath := filepath.Join(parentPath, entry.Name())
	if workspacePathUsesReservedManagedEntry(entryPath) {
		return models.WorkspaceFileEntry{}, false
	}
	info, infoErr := root.Lstat(entryPath)
	if infoErr != nil {
		return models.WorkspaceFileEntry{}, false
	}

	isDir := entry.IsDir()
	if info.Mode()&os.ModeSymlink != 0 {
		targetInfo, targetInfoErr := root.Stat(entryPath)
		if targetInfoErr != nil {
			return models.WorkspaceFileEntry{}, false
		}
		info = targetInfo
		isDir = targetInfo.IsDir()
	}

	kind := workspaceFileKindFile
	hasChildren := false
	if isDir {
		kind = workspaceFileKindDirectory
		hasChildren = workspaceRootDirectoryHasChildren(root, entryPath)
	}

	return models.WorkspaceFileEntry{
		Name:        entry.Name(),
		Path:        filepath.ToSlash(entryPath),
		Kind:        kind,
		Size:        info.Size(),
		ModifiedAt:  info.ModTime().UTC().Format(time.RFC3339),
		HasChildren: hasChildren,
	}, true
}

func listWorkspaceEntriesInRoot(root *os.Root, dirPath string) ([]models.WorkspaceFileEntry, error) {
	dir, err := root.Open(workspaceRootName(dirPath))
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}

	result := make([]models.WorkspaceFileEntry, 0, len(entries))
	for _, entry := range entries {
		if item, ok := workspaceEntryFromRootDirEntry(root, dirPath, entry); ok {
			result = append(result, item)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind == workspaceFileKindDirectory
		}
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})

	return result, nil
}

// @Summary List lab workspace files
// @Description Lists files and folders inside the authenticated user's editable lab workspace root.
// @Description Top-level `.archive-*` and `.backup-*` entries are reserved for internal archive transactions and are hidden.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param path query string false "Relative directory path inside the workspace root"
// @Success 200 {array} models.WorkspaceFileEntry "Workspace entries"
// @Failure 400 {object} models.ErrorResponse "Invalid path"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Directory not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/workspace/tree [get]
func ListWorkspaceTreeHandler(c *gin.Context) {
	username := c.GetString("username")
	_, rootPath, relativePath, _, _, err := resolveWorkspacePath(username, c.Query("path"), true)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}

	root, rootErr := openWorkspaceRoot(rootPath)
	if rootErr != nil {
		if os.IsNotExist(rootErr) && relativePath == "" {
			c.JSON(http.StatusOK, []models.WorkspaceFileEntry{})
			return
		}
		if os.IsNotExist(rootErr) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: "Directory not found"})
			return
		}
		if workspaceRootErrorIsBadPath(rootErr) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: rootErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: rootErr.Error()})
		return
	}
	defer root.Close()

	info, infoErr := root.Stat(workspaceRootName(relativePath))
	if infoErr != nil {
		if os.IsNotExist(infoErr) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: "Directory not found"})
			return
		}
		if workspaceRootErrorIsBadPath(infoErr) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: infoErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: infoErr.Error()})
		return
	}
	if !info.IsDir() {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Path is not a directory"})
		return
	}

	entries, listErr := listWorkspaceEntriesInRoot(root, relativePath)
	if listErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: listErr.Error()})
		return
	}
	c.JSON(http.StatusOK, entries)
}

// @Summary Read lab workspace file
// @Description Reads a text or binary file from the authenticated user's editable lab workspace root.
// @Description Paths whose first component starts with `.archive-*` or `.backup-*` are reserved and rejected.
// @Tags Labs
// @Security BearerAuth
// @Produce plain
// @Param path query string true "Relative file path inside the workspace root"
// @Success 200 {string} string "File content"
// @Failure 400 {object} models.ErrorResponse "Invalid path"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "File not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/workspace/file [get]
func GetWorkspaceFileHandler(c *gin.Context) {
	username := c.GetString("username")
	_, rootPath, relativePath, _, _, err := resolveWorkspacePath(username, c.Query("path"), false)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}

	root, rootErr := openWorkspaceRoot(rootPath)
	if rootErr != nil {
		if os.IsNotExist(rootErr) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: "File not found"})
			return
		}
		if workspaceRootErrorIsBadPath(rootErr) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: rootErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: rootErr.Error()})
		return
	}
	defer root.Close()

	file, openErr := root.Open(relativePath)
	if openErr != nil {
		if os.IsNotExist(openErr) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: "File not found"})
			return
		}
		if workspaceRootErrorIsBadPath(openErr) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: openErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: openErr.Error()})
		return
	}
	defer file.Close()

	info, statErr := file.Stat()
	if statErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: statErr.Error()})
		return
	}
	if info.IsDir() {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Path is not a file"})
		return
	}
	c.DataFromReader(http.StatusOK, info.Size(), "application/octet-stream", file, nil)
}

// @Summary Write lab workspace file
// @Description Writes a file inside the authenticated user's editable lab workspace root.
// @Description Paths whose first component starts with `.archive-*` or `.backup-*` are reserved and rejected.
// @Tags Labs
// @Security BearerAuth
// @Accept plain
// @Produce json
// @Param path query string true "Relative file path inside the workspace root"
// @Param content body string true "File content"
// @Success 200 {object} models.SimpleSuccessResponse "Write success"
// @Failure 400 {object} models.ErrorResponse "Invalid path"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/workspace/file [put]
func PutWorkspaceFileHandler(c *gin.Context) {
	username := c.GetString("username")
	_, rootPath, relativePath, uid, gid, err := resolveWorkspacePath(username, c.Query("path"), false)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}
	if err := ensureWorkspaceRoot(rootPath, uid, gid); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to ensure workspace directory: %s", err.Error())})
		return
	}

	root, rootErr := openWorkspaceRoot(rootPath)
	if rootErr != nil {
		if workspaceRootErrorIsBadPath(rootErr) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: rootErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: rootErr.Error()})
		return
	}
	defer root.Close()

	body, readErr := io.ReadAll(c.Request.Body)
	if readErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Failed to read request body"})
		return
	}
	if parentErr := ensureWorkspaceParentExists(root, relativePath); parentErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: parentErr.Error()})
		return
	}

	file, openErr := root.OpenFile(relativePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if openErr != nil {
		if workspaceRootErrorIsBadPath(openErr) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: openErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to open file for writing: %s", openErr.Error())})
		return
	}
	defer file.Close()

	_ = file.Chown(uid, gid)
	if _, writeErr := file.Write(body); writeErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to write file: %s", writeErr.Error())})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// @Summary Delete lab workspace file
// @Description Deletes a file or directory inside the authenticated user's editable lab workspace root. Directories with children require recursive=true.
// @Description Paths whose first component starts with `.archive-*` or `.backup-*` are reserved and rejected.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param path query string true "Relative file path inside the workspace root"
// @Param recursive query bool false "Delete non-empty directories recursively"
// @Success 200 {object} models.SimpleSuccessResponse "Delete success"
// @Failure 400 {object} models.ErrorResponse "Invalid path"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/workspace/file [delete]
func DeleteWorkspaceFileHandler(c *gin.Context) {
	username := c.GetString("username")
	_, rootPath, relativePath, _, _, err := resolveWorkspacePath(username, c.Query("path"), false)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}

	root, rootErr := openWorkspaceRoot(rootPath)
	if rootErr != nil {
		if os.IsNotExist(rootErr) {
			c.JSON(http.StatusOK, gin.H{"success": true})
			return
		}
		if workspaceRootErrorIsBadPath(rootErr) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: rootErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: rootErr.Error()})
		return
	}
	defer root.Close()

	info, statErr := root.Lstat(relativePath)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			c.JSON(http.StatusOK, gin.H{"success": true})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: statErr.Error()})
		return
	}
	recursive := workspaceQueryBool(c, "recursive")
	isSymlink := info.Mode()&os.ModeSymlink != 0
	if !isSymlink && info.IsDir() && !recursive && workspaceRootDirectoryHasChildren(root, relativePath) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Directory is not empty"})
		return
	}

	var removeErr error
	if recursive && info.IsDir() && !isSymlink {
		removeErr = root.RemoveAll(relativePath)
	} else {
		removeErr = root.Remove(relativePath)
	}
	if removeErr != nil && !os.IsNotExist(removeErr) {
		if workspaceRootErrorIsBadPath(removeErr) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: removeErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to delete file: %s", removeErr.Error())})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// @Summary Rename lab workspace file
// @Description Renames or moves a file inside the authenticated user's editable lab workspace root.
// @Description Source or destination paths whose first component starts with `.archive-*` or `.backup-*` are reserved and rejected.
// @Tags Labs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param rename_request body models.WorkspaceFileRenameRequest true "Old and new relative file paths"
// @Success 200 {object} models.SimpleSuccessResponse "Rename success"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/workspace/file/rename [post]
func RenameWorkspaceFileHandler(c *gin.Context) {
	username := c.GetString("username")
	var req models.WorkspaceFileRenameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	_, rootPath, oldRelativePath, _, _, oldErr := resolveWorkspacePath(username, req.OldPath, false)
	if oldErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: oldErr.Error()})
		return
	}
	_, _, newRelativePath, uid, gid, newErr := resolveWorkspacePath(username, req.NewPath, false)
	if newErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: newErr.Error()})
		return
	}
	if err := ensureWorkspaceRoot(rootPath, uid, gid); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to ensure workspace directory: %s", err.Error())})
		return
	}

	root, rootErr := openWorkspaceRoot(rootPath)
	if rootErr != nil {
		if workspaceRootErrorIsBadPath(rootErr) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: rootErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: rootErr.Error()})
		return
	}
	defer root.Close()

	if _, statErr := root.Stat(oldRelativePath); statErr != nil {
		if os.IsNotExist(statErr) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: "Source file not found"})
			return
		}
		if workspaceRootErrorIsBadPath(statErr) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: statErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: statErr.Error()})
		return
	}

	if parentErr := ensureWorkspaceParentExists(root, newRelativePath); parentErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: parentErr.Error()})
		return
	}
	if renameErr := root.Rename(oldRelativePath, newRelativePath); renameErr != nil {
		if os.IsNotExist(renameErr) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: "Source file not found"})
			return
		}
		if workspaceRootErrorIsBadPath(renameErr) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: renameErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to rename file: %s", renameErr.Error())})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// @Summary Create lab workspace directory
// @Description Creates a directory inside the authenticated user's editable lab workspace root.
// @Description Paths whose first component starts with `.archive-*` or `.backup-*` are reserved and rejected.
// @Tags Labs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param directory_request body models.WorkspaceDirectoryRequest true "Directory path"
// @Success 200 {object} models.SimpleSuccessResponse "Directory create success"
// @Failure 400 {object} models.ErrorResponse "Invalid path"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/workspace/directory [post]
func CreateWorkspaceDirectoryHandler(c *gin.Context) {
	username := c.GetString("username")
	var req models.WorkspaceDirectoryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	_, rootPath, relativePath, uid, gid, err := resolveWorkspacePath(username, req.Path, false)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}
	if err := ensureWorkspaceRoot(rootPath, uid, gid); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to ensure workspace directory: %s", err.Error())})
		return
	}

	root, rootErr := openWorkspaceRoot(rootPath)
	if rootErr != nil {
		if workspaceRootErrorIsBadPath(rootErr) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: rootErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: rootErr.Error()})
		return
	}
	defer root.Close()

	if parentErr := ensureWorkspaceParentExists(root, relativePath); parentErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: parentErr.Error()})
		return
	}
	if mkdirErr := root.MkdirAll(relativePath, 0750); mkdirErr != nil {
		if workspaceRootErrorIsBadPath(mkdirErr) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: mkdirErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to create directory: %s", mkdirErr.Error())})
		return
	}
	_ = root.Lchown(relativePath, uid, gid)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

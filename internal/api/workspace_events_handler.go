package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/models"
)

const workspaceFileEventDebounce = 150 * time.Millisecond

func workspaceFileEventAction(op fsnotify.Op) string {
	switch {
	case op&fsnotify.Create != 0:
		return "create"
	case op&fsnotify.Write != 0:
		return "change"
	case op&fsnotify.Remove != 0:
		return "delete"
	case op&fsnotify.Rename != 0:
		return "rename"
	default:
		return "change"
	}
}

func workspaceFileEventKind(absPath string) string {
	info, err := os.Lstat(absPath)
	if err != nil {
		return ""
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ""
	}
	if info.IsDir() {
		return workspaceFileKindDirectory
	}
	return workspaceFileKindFile
}

func workspaceEventParentPath(relPath string) string {
	parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(relPath)))
	if parent == "." {
		return ""
	}
	return parent
}

func buildWorkspaceFileEvent(rootPath, absPath string, op fsnotify.Op) (models.WorkspaceFileEventResponse, bool) {
	if !pathIsInsideRoot(rootPath, absPath) {
		return models.WorkspaceFileEventResponse{}, false
	}
	relPath := workspaceRelativePath(rootPath, absPath)
	if relPath == "" || workspacePathUsesReservedManagedEntry(relPath) {
		return models.WorkspaceFileEventResponse{}, false
	}
	return models.WorkspaceFileEventResponse{
		Type:       "workspace-file",
		Path:       relPath,
		ParentPath: workspaceEventParentPath(relPath),
		Kind:       workspaceFileEventKind(absPath),
		Action:     workspaceFileEventAction(op),
	}, true
}

func addWorkspaceWatchDir(watcher *fsnotify.Watcher, watchedDirs map[string]struct{}, dirPath string) {
	cleanPath := filepath.Clean(dirPath)
	if _, ok := watchedDirs[cleanPath]; ok {
		return
	}
	if err := watcher.Add(cleanPath); err == nil {
		watchedDirs[cleanPath] = struct{}{}
	}
}

func addWorkspaceWatchDirs(watcher *fsnotify.Watcher, watchedDirs map[string]struct{}, rootPath string) error {
	return filepath.WalkDir(rootPath, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !entry.IsDir() {
			return nil
		}
		if relativePath, relErr := filepath.Rel(rootPath, path); relErr == nil && workspacePathUsesReservedManagedEntry(relativePath) {
			return filepath.SkipDir
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return filepath.SkipDir
		}
		addWorkspaceWatchDir(watcher, watchedDirs, path)
		return nil
	})
}

func workspaceEventIsDuplicate(lastByKey map[string]time.Time, event models.WorkspaceFileEventResponse) bool {
	key := strings.Join([]string{event.Action, event.Path}, ":")
	now := time.Now()
	if last, ok := lastByKey[key]; ok && now.Sub(last) < workspaceFileEventDebounce {
		return true
	}
	lastByKey[key] = now
	return false
}

// @Summary Stream lab workspace file events
// @Description Streams create/change/delete/rename events inside the authenticated user's editable lab workspace root as NDJSON.
// @Description Internal `.archive-*` and `.backup-*` transaction paths are excluded from the stream.
// @Tags Labs
// @Security BearerAuth
// @Produce application/x-ndjson
// @Success 200 {object} models.WorkspaceFileEventResponse "Workspace file event stream"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/workspace/events [get]
func StreamWorkspaceEventsHandler(c *gin.Context) {
	username := c.GetString("username")
	rootPath, uid, gid, err := getUserWorkspaceDirectory(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("failed to resolve workspace directory: %v", err)})
		return
	}
	if err := ensureWorkspaceRoot(rootPath, uid, gid); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("failed to ensure workspace directory: %v", err)})
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("failed to create watcher: %v", err)})
		return
	}
	defer watcher.Close()

	watchedDirs := map[string]struct{}{}
	if err := addWorkspaceWatchDirs(watcher, watchedDirs, rootPath); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("failed to watch workspace directory: %v", err)})
		return
	}

	c.Writer.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Status(http.StatusOK)
	c.Writer.WriteHeaderNow()
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		return
	}
	_, _ = c.Writer.Write([]byte("\n"))
	flusher.Flush()

	writer := bufio.NewWriter(c.Writer)
	lastByKey := map[string]time.Time{}
	heartbeat := time.NewTicker(ndjsonStreamHeartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case <-c.Request.Context().Done():
			return
		case <-heartbeat.C:
			if !writeNDJSONHeartbeat(writer, flusher) {
				return
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			payload, _ := json.Marshal(gin.H{"type": "error", "error": err.Error()})
			if !writeNDJSONLine(writer, flusher, string(payload)) {
				return
			}
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) == 0 {
				continue
			}

			workspaceEvent, ok := buildWorkspaceFileEvent(rootPath, event.Name, event.Op)
			if !ok {
				continue
			}
			if event.Op&fsnotify.Create != 0 && workspaceFileEventKind(event.Name) == workspaceFileKindDirectory {
				_ = addWorkspaceWatchDirs(watcher, watchedDirs, event.Name)
			}
			if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
				delete(watchedDirs, filepath.Clean(event.Name))
			}
			if workspaceEventIsDuplicate(lastByKey, workspaceEvent) {
				continue
			}
			payload, err := json.Marshal(workspaceEvent)
			if err != nil {
				continue
			}
			if !writeNDJSONLine(writer, flusher, string(payload)) {
				return
			}
		}
	}
}

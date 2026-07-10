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

const topologyRevisionHeader = "X-Topology-Document-Revision"

type topologyDocumentSet struct {
	labName            string
	yamlRelPath        string
	annotationsRelPath string
	yamlAbsPath        string
	annotationsAbsPath string
}

type topologyDocEvent struct {
	Type         string `json:"type"`
	LabName      string `json:"labName"`
	Path         string `json:"path"`
	DocumentKind string `json:"documentKind"`
	Action       string `json:"action"`
	Revision     string `json:"revision"`
}

func resolveTopologyDocumentSet(username, labName, relPath string) (topologyDocumentSet, string, error) {
	trimmed := strings.TrimSpace(relPath)
	if trimmed == "" {
		return topologyDocumentSet{}, "", fmt.Errorf("missing required query parameter 'path'")
	}

	cleanPath := filepath.Clean(trimmed)
	if cleanPath == "." || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) || filepath.IsAbs(cleanPath) {
		return topologyDocumentSet{}, "", fmt.Errorf("invalid file path")
	}

	yamlRelPath := cleanPath
	documentKind := "yaml"
	if strings.HasSuffix(cleanPath, ".annotations.json") {
		yamlRelPath = strings.TrimSuffix(cleanPath, ".annotations.json")
		documentKind = "annotations"
	}

	yamlAbsPath, _, _, _, err := resolveTopologyFilePath(username, labName, yamlRelPath)
	if err != nil {
		return topologyDocumentSet{}, "", err
	}

	annotationsRelPath := yamlRelPath + ".annotations.json"
	annotationsAbsPath, _, _, _, err := resolveTopologyFilePath(username, labName, annotationsRelPath)
	if err != nil {
		return topologyDocumentSet{}, "", err
	}

	return topologyDocumentSet{
		labName:            labName,
		yamlRelPath:        yamlRelPath,
		annotationsRelPath: annotationsRelPath,
		yamlAbsPath:        yamlAbsPath,
		annotationsAbsPath: annotationsAbsPath,
	}, documentKind, nil
}

func fileRevisionPart(absPath string) string {
	info, err := os.Lstat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "missing"
		}
		return "error"
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "invalid"
	}

	return fmt.Sprintf("%d-%d", info.Size(), info.ModTime().UnixNano())
}

func topologyDocumentRevision(set topologyDocumentSet) string {
	return strings.Join([]string{
		"yaml=" + fileRevisionPart(set.yamlAbsPath),
		"annotations=" + fileRevisionPart(set.annotationsAbsPath),
	}, ";")
}

func topologyEventAction(op fsnotify.Op) string {
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

func buildTopologyDocEvent(set topologyDocumentSet, changedPath string, op fsnotify.Op) topologyDocEvent {
	documentKind := "yaml"
	relPath := set.yamlRelPath
	if filepath.Clean(changedPath) == filepath.Clean(set.annotationsAbsPath) {
		documentKind = "annotations"
		relPath = set.annotationsRelPath
	}

	return topologyDocEvent{
		Type:         "topology-doc",
		LabName:      set.labName,
		Path:         relPath,
		DocumentKind: documentKind,
		Action:       topologyEventAction(op),
		Revision:     topologyDocumentRevision(set),
	}
}

func writeTopologyRevisionHeader(c *gin.Context, username, labName, relPath string) {
	set, _, err := resolveTopologyDocumentSet(username, labName, relPath)
	if err != nil {
		return
	}
	c.Header(topologyRevisionHeader, topologyDocumentRevision(set))
}

// @Summary Stream topology document events
// @Description Streams topology YAML/annotations change events for a single lab topology document pair as NDJSON.
// @Tags Labs
// @Security BearerAuth
// @Produce application/x-ndjson
// @Param labName path string true "Lab name"
// @Param path query string true "Relative topology YAML or annotations path inside lab directory"
// @Success 200 {object} models.TopologyDocEventResponse "Topology document event stream"
// @Failure 400 {object} models.ErrorResponse "Invalid path"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/topology/events [get]
func StreamTopologyFileEventsHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	relPath := c.Query("path")

	set, _, err := resolveTopologyDocumentSet(username, labName, relPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("failed to create watcher: %v", err)})
		return
	}
	defer watcher.Close()

	if err := watcher.Add(filepath.Dir(set.yamlAbsPath)); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("failed to watch topology directory: %v", err)})
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
	lastRevision := ""
	lastEventAt := time.Time{}
	heartbeat := time.NewTicker(ndjsonStreamHeartbeatInterval)
	defer heartbeat.Stop()
	matchesTrackedDoc := func(name string) bool {
		clean := filepath.Clean(name)
		return clean == filepath.Clean(set.yamlAbsPath) || clean == filepath.Clean(set.annotationsAbsPath)
	}

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
			if !matchesTrackedDoc(event.Name) {
				continue
			}

			docEvent := buildTopologyDocEvent(set, event.Name, event.Op)
			if docEvent.Revision == lastRevision && time.Since(lastEventAt) < 250*time.Millisecond {
				continue
			}
			payload, err := json.Marshal(docEvent)
			if err != nil {
				continue
			}
			if !writeNDJSONLine(writer, flusher, string(payload)) {
				return
			}
			lastRevision = docEvent.Revision
			lastEventAt = time.Now()
		}
	}
}

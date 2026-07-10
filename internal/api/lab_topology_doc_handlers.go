package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/models"
)

type labTopologyDocPaths struct {
	deployed      bool
	runningDoc    string
	localDoc      string
	ownerUsername string
}

type cachedLabInfo struct {
	expiresAt  time.Time
	exists     bool
	owner      string
	absLabPath string
}

const labTopologyInfoCacheTTL = 1500 * time.Millisecond

var labTopologyInfoCache sync.Map

func getLabInfoCached(ctx context.Context, username, labName string) (*models.ClabContainerInfo, bool, error) {
	cacheKey := username + "\x00" + labName

	if cachedValue, ok := labTopologyInfoCache.Load(cacheKey); ok {
		if cached, typed := cachedValue.(cachedLabInfo); typed {
			if time.Now().Before(cached.expiresAt) {
				if !cached.exists {
					return nil, false, nil
				}
				return &models.ClabContainerInfo{
					Owner:      cached.owner,
					AbsLabPath: cached.absLabPath,
				}, true, nil
			}
			labTopologyInfoCache.Delete(cacheKey)
		}
	}

	info, exists, err := getLabInfo(ctx, username, labName)
	if err != nil {
		return nil, false, err
	}

	record := cachedLabInfo{
		expiresAt: time.Now().Add(labTopologyInfoCacheTTL),
		exists:    exists,
	}
	if exists && info != nil {
		record.owner = info.Owner
		record.absLabPath = info.AbsLabPath
	}
	labTopologyInfoCache.Store(cacheKey, record)

	if !exists || info == nil {
		return nil, false, nil
	}
	return info, true, nil
}

func resolveLabTopologyDocPaths(c *gin.Context, docType string) (*labTopologyDocPaths, error) {
	username := c.GetString("username")
	labName := c.Param("labName")

	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return nil, fmt.Errorf("invalid lab name")
	}

	if docType != "yaml" && docType != "annotations" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid topology document type."})
		return nil, fmt.Errorf("invalid topology document type")
	}

	localDoc, _, _, _, err := resolveDefaultTopologyDocPath(username, labName, docType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to resolve lab document path: %s", err.Error())})
		return nil, err
	}

	paths := &labTopologyDocPaths{
		deployed:      false,
		localDoc:      localDoc,
		ownerUsername: username,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	labInfo, exists, lookupErr := getLabInfoCached(ctx, username, labName)
	if lookupErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to check lab '%s' status: %s", labName, lookupErr.Error())})
		return nil, lookupErr
	}

	if !exists {
		return paths, nil
	}

	if !isSuperuser(username) && labInfo.Owner != username {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("lab '%s' not found or not owned by user", labName)})
		return nil, fmt.Errorf("lab '%s' not found or not owned by user", labName)
	}

	paths.deployed = true
	if strings.TrimSpace(labInfo.Owner) != "" {
		paths.ownerUsername = labInfo.Owner
	}

	if strings.TrimSpace(labInfo.AbsLabPath) != "" {
		paths.runningDoc = filepath.Clean(labInfo.AbsLabPath)
		if docType == "annotations" {
			paths.runningDoc += ".annotations.json"
		}
	}

	ownerLocalDoc, _, _, _, ownerPathErr := resolveDefaultTopologyDocPath(paths.ownerUsername, labName, docType)
	if ownerPathErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to resolve owner lab document path: %s", ownerPathErr.Error())})
		return nil, ownerPathErr
	}
	paths.localDoc = ownerLocalDoc

	return paths, nil
}

func readLabTopologyDoc(c *gin.Context, docType string) {
	paths, err := resolveLabTopologyDocPaths(c, docType)
	if err != nil {
		return
	}

	if paths.deployed && strings.TrimSpace(paths.runningDoc) != "" {
		runningPath, resolveErr := resolveUserRootedFilePath(paths.ownerUsername, paths.runningDoc)
		if resolveErr != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: resolveErr.Error()})
			return
		}
		content, readErr := readRootedFile(runningPath)
		if readErr == nil {
			c.Data(http.StatusOK, "text/plain; charset=utf-8", content)
			return
		}
		if !os.IsNotExist(readErr) {
			writeTopologyRootError(c, readErr, "File not found")
			return
		}
	}

	localPath, resolveErr := resolveUserRootedFilePath(paths.ownerUsername, paths.localDoc)
	if resolveErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: resolveErr.Error()})
		return
	}
	content, readErr := readRootedFile(localPath)
	if readErr != nil {
		writeTopologyRootError(c, readErr, "File not found")
		return
	}

	c.Data(http.StatusOK, "text/plain; charset=utf-8", content)
}

func writeLabTopologyDoc(c *gin.Context, docType string) {
	paths, err := resolveLabTopologyDocPaths(c, docType)
	if err != nil {
		return
	}

	body, readErr := io.ReadAll(c.Request.Body)
	if readErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Failed to read request body"})
		return
	}

	targetPath, resolveErr := resolveUserRootedFilePath(paths.ownerUsername, paths.localDoc)
	if resolveErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: resolveErr.Error()})
		return
	}
	ensureRoot := true
	if paths.deployed && strings.TrimSpace(paths.runningDoc) != "" {
		runningPath, runningResolveErr := resolveUserRootedFilePath(paths.ownerUsername, paths.runningDoc)
		if runningResolveErr != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: runningResolveErr.Error()})
			return
		}
		if _, statErr := statRootedFile(runningPath); statErr == nil {
			targetPath = runningPath
			ensureRoot = false
		} else if !os.IsNotExist(statErr) {
			writeTopologyRootError(c, statErr, "File not found")
			return
		}
	}

	if writeErr := writeRootedFile(targetPath, body, ensureRoot); writeErr != nil {
		writeTopologyRootError(c, writeErr, "File not found")
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// @Summary Get lab topology YAML
// @Description Returns the topology YAML for the specified lab. For deployed labs, the running topology source path is preferred and local files are used as fallback.
// @Tags Labs
// @Security BearerAuth
// @Produce plain
// @Param labName path string true "Lab name"
// @Success 200 {string} string "Topology YAML content"
// @Failure 400 {object} models.ErrorResponse "Invalid lab name"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "File not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/topology/yaml [get]
// GetRunningLabYamlHandler returns the source YAML used by a lab.
func GetRunningLabYamlHandler(c *gin.Context) {
	readLabTopologyDoc(c, "yaml")
}

// @Summary Update lab topology YAML
// @Description Updates the topology YAML for the specified lab. For deployed labs, writes to the running topology source when present and otherwise writes to local files.
// @Tags Labs
// @Security BearerAuth
// @Accept plain
// @Produce json
// @Param labName path string true "Lab name"
// @Param content body string true "Topology YAML content"
// @Success 200 {object} models.SimpleSuccessResponse "Write success"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/topology/yaml [put]
// PutRunningLabYamlHandler updates the source YAML used by a lab.
func PutRunningLabYamlHandler(c *gin.Context) {
	writeLabTopologyDoc(c, "yaml")
}

// @Summary Get lab annotations
// @Description Returns annotations for the specified lab. For deployed labs, the running annotations path is preferred and local files are used as fallback.
// @Tags Labs
// @Security BearerAuth
// @Produce plain
// @Param labName path string true "Lab name"
// @Success 200 {string} string "Annotations content"
// @Failure 400 {object} models.ErrorResponse "Invalid lab name"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "File not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/topology/annotations [get]
// GetRunningLabAnnotationsHandler returns the annotations JSON associated with a lab.
func GetRunningLabAnnotationsHandler(c *gin.Context) {
	readLabTopologyDoc(c, "annotations")
}

// @Summary Update lab annotations
// @Description Updates annotations for the specified lab. For deployed labs, writes to the running annotations path when present and otherwise writes to local files.
// @Tags Labs
// @Security BearerAuth
// @Accept plain
// @Produce json
// @Param labName path string true "Lab name"
// @Param content body string true "Annotations content"
// @Success 200 {object} models.SimpleSuccessResponse "Write success"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/topology/annotations [put]
// PutRunningLabAnnotationsHandler updates or creates the annotations JSON associated with a lab.
func PutRunningLabAnnotationsHandler(c *gin.Context) {
	writeLabTopologyDoc(c, "annotations")
}

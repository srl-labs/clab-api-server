package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	clabgit "github.com/srl-labs/containerlab/git"
	"gopkg.in/yaml.v3"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

func resolveDefaultTopologyDocPath(username, labName, docType string) (string, string, int, int, error) {
	if !isValidLabName(labName) {
		return "", "", -1, -1, fmt.Errorf("invalid lab name")
	}

	fileName := labName + ".clab.yml"
	switch docType {
	case "yaml":
		// keep default
	case "annotations":
		fileName += ".annotations.json"
	default:
		return "", "", -1, -1, fmt.Errorf("invalid topology document type")
	}

	return resolveTopologyFilePath(username, labName, fileName)
}

// @Summary List editable lab topology files
// @Description Returns editable topology entries from the authenticated user's lab directory.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Success 200 {array} models.TopologyEntry "Topology entries"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/topology/files [get]
// ListTopologiesHandler returns editable topology files for the authenticated user.
func ListTopologiesHandler(c *gin.Context) {
	username := c.GetString("username")

	baseDir, err := getUserLabsBaseDirectory(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	entries, listErr := listTopologyEntries(baseDir)
	if listErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: listErr.Error()})
		return
	}

	c.JSON(http.StatusOK, entries)
}

func sanitizeImportedLabName(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	var builder strings.Builder
	for _, r := range trimmed {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-':
			builder.WriteRune(r)
		default:
			builder.WriteRune('-')
		}
	}

	sanitized := strings.Trim(builder.String(), "-")
	if len(sanitized) > 128 {
		sanitized = sanitized[:128]
	}
	return sanitized
}

func canonicalizeTopologyName(raw []byte, labName string) []byte {
	trimmedLabName := strings.TrimSpace(labName)
	if trimmedLabName == "" {
		if bytes.HasSuffix(raw, []byte("\n")) {
			return raw
		}
		return append(raw, '\n')
	}

	var doc map[string]interface{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		if bytes.HasSuffix(raw, []byte("\n")) {
			return raw
		}
		return append(raw, '\n')
	}
	if doc == nil {
		doc = make(map[string]interface{})
	}
	doc["name"] = trimmedLabName

	rendered, err := yaml.Marshal(doc)
	if err != nil {
		if bytes.HasSuffix(raw, []byte("\n")) {
			return raw
		}
		return append(raw, '\n')
	}
	return rendered
}

func copyDirectoryTree(sourceDir, targetDir string, uid, gid int) error {
	sourceRoot := filepath.Clean(sourceDir)
	targetRoot := filepath.Clean(targetDir)

	return filepath.WalkDir(sourceRoot, func(currentPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		relativePath, relErr := filepath.Rel(sourceRoot, currentPath)
		if relErr != nil {
			return relErr
		}

		targetPath := targetRoot
		if relativePath != "." {
			targetPath = filepath.Join(targetRoot, relativePath)
		}

		if entry.Type()&os.ModeSymlink != 0 {
			// Skip symbolic links for safety.
			return nil
		}

		if entry.IsDir() {
			mode := os.FileMode(0750)
			if info, infoErr := entry.Info(); infoErr == nil {
				if perm := info.Mode().Perm(); perm != 0 {
					mode = perm
				}
			}
			if err := os.MkdirAll(targetPath, mode); err != nil {
				return err
			}
			_ = os.Chown(targetPath, uid, gid)
			return nil
		}

		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0750); err != nil {
			return err
		}
		content, readErr := os.ReadFile(currentPath)
		if readErr != nil {
			return readErr
		}

		fileMode := info.Mode().Perm()
		if fileMode == 0 {
			fileMode = 0640
		}
		if writeErr := os.WriteFile(targetPath, content, fileMode); writeErr != nil {
			return writeErr
		}
		_ = os.Chown(targetPath, uid, gid)
		return nil
	})
}

func directoryHasTopLevelTopologyFiles(dirPath string) (bool, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return false, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := strings.ToLower(entry.Name())
		if strings.HasSuffix(name, ".clab.yml") || strings.HasSuffix(name, ".clab.yaml") {
			return true, nil
		}
	}

	return false, nil
}

// @Summary Import topology repository as undeployed lab
// @Description Clones a supported Git repository URL and registers it as an undeployed lab.
// @Tags Labs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param import_request body models.ImportTopologyFromURLRequest true "Topology source URL"
// @Param labNameOverride query string false "Override imported lab name"
// @Success 200 {object} models.ImportTopologyFromURLResponse "Import result"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 409 {object} models.ErrorResponse "Lab already exists"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/topology/import-from-url [post]
func ImportTopologyFromURLHandler(c *gin.Context) {
	username := c.GetString("username")

	var req models.ImportTopologyFromURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	topologySourceURL := strings.TrimSpace(req.TopologySourceUrl)
	if topologySourceURL == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Missing required field 'topologySourceUrl'."})
		return
	}

	if !clabgit.IsGitHubOrGitLabURL(topologySourceURL) && !clabgit.IsGitHubShortURL(topologySourceURL) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Only GitHub and GitLab repository sources are supported for undeployed clone."})
		return
	}

	labNameOverride := strings.TrimSpace(c.Query("labNameOverride"))
	if labNameOverride != "" && !isValidLabName(labNameOverride) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in 'labNameOverride' query parameter."})
		return
	}

	normalizedSourceURL := topologySourceURL
	if clabgit.IsGitHubShortURL(normalizedSourceURL) {
		normalizedSourceURL = "https://github.com/" + normalizedSourceURL
	}
	repo, repoErr := clabgit.NewRepo(normalizedSourceURL)
	if repoErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid topology source URL."})
		return
	}

	labName := labNameOverride
	if labName == "" {
		labName = sanitizeImportedLabName(repo.GetName())
	}
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Unable to derive a valid lab name. Use labNameOverride."})
		return
	}

	targetDir, uid, gid, dirErr := getLabDirectoryInfo(username, labName)
	if dirErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: dirErr.Error()})
		return
	}

	if stat, statErr := os.Stat(targetDir); statErr == nil {
		if !stat.IsDir() {
			c.JSON(http.StatusConflict, models.ErrorResponse{Error: fmt.Sprintf("Path for lab '%s' already exists and is not a directory.", labName)})
			return
		}

		hasTopologyFiles, hasTopoErr := directoryHasTopLevelTopologyFiles(targetDir)
		if hasTopoErr != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to inspect existing lab directory: %s", hasTopoErr.Error())})
			return
		}
		if hasTopologyFiles {
			c.JSON(http.StatusConflict, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' already exists.", labName)})
			return
		}

		// The user may have deleted only the topology file, leaving a stale lab directory behind.
		// Remove it to ensure import recreates a clean undeployed lab tree.
		if removeErr := os.RemoveAll(targetDir); removeErr != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to reset existing lab directory: %s", removeErr.Error())})
			return
		}
	} else if statErr != nil && !os.IsNotExist(statErr) {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to stat lab directory: %s", statErr.Error())})
		return
	}

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	cloned, err := svc.CloneTopologySource(clab.CloneTopologySourceOptions{
		SourceURL: topologySourceURL,
		Username:  username,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to clone topology source: %s", err.Error())})
		return
	}

	sourceDir := filepath.Clean(cloned.RepoDir)
	targetDir = filepath.Clean(targetDir)
	if ensureErr := ensureLabDirectory(targetDir, uid, gid); ensureErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to create lab directory: %s", ensureErr.Error())})
		return
	}
	if sourceDir != targetDir {
		if copyErr := copyDirectoryTree(sourceDir, targetDir, uid, gid); copyErr != nil {
			_ = os.RemoveAll(targetDir)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to copy cloned repository: %s", copyErr.Error())})
			return
		}
	}

	topologyContent, readErr := os.ReadFile(cloned.TopologyPath)
	if readErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to read topology file: %s", readErr.Error())})
		return
	}

	fileName := labName + ".clab.yml"
	canonicalPath := filepath.Join(targetDir, fileName)
	canonicalContent := canonicalizeTopologyName(topologyContent, labName)
	if writeErr := os.WriteFile(canonicalPath, canonicalContent, 0640); writeErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to write canonical topology file: %s", writeErr.Error())})
		return
	}
	_ = os.Chown(canonicalPath, uid, gid)

	hasAnnotations := false
	sourceAnnotationsPath := cloned.TopologyPath + ".annotations.json"
	canonicalAnnotationsPath := canonicalPath + ".annotations.json"
	if _, statErr := os.Stat(sourceAnnotationsPath); statErr == nil {
		hasAnnotations = true
		if filepath.Clean(sourceAnnotationsPath) != filepath.Clean(canonicalAnnotationsPath) {
			annotationsContent, readAnnotationsErr := os.ReadFile(sourceAnnotationsPath)
			if readAnnotationsErr != nil {
				c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to read annotations file: %s", readAnnotationsErr.Error())})
				return
			}
			if writeAnnotationsErr := os.WriteFile(canonicalAnnotationsPath, annotationsContent, 0640); writeAnnotationsErr != nil {
				c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to write canonical annotations file: %s", writeAnnotationsErr.Error())})
				return
			}
			_ = os.Chown(canonicalAnnotationsPath, uid, gid)
		}
	} else if statErr != nil && !os.IsNotExist(statErr) {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to stat annotations file: %s", statErr.Error())})
		return
	}

	topology := models.TopologyEntry{
		LabName:             labName,
		YamlFileName:        fileName,
		AnnotationsFileName: fileName + ".annotations.json",
		HasAnnotations:      hasAnnotations,
		DeploymentState:     "undeployed",
	}

	c.JSON(http.StatusOK, models.ImportTopologyFromURLResponse{
		Success:  true,
		LabName:  labName,
		FileName: fileName,
		Topology: topology,
	})
}

// @Summary Deploy on-disk topology for lab
// @Description Deploys an on-disk topology from the authenticated user's lab directory.
// @Description
// @Description **Notes**
// @Description - `path` defaults to `<labName>.clab.yml` when omitted.
// @Description - `stream=true` returns `application/x-ndjson` lifecycle events.
// @Description - `includeLogs=true` includes captured lifecycle logs in the JSON response.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab name"
// @Param path query string false "Relative topology file path inside lab directory (defaults to <labName>.clab.yml)"
// @Param reconfigure query boolean false "Allow overwriting an existing lab"
// @Param maxWorkers query int false "Limit concurrent workers"
// @Param exportTemplate query string false "Custom Go template file for topology data export"
// @Param nodeFilter query string false "Comma-separated list of node names to deploy"
// @Param skipPostDeploy query boolean false "Skip post-deploy actions"
// @Param skipLabdirAcl query boolean false "Skip setting extended ACLs on lab directory"
// @Param stream query boolean false "Stream lifecycle output as NDJSON events"
// @Param includeLogs query boolean false "Include captured lifecycle logs in the JSON response"
// @Success 200 {object} models.ClabInspectOutput "Deployed lab details"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden"
// @Failure 404 {object} models.ErrorResponse "Topology file not found"
// @Failure 409 {object} models.ErrorResponse "Conflict"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/deploy [post]
// DeployTopologyHandler deploys an on-disk topology identified by lab name.
func DeployTopologyHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	streamLogs := c.Query("stream") == "true"
	includeLogs := c.Query("includeLogs") == "true"
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}

	reconfigure := c.Query("reconfigure") == "true"
	maxWorkersStr := c.DefaultQuery("maxWorkers", "0")
	exportTemplate := c.Query("exportTemplate")
	nodeFilter := c.Query("nodeFilter")
	skipPostDeploy := c.Query("skipPostDeploy") == "true"
	skipLabdirAcl := c.Query("skipLabdirAcl") == "true"

	if !isValidNodeFilter(nodeFilter) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in 'nodeFilter' query parameter."})
		return
	}
	if !isValidExportTemplate(exportTemplate) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'exportTemplate' query parameter."})
		return
	}
	maxWorkers, err := strconv.Atoi(maxWorkersStr)
	if err != nil || maxWorkers < 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'maxWorkers' query parameter."})
		return
	}

	releaseLabOperation, ok := beginLabOperationOrConflict(c, labName, "deploy")
	if !ok {
		return
	}
	defer releaseLabOperation()

	requestedPath := strings.TrimSpace(c.Query("path"))
	topologyPath := ""
	if requestedPath != "" {
		resolvedPath, _, _, _, resolveErr := resolveTopologyFilePath(username, labName, requestedPath)
		if resolveErr != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: resolveErr.Error()})
			return
		}
		topologyPath = resolvedPath
	} else {
		labDir, _, _, dirErr := getLabDirectoryInfo(username, labName)
		if dirErr != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: dirErr.Error()})
			return
		}
		topologyPath = filepath.Join(labDir, labName+".clab.yml")
	}

	if _, statErr := os.Stat(topologyPath); statErr != nil {
		if os.IsNotExist(statErr) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Topology file not found for lab '%s'.", labName)})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to stat topology file: %s", statErr.Error())})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
	defer cancel()

	labInfo, exists, checkErr := getLabInfo(ctx, username, labName)
	if checkErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Error checking lab '%s' status: %s", labName, checkErr.Error())})
		return
	}
	if exists {
		if !reconfigure {
			c.JSON(http.StatusConflict, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' already exists. Use 'reconfigure=true' to overwrite.", labName)})
			return
		}
		if !isSuperuser(username) && labInfo.Owner != username {
			c.JSON(http.StatusForbidden, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' is owned by '%s'. Permission denied.", labName, labInfo.Owner)})
			return
		}
	}

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	var nodeFilterSlice []string
	if nodeFilter != "" {
		nodeFilterSlice = strings.Split(nodeFilter, ",")
	}

	deployCtx, deployCancel := context.WithTimeout(c.Request.Context(), 10*time.Minute)
	defer deployCancel()

	deployOptions := clab.DeployOptions{
		TopoPath:       topologyPath,
		LabName:        labName,
		Username:       username,
		Reconfigure:    reconfigure,
		MaxWorkers:     uint(maxWorkers),
		ExportTemplate: exportTemplate,
		NodeFilter:     nodeFilterSlice,
		SkipPostDeploy: skipPostDeploy,
		SkipLabDirACLs: skipLabdirAcl,
	}

	if streamLogs {
		var inspectResult models.ClabInspectOutput
		streamLifecycleCommandWithOptions(c, func() error {
			containers, err := svc.Deploy(deployCtx, deployOptions)
			if err != nil {
				return fmt.Errorf("Failed to deploy lab '%s': %s", labName, err.Error())
			}
			inspectResult = clab.ContainersToClabInspectOutput(containers)
			return nil
		}, "", &lifecycleStreamOptions{
			Preamble: buildDeployPreambleLines(),
			OnSuccess: func() []string {
				lines := make([]string, 0, 32)
				lines = append(lines, buildDeployVersionNoticeLines()...)
				lines = append(lines, buildDeploySummaryTableLines(labName, inspectResult)...)
				return lines
			},
		})
		return
	}

	if includeLogs {
		var result models.ClabInspectOutput
		logs, deployErr := captureLifecycleLogs(func() error {
			containers, err := svc.Deploy(deployCtx, deployOptions)
			if err != nil {
				return err
			}
			result = clab.ContainersToClabInspectOutput(containers)
			return nil
		})
		if deployErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("Failed to deploy lab '%s': %s", labName, deployErr.Error()),
				"logs":  logs,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"result": result,
			"logs":   logs,
		})
		return
	}

	containers, deployErr := svc.Deploy(deployCtx, deployOptions)
	if deployErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to deploy lab '%s': %s", labName, deployErr.Error())})
		return
	}

	result := clab.ContainersToClabInspectOutput(containers)
	c.JSON(http.StatusOK, result)
}

// @Summary Apply on-disk topology for lab
// @Description Applies an on-disk topology from the authenticated user's lab directory. If the lab is not running, containerlab apply deploys it; otherwise it reconciles supported topology changes in place.
// @Description
// @Description **Notes**
// @Description - `path` defaults to the running lab topology path when the lab exists, otherwise `<labName>.clab.yml`.
// @Description - `dryRun=true` returns the apply plan without changing the lab.
// @Description - `stream=true` returns `application/x-ndjson` lifecycle events.
// @Description - `includeLogs=true` includes captured lifecycle logs in the JSON response.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab name"
// @Param path query string false "Relative topology file path inside lab directory (defaults to running topology path or <labName>.clab.yml)"
// @Param dryRun query boolean false "Show apply actions without applying them"
// @Param maxWorkers query int false "Limit concurrent workers for new nodes"
// @Param exportTemplate query string false "Custom Go template file for topology data export"
// @Param skipPostDeploy query boolean false "Skip post-deploy actions for added nodes"
// @Param stream query boolean false "Stream lifecycle output as NDJSON events"
// @Param includeLogs query boolean false "Include captured lifecycle logs in the JSON response"
// @Success 200 {object} models.ApplyLabResponse "Apply result"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab or topology file not found"
// @Failure 409 {object} models.ErrorResponse "Conflict"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/apply [post]
// ApplyTopologyHandler applies an on-disk topology identified by lab name.
func ApplyTopologyHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	streamLogs := c.Query("stream") == "true"
	includeLogs := c.Query("includeLogs") == "true"
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}

	dryRun := c.Query("dryRun") == "true"
	maxWorkersStr := c.DefaultQuery("maxWorkers", "0")
	exportTemplate := c.Query("exportTemplate")
	skipPostDeploy := c.Query("skipPostDeploy") == "true"

	if !isValidExportTemplate(exportTemplate) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'exportTemplate' query parameter."})
		return
	}
	maxWorkers, err := strconv.Atoi(maxWorkersStr)
	if err != nil || maxWorkers < 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'maxWorkers' query parameter."})
		return
	}

	releaseLabOperation, ok := beginLabOperationOrConflict(c, labName, "apply")
	if !ok {
		return
	}
	defer releaseLabOperation()

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	checkCtx, checkCancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
	defer checkCancel()

	labInfo, exists, checkErr := getLabInfo(checkCtx, username, labName)
	if checkErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Error checking lab '%s' status: %s", labName, checkErr.Error())})
		return
	}

	targetOwner := username
	if exists {
		if labInfo == nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Error checking lab '%s' status: missing lab information", labName)})
			return
		}
		if !isSuperuser(username) && labInfo.Owner != username {
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("lab '%s' not found or not owned by user", labName)})
			return
		}
		if strings.TrimSpace(labInfo.Owner) != "" {
			targetOwner = labInfo.Owner
		}
	}

	topologyPath := ""
	requestedPath := strings.TrimSpace(c.Query("path"))
	if requestedPath != "" {
		resolvedPath, _, _, _, resolveErr := resolveTopologyFilePath(targetOwner, labName, requestedPath)
		if resolveErr != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: resolveErr.Error()})
			return
		}
		topologyPath = resolvedPath
	} else if exists && strings.TrimSpace(labInfo.AbsLabPath) != "" {
		topologyPath = filepath.Clean(labInfo.AbsLabPath)
	} else {
		labDir, _, _, dirErr := getLabDirectoryInfo(targetOwner, labName)
		if dirErr != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: dirErr.Error()})
			return
		}
		topologyPath = filepath.Join(labDir, labName+".clab.yml")
	}

	if _, statErr := os.Stat(topologyPath); statErr != nil {
		if os.IsNotExist(statErr) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Topology file not found for lab '%s'.", labName)})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to stat topology file: %s", statErr.Error())})
		return
	}

	applyCtx, applyCancel := context.WithTimeout(c.Request.Context(), 10*time.Minute)
	defer applyCancel()

	applyOptions := clab.ApplyOptions{
		TopoPath:       topologyPath,
		Username:       targetOwner,
		DryRun:         dryRun,
		MaxWorkers:     uint(maxWorkers),
		ExportTemplate: exportTemplate,
		SkipPostDeploy: skipPostDeploy,
	}

	runApply := func() (models.ApplyLabResponse, error) {
		result, applyErr := svc.Apply(applyCtx, applyOptions)
		if applyErr != nil {
			return models.ApplyLabResponse{}, fmt.Errorf("Failed to apply lab '%s': %s", labName, applyErr.Error())
		}
		return clab.ApplyResultToResponse(result), nil
	}

	if streamLogs {
		var result models.ApplyLabResponse
		streamLifecycleCommandWithOptions(c, func() error {
			var runErr error
			result, runErr = runApply()
			return runErr
		}, "", &lifecycleStreamOptions{
			Preamble: buildDeployPreambleLines(),
			OnSuccess: func() []string {
				return buildApplySummaryTableLines(result)
			},
		})
		return
	}

	if includeLogs {
		var result models.ApplyLabResponse
		logs, applyErr := captureLifecycleLogs(func() error {
			var runErr error
			result, runErr = runApply()
			return runErr
		})
		if applyErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": applyErr.Error(),
				"logs":  logs,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"result": result,
			"logs":   logs,
		})
		return
	}

	result, applyErr := runApply()
	if applyErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: applyErr.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// @Summary Read lab topology file
// @Description Reads a file from within the specified lab directory using a scoped relative path.
// @Tags Labs
// @Security BearerAuth
// @Produce plain
// @Param labName path string true "Lab name"
// @Param path query string true "Relative file path inside lab directory"
// @Success 200 {string} string "File content"
// @Failure 400 {object} models.ErrorResponse "Invalid path"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "File not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/topology/file [get]
func GetTopologyFileHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	relPath := c.Query("path")

	absPath, _, _, _, err := resolveTopologyFilePath(username, labName, relPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}
	writeTopologyRevisionHeader(c, username, labName, relPath)

	content, readErr := os.ReadFile(absPath)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: "File not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: readErr.Error()})
		return
	}

	c.Data(http.StatusOK, "text/plain; charset=utf-8", content)
}

// @Summary Check lab topology file existence
// @Description Checks whether a file exists inside the specified lab directory.
// @Tags Labs
// @Security BearerAuth
// @Param labName path string true "Lab name"
// @Param path query string true "Relative file path inside lab directory"
// @Success 200 "File exists"
// @Failure 400 "Invalid path"
// @Failure 401 "Unauthorized"
// @Failure 404 "File not found"
// @Failure 500 "Internal server error"
// @Router /api/v1/labs/{labName}/topology/file [head]
func HeadTopologyFileHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	relPath := c.Query("path")

	absPath, _, _, _, err := resolveTopologyFilePath(username, labName, relPath)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	writeTopologyRevisionHeader(c, username, labName, relPath)

	if _, statErr := os.Stat(absPath); statErr != nil {
		if os.IsNotExist(statErr) {
			c.Status(http.StatusNotFound)
			return
		}
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Status(http.StatusOK)
}

// @Summary Write lab topology file
// @Description Writes a file inside the specified lab directory using a scoped relative path.
// @Tags Labs
// @Security BearerAuth
// @Accept plain
// @Produce json
// @Param labName path string true "Lab name"
// @Param path query string true "Relative file path inside lab directory"
// @Param content body string true "File content"
// @Success 200 {object} models.SimpleSuccessResponse "Write success"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/topology/file [put]
func PutTopologyFileHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	relPath := c.Query("path")

	absPath, labDir, uid, gid, err := resolveTopologyFilePath(username, labName, relPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}

	body, readErr := io.ReadAll(c.Request.Body)
	if readErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Failed to read request body"})
		return
	}

	if mkdirErr := ensureLabDirectory(labDir, uid, gid); mkdirErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to ensure lab directory: %s", mkdirErr.Error())})
		return
	}

	if writeErr := os.WriteFile(absPath, body, 0640); writeErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to write file: %s", writeErr.Error())})
		return
	}
	_ = os.Chown(absPath, uid, gid)

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// @Summary Delete lab topology file
// @Description Deletes a file inside the specified lab directory using a scoped relative path.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab name"
// @Param path query string true "Relative file path inside lab directory"
// @Success 200 {object} models.SimpleSuccessResponse "Delete success"
// @Failure 400 {object} models.ErrorResponse "Invalid path"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/topology/file [delete]
func DeleteTopologyFileHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	relPath := c.Query("path")

	absPath, _, _, _, err := resolveTopologyFilePath(username, labName, relPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}

	if unlinkErr := os.Remove(absPath); unlinkErr != nil && !os.IsNotExist(unlinkErr) {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to delete file: %s", unlinkErr.Error())})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// @Summary Rename lab topology file
// @Description Renames or moves a file inside the specified lab directory using scoped relative paths.
// @Tags Labs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param labName path string true "Lab name"
// @Param rename_request body models.TopologyFileRenameRequest true "Old and new relative file paths"
// @Success 200 {object} models.SimpleSuccessResponse "Rename success"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/topology/file/rename [post]
func RenameTopologyFileHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")

	var req models.TopologyFileRenameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	oldPath, _, _, _, oldErr := resolveTopologyFilePath(username, labName, req.OldPath)
	if oldErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: oldErr.Error()})
		return
	}

	newPath, labDir, uid, gid, newErr := resolveTopologyFilePath(username, labName, req.NewPath)
	if newErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: newErr.Error()})
		return
	}

	if ensureErr := ensureLabDirectory(labDir, uid, gid); ensureErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to ensure lab directory: %s", ensureErr.Error())})
		return
	}

	if mkdirErr := os.MkdirAll(filepath.Dir(newPath), 0750); mkdirErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to ensure destination directory: %s", mkdirErr.Error())})
		return
	}
	_ = os.Chown(filepath.Dir(newPath), uid, gid)

	if renameErr := os.Rename(oldPath, newPath); renameErr != nil {
		// Make rename robust for retry/concurrency races used by editor temp-file flows:
		// if source vanished but destination already exists, treat as already-renamed.
		if os.IsNotExist(renameErr) {
			_, statErr := os.Stat(newPath)
			if statErr == nil {
				c.JSON(http.StatusOK, gin.H{"success": true})
				return
			}
			if os.IsNotExist(statErr) {
				c.JSON(http.StatusNotFound, models.ErrorResponse{Error: "Source file not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to stat destination file: %s", statErr.Error())})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to rename file: %s", renameErr.Error())})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func listTopologyEntries(baseDir string) ([]models.TopologyEntry, error) {
	entries := []models.TopologyEntry{}
	entryByLab := map[string]models.TopologyEntry{}

	dirEntries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return entries, nil
		}
		return nil, fmt.Errorf("failed to read labs directory: %w", err)
	}

	for _, entry := range dirEntries {
		if !entry.IsDir() {
			continue
		}

		labName := entry.Name()
		if !isValidLabName(labName) {
			continue
		}

		labDir := filepath.Join(baseDir, labName)
		labDirEntries, readErr := os.ReadDir(labDir)
		if readErr != nil {
			continue
		}

		yamlCandidates := []string{}
		for _, labEntry := range labDirEntries {
			if labEntry.IsDir() {
				continue
			}
			name := labEntry.Name()
			lower := strings.ToLower(name)
			if strings.HasSuffix(lower, ".clab.yml") || strings.HasSuffix(lower, ".clab.yaml") {
				yamlCandidates = append(yamlCandidates, name)
			}
		}
		if len(yamlCandidates) == 0 {
			continue
		}

		sort.Strings(yamlCandidates)
		yamlFileName := yamlCandidates[0]
		preferredYml := labName + ".clab.yml"
		preferredYaml := labName + ".clab.yaml"
		for _, candidate := range yamlCandidates {
			if candidate == preferredYml {
				yamlFileName = candidate
				break
			}
			if candidate == preferredYaml {
				yamlFileName = candidate
			}
		}

		annotationsFileName := yamlFileName + ".annotations.json"
		annotationsPath := filepath.Join(labDir, annotationsFileName)

		_, hasAnnotations := func() (os.FileInfo, bool) {
			info, err := os.Stat(annotationsPath)
			return info, err == nil
		}()

		topologyEntry := models.TopologyEntry{
			LabName:             labName,
			YamlFileName:        yamlFileName,
			AnnotationsFileName: annotationsFileName,
			HasAnnotations:      hasAnnotations,
			DeploymentState:     "undeployed",
		}
		entries = append(entries, topologyEntry)
		entryByLab[labName] = topologyEntry
	}

	for _, entry := range dirEntries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".clab.yml") && !strings.HasSuffix(lower, ".clab.yaml") {
			continue
		}

		labName := name
		if strings.HasSuffix(lower, ".clab.yml") {
			labName = name[:len(name)-len(".clab.yml")]
		} else if strings.HasSuffix(lower, ".clab.yaml") {
			labName = name[:len(name)-len(".clab.yaml")]
		}
		if !isValidLabName(labName) {
			continue
		}
		if _, exists := entryByLab[labName]; exists {
			continue
		}

		annotationsFileName := name + ".annotations.json"
		annotationsPath := filepath.Join(baseDir, annotationsFileName)
		_, hasAnnotations := func() (os.FileInfo, bool) {
			info, err := os.Stat(annotationsPath)
			return info, err == nil
		}()

		topologyEntry := models.TopologyEntry{
			LabName:             labName,
			YamlFileName:        name,
			AnnotationsFileName: annotationsFileName,
			HasAnnotations:      hasAnnotations,
			DeploymentState:     "undeployed",
		}
		entries = append(entries, topologyEntry)
		entryByLab[labName] = topologyEntry
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].LabName < entries[j].LabName
	})

	return entries, nil
}

func getUserLabsBaseDirectory(username string) (string, error) {
	baseDir, _, _, err := getUserLabsBaseDirectoryInfo(username)
	if err != nil {
		return "", fmt.Errorf("failed to resolve labs directory: %w", err)
	}
	return baseDir, nil
}

func resolveCanonicalTopologyRootPath(cleanLabDir, labName, cleanPath string) string {
	// Only allow canonical root-level topology files (no nested paths).
	if strings.Contains(cleanPath, string(filepath.Separator)) {
		return ""
	}

	canonicalNames := map[string]struct{}{
		labName + ".clab.yml":                   {},
		labName + ".clab.yaml":                  {},
		labName + ".clab.yml.annotations.json":  {},
		labName + ".clab.yaml.annotations.json": {},
	}
	if _, ok := canonicalNames[cleanPath]; !ok {
		return ""
	}

	rootDir := filepath.Clean(filepath.Dir(cleanLabDir))
	rootCandidate := filepath.Clean(filepath.Join(rootDir, cleanPath))

	if _, err := os.Stat(rootCandidate); err == nil {
		return rootCandidate
	}

	// For annotations files, prefer the root location when the corresponding
	// root topology YAML exists, even if annotations are being created first.
	if strings.HasSuffix(cleanPath, ".annotations.json") {
		rootYAML := strings.TrimSuffix(rootCandidate, ".annotations.json")
		if _, err := os.Stat(rootYAML); err == nil {
			return rootCandidate
		}
	}

	return ""
}

func resolveTopologyFilePath(username, labName, relPath string) (absolutePath, labDir string, uid, gid int, err error) {
	if !isValidLabName(labName) {
		return "", "", -1, -1, fmt.Errorf("invalid lab name")
	}

	trimmed := strings.TrimSpace(relPath)
	if trimmed == "" {
		return "", "", -1, -1, fmt.Errorf("missing required query parameter 'path'")
	}

	cleanPath := filepath.Clean(trimmed)
	if cleanPath == "." || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) || filepath.IsAbs(cleanPath) {
		return "", "", -1, -1, fmt.Errorf("invalid file path")
	}

	labDir, uid, gid, dirErr := getLabDirectoryInfo(username, labName)
	if dirErr != nil {
		return "", "", -1, -1, dirErr
	}

	cleanLabDir := filepath.Clean(labDir)
	absPath := filepath.Clean(filepath.Join(cleanLabDir, cleanPath))

	// Canonical root fallback is only relevant for managed local lab directories.
	if canonicalRootPath := resolveCanonicalTopologyRootPath(cleanLabDir, labName, cleanPath); canonicalRootPath != "" {
		return canonicalRootPath, cleanLabDir, uid, gid, nil
	}

	if absPath != cleanLabDir && !strings.HasPrefix(absPath, cleanLabDir+string(filepath.Separator)) {
		return "", "", -1, -1, fmt.Errorf("resolved path escapes lab directory")
	}

	return absPath, cleanLabDir, uid, gid, nil
}

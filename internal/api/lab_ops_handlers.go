package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

const (
	maxExecLabelFilters  = 16
	defaultSnapshotDir   = "snapshots"
	snapshotCopyDeadline = 30 * time.Minute
)

// labelKeyRegex accepts Docker/OCI style label keys such as "clab-node-kind" or
// "com.example/role"; labelValueRegex accepts typical label values. Neither
// allows "=" or ",", which containerlab's own label parsing cannot express.
var (
	labelKeyRegex   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$`)
	labelValueRegex = regexp.MustCompile(`^[a-zA-Z0-9._:/@+-]{1,256}$`)
)

// parseNodeNameList splits a comma-separated list of topology node names.
// Empty entries are ignored, duplicates removed; an all-empty list is invalid.
func parseNodeNameList(raw string) ([]string, error) {
	if !isValidNodeFilter(strings.ReplaceAll(raw, " ", "")) {
		return nil, fmt.Errorf("invalid characters in node list")
	}
	var names []string
	seen := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		if !isValidNodeName(name) {
			return nil, fmt.Errorf("invalid node name %q", name)
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("node list must contain at least one node name")
	}
	return names, nil
}

// parseLabelFilter parses a containerlab-style "key=value" label filter.
func parseLabelFilter(raw string) (clab.LabelFilter, error) {
	trimmed := strings.TrimSpace(raw)
	key, value, ok := strings.Cut(trimmed, "=")
	if !ok {
		return clab.LabelFilter{}, fmt.Errorf("label filter %q must use the form key=value", raw)
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if !labelKeyRegex.MatchString(key) {
		return clab.LabelFilter{}, fmt.Errorf("invalid label key %q", key)
	}
	if !labelValueRegex.MatchString(value) {
		return clab.LabelFilter{}, fmt.Errorf("invalid value for label %q", key)
	}
	return clab.LabelFilter{Key: key, Value: value}, nil
}

// execFilterQuery holds the multi-node and label filters of the exec endpoint.
type execFilterQuery struct {
	nodes  []string
	labels []clab.LabelFilter
}

func (q execFilterQuery) active() bool {
	return len(q.nodes) > 0 || len(q.labels) > 0
}

// parseExecFilterQuery reads the `nodes` and repeatable `label` query
// parameters. It writes a 400 response and returns false on invalid input.
func parseExecFilterQuery(c *gin.Context) (execFilterQuery, bool) {
	var query execFilterQuery

	if rawNodes, present := c.GetQuery("nodes"); present {
		nodes, err := parseNodeNameList(rawNodes)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'nodes' query parameter: " + err.Error()})
			return query, false
		}
		query.nodes = nodes
	}

	rawLabels := c.QueryArray("label")
	if len(rawLabels) > maxExecLabelFilters {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("At most %d 'label' filters are allowed.", maxExecLabelFilters)})
		return query, false
	}
	for _, rawLabel := range rawLabels {
		label, err := parseLabelFilter(rawLabel)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'label' query parameter: " + err.Error()})
			return query, false
		}
		query.labels = append(query.labels, label)
	}

	return query, true
}

// runFilteredExec executes a command on the lab containers matched by the
// node and label filters. The lab filter is always applied by the service.
func runFilteredExec(c *gin.Context, svc *clab.Service, username, labName, command string, filters execFilterQuery) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Minute)
	defer cancel()

	log.Infof("ExecCommand user '%s': Executing command on lab '%s' (nodes=%v, labels=%v)...", username, labName, filters.nodes, filters.labels)
	result, err := svc.ExecFiltered(ctx, clab.ExecFilterOptions{
		LabName:   labName,
		NodeNames: filters.nodes,
		Labels:    filters.labels,
		Commands:  []string{command},
		Username:  username,
	})
	if errors.Is(err, clab.ErrNoMatchingContainers) {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("No nodes in lab '%s' match the given 'nodes'/'label' filters.", labName)})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to execute command on lab '%s': %s", labName, err.Error())})
		return
	}

	log.Infof("ExecCommand user '%s': Command executed successfully on lab '%s'.", username, labName)
	c.JSON(http.StatusOK, clab.ExecCollectionToExecResponse(result))
}

// parseLifecycleNodeFilter reads the optional comma-separated `nodeFilter`
// query parameter of the lab-level start/stop/restart endpoints.
func parseLifecycleNodeFilter(c *gin.Context) ([]string, bool) {
	raw, present := c.GetQuery("nodeFilter")
	if !present {
		return nil, true
	}
	nodes, err := parseNodeNameList(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'nodeFilter' query parameter: " + err.Error()})
		return nil, false
	}
	return nodes, true
}

// verifyLifecycleNodesExist writes a 404 and returns false when a requested
// node has no container in the lab, so a typo never acts on other nodes.
func verifyLifecycleNodesExist(c *gin.Context, svc *clab.Service, labName string, nodes []string) bool {
	if len(nodes) == 0 {
		return true
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
	defer cancel()

	missing, err := svc.MissingLabNodes(ctx, labName, nodes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to list nodes of lab '%s': %s", labName, err.Error())})
		return false
	}
	if len(missing) > 0 {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Node(s) not found in lab '%s': %s", labName, strings.Join(missing, ", "))})
		return false
	}
	return true
}

// lifecycleSuccessMessage describes a lab-level lifecycle action.
func lifecycleSuccessMessage(labName string, action clab.NodeLifecycleAction, nodes []string) string {
	if len(nodes) == 0 {
		return fmt.Sprintf("Lab '%s' nodes %s successfully.", labName, lifecyclePastTense(action))
	}
	return fmt.Sprintf("Lab '%s' nodes %s %s successfully.", labName, strings.Join(nodes, ", "), lifecyclePastTense(action))
}

// lifecycleErrorStatus maps containerlab's rejection of unknown nodes to 400.
func lifecycleErrorStatus(err error) int {
	if errors.Is(err, clab.ErrIncorrectInput) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// inspectLabDetails responds with `containerlab inspect --details` output for one lab.
func inspectLabDetails(c *gin.Context, svc *clab.Service, username, labName string) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
	defer cancel()

	details, err := svc.InspectLabDetails(ctx, clab.InspectOptions{
		LabName:  labName,
		Username: username,
		Details:  true,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to inspect lab '%s': %s", labName, err.Error())})
		return
	}
	if len(details[labName]) == 0 {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' not found.", labName)})
		return
	}
	c.JSON(http.StatusOK, gin.H{labName: details[labName]})
}

// parseRequiredLabPathQuery returns the value of an optional lab path query
// parameter. A present but blank value is rejected with 400.
func parseRequiredLabPathQuery(c *gin.Context, param string) (string, bool, bool) {
	raw, present := c.GetQuery(param)
	if !present {
		return "", false, true
	}
	if strings.TrimSpace(raw) == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("'%s' query parameter must not be empty.", param)})
		return "", true, false
	}
	return raw, true, true
}

// resolveLabOutputDir resolves a lab path that the server will write into and
// makes sure its confinement root exists.
func resolveLabOutputDir(username, topoPath, raw string) (resolvedLabPath, error) {
	scope, err := labPathScopeFor(username, topoPath)
	if err != nil {
		return resolvedLabPath{}, err
	}
	resolved, err := scope.resolve(raw)
	if err != nil {
		return resolvedLabPath{}, err
	}
	if info, statErr := os.Stat(resolved.Path); statErr == nil && !info.IsDir() {
		return resolvedLabPath{}, fmt.Errorf("%s exists and is not a directory", resolved.display())
	}
	return resolved, nil
}

// ensureLabPathRoot creates a missing workspace root before writing below it.
func ensureLabPathRoot(resolved resolvedLabPath) error {
	if _, err := os.Stat(resolved.Root); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if resolved.Shared {
		return fmt.Errorf("shared labs root does not exist")
	}
	return ensureWorkspaceRoot(resolved.Root, resolved.UID, resolved.GID)
}

func (p resolvedLabPath) outputDir() clab.OutputDir {
	return clab.OutputDir{Root: p.Root, Rel: p.Rel, UID: p.UID, GID: p.GID}
}

// displayChild returns the display form of an absolute path below p's root.
func (p resolvedLabPath) displayChild(absPath string) string {
	rel, err := filepath.Rel(p.Root, absPath)
	if err != nil || !filepath.IsLocal(rel) {
		return absPath
	}
	child := p
	child.Path = absPath
	child.Rel = rel
	return child.display()
}

// @Summary Save VM snapshots
// @Description Saves VM snapshots of vrnetlab-based nodes, like `containerlab tools snapshot save`. Each snapshot is written to `<outputDir>/<node>.tar`; non-vrnetlab nodes are skipped.
// @Description
// @Description **Notes**
// @Description - `outputDir` is relative to the lab's topology directory (or absolute) and must stay inside the user's workspace, or the shared root for shared labs. Defaults to `snapshots`.
// @Description - `timeout` is the per-node wait as a Go duration (default `5m`, maximum `30m`).
// @Description - Nodes run concurrently. The response is 200 even when nodes fail; read each result's `status` (`success`, `failed`, `skipped`).
// @Description - The lab is locked for other lifecycle operations while snapshots run.
// @Tags Labs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param labName path string true "Name of the lab"
// @Param snapshot_request body models.SnapshotSaveRequest false "Snapshot options"
// @Success 200 {object} models.SnapshotSaveResponse "Per-node snapshot results"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab or node not found"
// @Failure 409 {object} models.ErrorResponse "Lab busy with another operation"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/snapshots [post]
func SaveLabSnapshotsHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")

	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}

	var req models.SnapshotSaveRequest
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}
	nodes, timeout, outputDir, err := validateSnapshotRequest(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}

	releaseLabOperation, ok := beginLabOperationOrConflict(c, labName, "snapshot")
	if !ok {
		return
	}
	defer releaseLabOperation()

	originalTopoPath, ownerCheckErr := verifyLabOwnership(c, username, labName)
	if ownerCheckErr != nil {
		return
	}

	resolved, err := resolveLabOutputDir(username, originalTopoPath, outputDir)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'outputDir': " + err.Error()})
		return
	}
	if err := ensureLabPathRoot(resolved); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to prepare output directory: " + err.Error()})
		return
	}

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), timeout+snapshotCopyDeadline)
	defer cancel()

	log.Infof("SaveLabSnapshots user '%s': Saving snapshots for lab '%s' to '%s'...", username, labName, resolved.Path)
	results, err := svc.SaveSnapshots(ctx, clab.SnapshotSaveOptions{
		LabName:   labName,
		NodeNames: nodes,
		Output:    resolved.outputDir(),
		Timeout:   timeout,
	})
	if errors.Is(err, clab.ErrSnapshotNodesNotFound) {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to save snapshots for lab '%s': %s", labName, err.Error())})
		return
	}

	c.JSON(http.StatusOK, buildSnapshotSaveResponse(resolved, results))
}

// validateSnapshotRequest checks the snapshot request and applies defaults.
func validateSnapshotRequest(req models.SnapshotSaveRequest) (nodes []string, timeout time.Duration, outputDir string, err error) {
	seen := map[string]struct{}{}
	for _, node := range req.Nodes {
		name := strings.TrimSpace(node)
		if !isValidNodeName(name) {
			return nil, 0, "", fmt.Errorf("invalid node name %q in 'nodes'", node)
		}
		if _, dup := seen[name]; !dup {
			seen[name] = struct{}{}
			nodes = append(nodes, name)
		}
	}

	timeout = clab.DefaultSnapshotTimeout
	if req.Timeout != nil {
		parsed, parseErr := time.ParseDuration(strings.TrimSpace(*req.Timeout))
		if parseErr != nil || parsed < time.Second || parsed > clab.MaxSnapshotTimeout {
			return nil, 0, "", fmt.Errorf("invalid 'timeout': use a duration between 1s and %s, like '5m'", clab.MaxSnapshotTimeout)
		}
		timeout = parsed
	}

	outputDir = defaultSnapshotDir
	if req.OutputDir != nil {
		if strings.TrimSpace(*req.OutputDir) == "" {
			return nil, 0, "", fmt.Errorf("'outputDir' must not be empty")
		}
		outputDir = *req.OutputDir
	}
	return nodes, timeout, outputDir, nil
}

// buildSnapshotSaveResponse converts service results to the API response.
func buildSnapshotSaveResponse(outputDir resolvedLabPath, results []clab.SnapshotNodeResult) models.SnapshotSaveResponse {
	response := models.SnapshotSaveResponse{
		OutputDir: outputDir.display(),
		Results:   make([]models.SnapshotNodeResult, 0, len(results)),
		Summary:   clab.SummarizeSnapshotResults(results),
	}
	for _, result := range results {
		item := models.SnapshotNodeResult{
			Node:       result.Node,
			Status:     result.Status,
			SizeBytes:  result.SizeBytes,
			DurationMs: result.Duration.Milliseconds(),
			Error:      result.Error,
			Reason:     result.Reason,
		}
		if result.Status == clab.SnapshotStatusSuccess && result.Path != "" {
			item.Path = outputDir.displayChild(result.Path)
		}
		response.Results = append(response.Results, item)
	}
	return response
}

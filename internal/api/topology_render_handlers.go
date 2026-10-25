package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// literalTopologyNameRegex matches a literal top-level `name:` line, which is
// still readable when a topology template is not valid YAML.
var literalTopologyNameRegex = regexp.MustCompile(`(?m)^name:[ \t]*(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s#"'{][^\s#]*))[ \t]*(?:#.*)?\r?$`)

// errTopologyInputNotFound marks a topology or vars file that does not exist.
var errTopologyInputNotFound = errors.New("file not found")

// topologyInput is a topology file resolved inside a workspace.
type topologyInput struct {
	absPath string
	// root is the workspace root the topology belongs to; vars files and
	// subtemplates must stay inside it.
	root string
}

// relativeToTopologyDir returns absPath relative to the topology directory, the
// form in which varsPath is given.
func (in topologyInput) relativeToTopologyDir(absPath string) string {
	rel, err := filepath.Rel(filepath.Dir(in.absPath), absPath)
	if err != nil {
		return filepath.Base(absPath)
	}
	return filepath.ToSlash(rel)
}

// topologyWorkspaceRoot returns the shared or personal workspace root containing
// topoAbsPath. Topologies outside every known workspace are confined to their
// own directory.
func topologyWorkspaceRoot(topoAbsPath string, usernames ...string) string {
	if sharedRootContains(topoAbsPath) {
		return filepath.Clean(sharedLabsRoot())
	}
	for _, username := range usernames {
		if strings.TrimSpace(username) == "" {
			continue
		}
		root, _, _, err := getUserWorkspaceDirectory(username)
		if err == nil && pathIsInsideRoot(root, topoAbsPath) {
			return filepath.Clean(root)
		}
	}
	return filepath.Dir(filepath.Clean(topoAbsPath))
}

// resolveTopologyInput resolves a topology file exactly like the topology file
// endpoints and checks that it exists inside the workspace. Errors other than
// errTopologyInputNotFound are invalid input.
func resolveTopologyInput(username, labName, requestedPath string) (topologyInput, error) {
	absPath, _, _, _, err := resolveTopologyFilePath(username, labName, requestedPath)
	if err != nil {
		return topologyInput{}, err
	}
	input := topologyInput{absPath: absPath, root: topologyWorkspaceRoot(absPath, username)}
	if err := requireExistingWorkspaceFile(input.root, absPath, strings.TrimSpace(requestedPath)); err != nil {
		return topologyInput{}, err
	}
	return input, nil
}

// resolveVarsPath resolves varsPath relative to the topology directory, like
// containerlab --vars run from there. The file must stay inside the topology's
// workspace root.
func (in topologyInput) resolveVarsPath(varsPath string) (string, error) {
	trimmed := strings.TrimSpace(varsPath)
	if filepath.IsAbs(trimmed) {
		return "", fmt.Errorf("varsPath must be relative to the topology directory")
	}
	absPath := filepath.Clean(filepath.Join(filepath.Dir(in.absPath), filepath.FromSlash(trimmed)))
	if absPath == in.root || !pathIsInsideRoot(in.root, absPath) {
		return "", fmt.Errorf("varsPath resolves outside the workspace")
	}
	if err := requireExistingWorkspaceFile(in.root, absPath, trimmed); err != nil {
		return "", err
	}
	return absPath, nil
}

// requireExistingWorkspaceFile checks that absPath is an existing file inside root.
func requireExistingWorkspaceFile(root, absPath, displayPath string) error {
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", errTopologyInputNotFound, displayPath)
		}
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("path %q is a directory", displayPath)
	}
	return requireInsideWorkspace(root, absPath)
}

// requireInsideWorkspace rejects files whose real location, after following
// symbolic links, is outside root. Containerlab reads topology inputs with the
// server's privileges, so links must not reach files outside the workspace.
func requireInsideWorkspace(root, absPath string) error {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("failed to resolve workspace directory: %w", err)
	}
	realPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return fmt.Errorf("failed to resolve %s: %w", filepath.Base(absPath), err)
	}
	if !pathIsInsideRoot(realRoot, realPath) {
		return fmt.Errorf("%s resolves outside the workspace", filepath.Base(absPath))
	}
	return nil
}

// writeTopologyInputError maps a topology or vars file resolution error to a
// JSON response.
func writeTopologyInputError(c *gin.Context, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, errTopologyInputNotFound) {
		status = http.StatusNotFound
	}
	c.JSON(status, models.ErrorResponse{Error: err.Error()})
}

// varsFilesFromQuery resolves the optional varsPath query parameter relative to
// the topology at topoAbsPath into the vars files passed to containerlab.
// usernames name the personal workspaces the topology may belong to. It writes
// the error response and returns false when the parameter is invalid; nil keeps
// containerlab's vars file discovery.
func varsFilesFromQuery(c *gin.Context, topoAbsPath string, usernames ...string) ([]string, bool) {
	varsPath := strings.TrimSpace(c.Query("varsPath"))
	if varsPath == "" {
		return nil, true
	}
	if !filepath.IsAbs(topoAbsPath) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "varsPath requires a local topology file"})
		return nil, false
	}
	topology := topologyInput{absPath: filepath.Clean(topoAbsPath), root: topologyWorkspaceRoot(topoAbsPath, usernames...)}
	absPath, err := topology.resolveVarsPath(varsPath)
	if err != nil {
		writeTopologyInputError(c, err)
		return nil, false
	}
	return []string{absPath}, true
}

// runningLabVarsFilesFromQuery resolves varsPath relative to a running lab's
// topology, which may live in the lab owner's workspace.
func runningLabVarsFilesFromQuery(ctx context.Context, c *gin.Context, username, labName, topoAbsPath string) ([]string, bool) {
	if strings.TrimSpace(c.Query("varsPath")) == "" {
		return nil, true
	}
	usernames := []string{username}
	if info, exists, err := getLabInfo(ctx, username, labName); err == nil && exists && info != nil && info.Owner != "" {
		usernames = append(usernames, info.Owner)
	}
	return varsFilesFromQuery(c, topoAbsPath, usernames...)
}

// topologyContentLabName returns the top-level name of topology content. A
// literal name line is used when the content is not valid YAML.
func topologyContentLabName(content []byte) string {
	var topology struct {
		Name string `yaml:"name"`
	}
	if yaml.Unmarshal(content, &topology) == nil {
		return strings.TrimSpace(topology.Name)
	}
	match := literalTopologyNameRegex.FindSubmatch(content)
	if match == nil {
		return ""
	}
	for _, group := range match[1:] {
		if len(group) > 0 {
			return strings.TrimSpace(string(group))
		}
	}
	return ""
}

// @Summary Render lab topology file
// @Description Renders a topology file the way containerlab does before deploying it: Go template execution with variables from `<topology name without extension>_vars.{yaml,yml,json}` or `varsPath`, `clab_templates/*.gotmpl` subtemplates, and `${VAR:=default}` environment expansion. Nothing is deployed and no lab state changes.
// @Description
// @Description **Notes**
// @Description - `path` resolves like the topology file endpoints. `varsPath` is relative to the topology file's directory (like `containerlab --vars` run from there) and must stay inside the topology's workspace.
// @Description - `varsFiles` lists the variable files used, relative to the topology file's directory.
// @Description - A topology that renders but is rejected by containerlab returns 200 with the rendered content and `error` set.
// @Description - Template parse or execution errors return 422.
// @Description Shared workspace paths start with @shared/ when CLAB_SHARED_LABS_ROOT is configured; all authenticated API users can access them.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab name"
// @Param path query string true "Workspace-relative path from the topology listing, or legacy lab-relative path"
// @Param varsPath query string false "Template variables file relative to the topology file's directory (like --vars); defaults to containerlab's vars file discovery"
// @Success 200 {object} models.RenderedTopologyResponse "Rendered topology"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Topology or vars file not found"
// @Failure 422 {object} models.ErrorResponse "Topology template could not be rendered"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/topology/rendered [get]
// RenderTopologyHandler returns a topology file rendered by containerlab.
func RenderTopologyHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}

	requestedPath := strings.TrimSpace(c.Query("path"))
	if requestedPath == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "missing required query parameter 'path'"})
		return
	}
	topology, err := resolveTopologyInput(username, labName, requestedPath)
	if err != nil {
		writeTopologyInputError(c, err)
		return
	}

	var explicitVars []string
	varsFiles := []string{}
	if varsPath := strings.TrimSpace(c.Query("varsPath")); varsPath != "" {
		varsAbsPath, err := topology.resolveVarsPath(varsPath)
		if err != nil {
			writeTopologyInputError(c, err)
			return
		}
		explicitVars = []string{varsAbsPath}
		varsFiles = append(varsFiles, topology.relativeToTopologyDir(varsAbsPath))
	} else {
		discovered, err := clab.TopologyVarsFiles(topology.absPath, nil)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to find template variable files: %s", err.Error())})
			return
		}
		for _, varsFile := range discovered {
			if err := requireInsideWorkspace(topology.root, varsFile); err != nil {
				c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
				return
			}
			varsFiles = append(varsFiles, topology.relativeToTopologyDir(varsFile))
		}
	}

	subtemplates, err := clab.TopologySubtemplates(topology.absPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to find topology subtemplates: %s", err.Error())})
		return
	}
	for _, subtemplate := range subtemplates {
		if err := requireInsideWorkspace(topology.root, subtemplate); err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
			return
		}
	}

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	rendered, err := svc.RenderTopology(topology.absPath, explicitVars)
	if err != nil {
		var templateErr *clab.TopologyTemplateError
		if errors.As(err, &templateErr) {
			c.JSON(http.StatusUnprocessableEntity, models.ErrorResponse{Error: templateErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to render topology: %s", err.Error())})
		return
	}

	response := models.RenderedTopologyResponse{
		Path:      requestedPath,
		Content:   string(rendered.Content),
		LabName:   clab.ExpandLabNameGitTokens(topologyContentLabName(rendered.Content), filepath.Dir(topology.absPath)),
		VarsFiles: varsFiles,
	}
	if rendered.LoadError != nil {
		response.Error = rendered.LoadError.Error()
	}
	c.JSON(http.StatusOK, response)
}

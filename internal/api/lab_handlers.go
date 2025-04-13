// internal/api/lab_handlers.go
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"github.com/srl-labs/clab-api-server/internal/auth"
	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// @Summary Deploy Lab
// @Description Deploys a containerlab topology. Requires EITHER 'topologyContent' OR 'topologySourceUrl' in the request body, but not both.
// @Description Optional deployment flags are provided as query parameters.
// @Tags Labs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param deploy_request body models.DeployRequest true "Deployment Source: Provide 'topologyContent' OR 'topologySourceUrl'."
// @Param labNameOverride query string false "Overrides the 'name' field within the topology or inferred from URL." example="my-specific-lab-run"
// @Param reconfigure query boolean false "Destroy lab and clean directory before deploying (default: false)." example="true"
// @Param maxWorkers query int false "Limit concurrent workers (0 or omit for default)." example="4"
// @Param exportTemplate query string false "Custom Go template file for topology data export ('__full' for full export)." example="__full"
// @Param nodeFilter query string false "Comma-separated list of node names to deploy." example="srl1,router2"
// @Param skipPostDeploy query boolean false "Skip post-deploy actions defined for nodes (default: false)." example="false"
// @Param skipLabdirAcl query boolean false "Skip setting extended ACLs on lab directory (default: false)." example="true"
// @Success 200 {object} object "Raw JSON output from 'clab deploy' (or plain text on error)"
// @Failure 400 {object} models.ErrorResponse "Invalid input (e.g., missing/both content/URL, invalid flags/params)"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error (e.g., file system errors, clab execution failed)"
// @Router /api/v1/labs [post]
func DeployLabHandler(c *gin.Context) {
	username := c.GetString("username") // Authenticated user

	// --- Bind Request Body (Only contains topology source now) ---
	var req models.DeployRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("DeployLab failed for user '%s': Invalid request body: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	// --- Validate Input: Must have Content XOR URL ---
	hasContent := strings.TrimSpace(req.TopologyContent) != ""
	hasUrl := strings.TrimSpace(req.TopologySourceUrl) != ""

	if !hasContent && !hasUrl {
		log.Warnf("DeployLab failed for user '%s': Request body must include either 'topologyContent' or 'topologySourceUrl'", username)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Request body must include either 'topologyContent' or 'topologySourceUrl'"})
		return
	}
	if hasContent && hasUrl {
		log.Warnf("DeployLab failed for user '%s': Request body cannot include both 'topologyContent' and 'topologySourceUrl'", username)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Request body cannot include both 'topologyContent' and 'topologySourceUrl'"})
		return
	}

	// --- Get & Validate Optional Query Parameters ---
	labNameOverride := c.Query("labNameOverride")
	reconfigure := c.Query("reconfigure") == "true" // Simple bool conversion
	maxWorkersStr := c.DefaultQuery("maxWorkers", "0")
	exportTemplate := c.Query("exportTemplate")
	nodeFilter := c.Query("nodeFilter")
	skipPostDeploy := c.Query("skipPostDeploy") == "true"
	skipLabdirAcl := c.Query("skipLabdirAcl") == "true"

	// Validate query param values
	if labNameOverride != "" && !isValidLabName(labNameOverride) {
		log.Warnf("DeployLab failed for user '%s': Invalid characters in labNameOverride query param '%s'", username, labNameOverride)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in 'labNameOverride' query parameter."})
		return
	}
	if !isValidNodeFilter(nodeFilter) {
		log.Warnf("DeployLab failed for user '%s': Invalid characters in nodeFilter query param '%s'", username, nodeFilter)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in 'nodeFilter' query parameter."})
		return
	}
	if !isValidExportTemplate(exportTemplate) {
		log.Warnf("DeployLab failed for user '%s': Invalid exportTemplate query param '%s'", username, exportTemplate)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'exportTemplate' query parameter."})
		return
	}
	maxWorkers, err := strconv.Atoi(maxWorkersStr)
	if err != nil || maxWorkers < 0 {
		log.Warnf("DeployLab failed for user '%s': Invalid maxWorkers query param '%s'", username, maxWorkersStr)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'maxWorkers' query parameter: must be a non-negative integer."})
		return
	}

	// --- Prepare Base Arguments ---
	args := []string{"deploy", "--format", "json"}

	// --- Handle Topology Source and Lab Name ---
	var labName string // Will hold the determined lab name for logging/cleanup reference
	var topoPathForClab string

	if hasUrl {
		log.Infof("DeployLab user '%s': Deploying from URL: %s", username, req.TopologySourceUrl)
		_, urlErr := url.ParseRequestURI(req.TopologySourceUrl)
		isShortcut := !strings.Contains(req.TopologySourceUrl, "/") && !strings.Contains(req.TopologySourceUrl, ":")
		if urlErr != nil && !isShortcut && !strings.HasPrefix(req.TopologySourceUrl, "http") {
			log.Warnf("DeployLab failed for user '%s': Invalid topologySourceUrl format: %s", username, req.TopologySourceUrl)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid topologySourceUrl format"})
			return
		}
		topoPathForClab = req.TopologySourceUrl
		if labNameOverride != "" {
			labName = labNameOverride
		} else {
			labName = "<determined_by_clab_from_url>"
		}
	} else { // hasContent
		log.Infof("DeployLab user '%s': Deploying from provided topology content.", username)
		trimmedContent := strings.TrimSpace(req.TopologyContent)

		// --- Get User Home Directory, UID/GID, Parse YAML, Determine Lab Name ---
		usr, err := user.Lookup(username)
		if err != nil {
			log.Errorf("DeployLab failed for user '%s': Could not determine user details: %v", username, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Could not determine user details."})
			return
		}
		homeDir := usr.HomeDir
		uid, err := strconv.Atoi(usr.Uid)
		if err != nil {
			log.Errorf("DeployLab failed for user '%s': Could not process user UID: %v", username, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Could not process user UID."})
			return
		}
		gid, err := strconv.Atoi(usr.Gid)
		if err != nil {
			log.Errorf("DeployLab failed for user '%s': Could not process user GID: %v", username, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Could not process user GID."})
			return
		}

		var topoData map[string]interface{}
		err = yaml.Unmarshal([]byte(trimmedContent), &topoData)
		if err != nil {
			log.Warnf("DeployLab failed for user '%s': Invalid topology YAML: %v", username, err)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid topology YAML: " + err.Error()})
			return
		}
		originalLabNameValue, ok := topoData["name"]
		if !ok {
			log.Warnf("DeployLab failed for user '%s': Topology YAML missing 'name' field", username)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Topology YAML must contain a top-level 'name' field."})
			return
		}
		originalLabName, ok := originalLabNameValue.(string)
		if !ok || originalLabName == "" {
			log.Warnf("DeployLab failed for user '%s': Topology 'name' field is not a non-empty string", username)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Topology 'name' field must be a non-empty string."})
			return
		}
		if !isValidLabName(originalLabName) {
			log.Warnf("DeployLab failed for user '%s': Invalid characters in topology 'name': %s", username, originalLabName)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in topology 'name'."})
			return
		}

		// Determine effective lab name
		if labNameOverride != "" {
			labName = labNameOverride
		} else {
			labName = originalLabName
		}

		// --- Construct Paths, Create Dirs, Set Ownership, Write File ---
		clabUserDir := filepath.Join(homeDir, ".clab")
		targetDir := filepath.Join(clabUserDir, originalLabName)
		targetFilePath := filepath.Join(targetDir, originalLabName+".clab.yml")
		topoPathForClab = targetFilePath

		err = os.MkdirAll(targetDir, 0750)
		if err != nil {
			log.Errorf("DeployLab failed for user '%s': Failed to create lab directory '%s': %v", username, targetDir, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to create lab directory: %s.", err.Error())})
			return
		}
		err = os.Chown(targetDir, uid, gid)
		if err != nil {
			log.Errorf("DeployLab failed for user '%s': Failed to set ownership on lab directory '%s': %v", username, targetDir, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to set ownership on lab directory: %s.", err.Error())})
			return
		}
		err = os.WriteFile(targetFilePath, []byte(trimmedContent), 0640)
		if err != nil {
			log.Errorf("DeployLab failed for user '%s': Failed to write topology file '%s': %v", username, targetFilePath, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to write topology file: %s.", err.Error())})
			return
		}
		err = os.Chown(targetFilePath, uid, gid)
		if err != nil {
			log.Errorf("DeployLab failed for user '%s': Failed to set ownership on topology file '%s': %v", username, targetFilePath, err)
			_ = os.Remove(targetFilePath) // Attempt cleanup
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to set ownership on topology file: %s.", err.Error())})
			return
		}
		log.Infof("Saved topology and set ownership for user '%s' lab '%s' to '%s'", username, originalLabName, targetFilePath)
	}

	// --- Add Topology Path/URL to Args ---
	args = append(args, "--topo", topoPathForClab)

	// --- Add Optional Flags from Query Params to Args ---
	if labNameOverride != "" {
		args = append(args, "--name", labNameOverride)
	}
	if reconfigure {
		args = append(args, "--reconfigure")
	}
	if maxWorkers > 0 { // Only add if explicitly set > 0
		args = append(args, "--max-workers", strconv.Itoa(maxWorkers))
	}
	if exportTemplate != "" {
		args = append(args, "--export-template", exportTemplate)
	}
	if nodeFilter != "" {
		args = append(args, "--node-filter", nodeFilter)
	}
	if skipPostDeploy {
		args = append(args, "--skip-post-deploy")
	}
	if skipLabdirAcl {
		args = append(args, "--skip-labdir-acl")
	}

	// --- Execute clab deploy ---
	log.Infof("DeployLab user '%s': Executing clab deploy for lab '%s'...", username, labName)
	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	// --- Handle command execution results ---
	if stderr != "" {
		log.Warnf("DeployLab user '%s', lab '%s': clab deploy stderr: %s", username, labName, stderr)
	}
	if err != nil {
		log.Errorf("DeployLab failed for user '%s', lab '%s': clab deploy command execution error: %v", username, labName, err)
		errMsg := fmt.Sprintf("Failed to deploy lab '%s': %s", labName, err.Error())
		// Only append stderr to the response if it looks like a significant error message
		if stderr != "" && (strings.Contains(stderr, "level=error") || strings.Contains(stderr, "failed") || strings.Contains(stderr, "panic")) {
			errMsg += "\nstderr: " + stderr
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	log.Infof("DeployLab user '%s': clab deploy for lab '%s' executed successfully.", username, labName)

	// --- Parse and return result ---
	var result interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		log.Warnf("DeployLab user '%s', lab '%s': Output from clab was not valid JSON: %v. Returning as plain text.", username, labName, err)
		// Check if the non-JSON output indicates an error
		if strings.Contains(stdout, "level=error") || strings.Contains(stdout, "failed") {
			c.JSON(http.StatusInternalServerError, gin.H{"output": stdout, "warning": "Deployment finished but output indicates errors and was not valid JSON"})
		} else {
			c.JSON(http.StatusOK, gin.H{"output": stdout, "warning": "Output was not valid JSON"})
		}
		return
	}

	c.JSON(http.StatusOK, result)
}

// @Summary Deploy Lab from Archive
// @Description Deploys a containerlab topology provided as a .zip or .tar.gz archive. The archive must contain the .clab.yml file and any necessary bind-mount files/directories.
// @Description The lab name is taken from the 'labName' query parameter. The archive is extracted to the user's ~/.clab/<labName>/ directory.
// @Tags Labs
// @Security BearerAuth
// @Accept multipart/form-data
// @Produce json
// @Param labArchive formData file true "Lab archive (.zip or .tar.gz) containing topology file and bind mounts."
// @Param labName query string true "Name for the lab. This determines the extraction directory (~/.clab/<labName>)." example="my-archived-lab"
// @Param reconfigure query boolean false "Destroy lab and clean directory before deploying (default: false)." example="true"
// @Param maxWorkers query int false "Limit concurrent workers (0 or omit for default)." example="4"
// @Param exportTemplate query string false "Custom Go template file for topology data export ('__full' for full export)." example="__full"
// @Param nodeFilter query string false "Comma-separated list of node names to deploy." example="srl1,router2"
// @Param skipPostDeploy query boolean false "Skip post-deploy actions defined for nodes (default: false)." example="false"
// @Param skipLabdirAcl query boolean false "Skip setting extended ACLs on lab directory (default: false)." example="true"
// @Success 200 {object} object "Raw JSON output from 'clab deploy' (or plain text on error)"
// @Failure 400 {object} models.ErrorResponse "Invalid input (e.g., missing archive, invalid labName, invalid archive format, missing topology file in archive)"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error (e.g., file system errors, extraction errors, clab execution failed)"
// @Router /api/v1/labs/archive [post]
func DeployLabArchiveHandler(c *gin.Context) {
	username := c.GetString("username")

	// --- Get User Details (uid, gid, homeDir) ---
	usr, err := user.Lookup(username)
	if err != nil {
		log.Errorf("DeployLab (Archive) failed for user '%s': Could not determine user details: %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Could not determine user details."})
		return
	}
	uid, uidErr := strconv.Atoi(usr.Uid)
	gid, gidErr := strconv.Atoi(usr.Gid)
	if uidErr != nil || gidErr != nil {
		log.Errorf("DeployLab (Archive) failed for user '%s': Could not process user UID/GID: %v / %v", username, uidErr, gidErr)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Could not process user UID/GID."})
		return
	}
	homeDir := usr.HomeDir

	// --- Get Lab Name (Required Query Parameter) ---
	labName := c.Query("labName")
	if labName == "" {
		log.Warnf("DeployLab (Archive) failed for user '%s': Missing required 'labName' query parameter", username)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Missing required 'labName' query parameter."})
		return
	}
	if !isValidLabName(labName) {
		log.Warnf("DeployLab (Archive) failed for user '%s': Invalid characters in labName query param '%s'", username, labName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in 'labName' query parameter."})
		return
	}
	log.Debugf("DeployLab (Archive) user '%s': Preparing lab '%s'", username, labName)

	// --- Get & Validate Optional Query Parameters ---
	reconfigure := c.Query("reconfigure") == "true"
	maxWorkersStr := c.DefaultQuery("maxWorkers", "0")
	exportTemplate := c.Query("exportTemplate")
	nodeFilter := c.Query("nodeFilter")
	skipPostDeploy := c.Query("skipPostDeploy") == "true"
	skipLabdirAcl := c.Query("skipLabdirAcl") == "true"

	// Validate query param values
	if !isValidNodeFilter(nodeFilter) {
		log.Warnf("DeployLab (Archive) failed for user '%s', lab '%s': Invalid nodeFilter '%s'", username, labName, nodeFilter)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in 'nodeFilter' query parameter."})
		return
	}
	if !isValidExportTemplate(exportTemplate) {
		log.Warnf("DeployLab (Archive) failed for user '%s', lab '%s': Invalid exportTemplate '%s'", username, labName, exportTemplate)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'exportTemplate' query parameter."})
		return
	}
	maxWorkers, err := strconv.Atoi(maxWorkersStr)
	if err != nil || maxWorkers < 0 {
		log.Warnf("DeployLab (Archive) failed for user '%s', lab '%s': Invalid maxWorkers '%s'", username, labName, maxWorkersStr)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'maxWorkers' query parameter: must be a non-negative integer."})
		return
	}

	// --- Prepare Target Directory ---
	targetDir := filepath.Join(homeDir, ".clab", labName)
	// Clean up existing directory if reconfigure is true *before* extraction
	if reconfigure {
		log.Infof("DeployLab (Archive) user '%s': Reconfigure requested. Removing existing directory '%s' before extraction.", username, targetDir)
		if err := os.RemoveAll(targetDir); err != nil {
			log.Warnf("DeployLab (Archive) user '%s': Failed to remove existing directory '%s' during reconfigure: %v. Continuing...", username, targetDir, err)
			// Don't necessarily fail here, MkdirAll might still work or handle it.
		}
	}

	if err := os.MkdirAll(targetDir, 0750); err != nil {
		log.Errorf("DeployLab (Archive) failed for user '%s': Failed to create lab directory '%s': %v", username, targetDir, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to create lab directory."})
		return
	}
	if err := os.Chown(targetDir, uid, gid); err != nil {
		// Log warning but continue. Extraction might still work if API user has permissions.
		log.Warnf("DeployLab (Archive) user '%s': Failed to set ownership on lab directory '%s': %v. Continuing...", username, targetDir, err)
	} else {
		log.Debugf("DeployLab (Archive) user '%s': Ensured lab directory '%s' exists with correct ownership.", username, targetDir)
	}

	// --- Process Uploaded Archive ---
	fileHeader, err := c.FormFile("labArchive") // Field name in the multipart form
	if err != nil {
		if err == http.ErrMissingFile {
			log.Warnf("DeployLab (Archive) failed for user '%s': Missing 'labArchive' file in request", username)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Missing 'labArchive' file in multipart form data."})
		} else {
			log.Warnf("DeployLab (Archive) failed for user '%s': Error retrieving 'labArchive' file: %v", username, err)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Error retrieving 'labArchive' file: " + err.Error()})
		}
		return
	}

	// --- Open the uploaded file ---
	archiveFile, err := fileHeader.Open()
	if err != nil {
		log.Errorf("DeployLab (Archive) failed for user '%s': Cannot open uploaded archive '%s': %v", username, fileHeader.Filename, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Cannot open uploaded archive."})
		return
	}
	defer archiveFile.Close()

	// --- Detect Type and Extract ---
	filename := fileHeader.Filename
	log.Infof("DeployLab (Archive) user '%s': Received archive '%s', size %d. Extracting to '%s'", username, filename, fileHeader.Size, targetDir)

	var extractionErr error

	if strings.HasSuffix(strings.ToLower(filename), ".zip") {
		extractionErr = extractZip(archiveFile, fileHeader.Size, targetDir, uid, gid)
	} else if strings.HasSuffix(strings.ToLower(filename), ".tar.gz") || strings.HasSuffix(strings.ToLower(filename), ".tgz") {
		extractionErr = extractTarGz(archiveFile, targetDir, uid, gid)
	} else {
		log.Warnf("DeployLab (Archive) failed for user '%s': Unsupported archive format for file '%s'", username, filename)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("Unsupported archive format: %s. Use .zip or .tar.gz.", filename)})
		return
	}

	// --- Handle Extraction Errors ---
	if extractionErr != nil {
		log.Errorf("DeployLab (Archive) failed for user '%s': Error extracting archive '%s': %v", username, filename, extractionErr)
		// Attempt to clean up partially extracted directory
		_ = os.RemoveAll(targetDir)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to extract archive: %s", extractionErr.Error())})
		return
	}
	log.Infof("DeployLab (Archive) user '%s': Successfully extracted archive '%s' to '%s'", username, filename, targetDir)

	// --- Find Topology File within extracted directory ---
	topoPathForClab := ""
	// First, look for a file named exactly <labName>.clab.yml
	expectedTopoPath := filepath.Join(targetDir, labName+".clab.yml")
	if _, err := os.Stat(expectedTopoPath); err == nil {
		topoPathForClab = expectedTopoPath
		log.Debugf("DeployLab (Archive) user '%s': Found topology file matching lab name: '%s'", username, topoPathForClab)
	} else {
		// If not found, search for the first *.clab.yml or *.clab.yaml file in the root of targetDir
		entries, readErr := os.ReadDir(targetDir)
		if readErr != nil {
			log.Errorf("DeployLab (Archive) failed for user '%s': Cannot read extracted directory '%s': %v", username, targetDir, readErr)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to read extracted lab directory."})
			_ = os.RemoveAll(targetDir)
			return
		}
		for _, entry := range entries {
			entryNameLower := strings.ToLower(entry.Name())
			if !entry.IsDir() && (strings.HasSuffix(entryNameLower, ".clab.yml") || strings.HasSuffix(entryNameLower, ".clab.yaml")) {
				topoPathForClab = filepath.Join(targetDir, entry.Name())
				log.Debugf("DeployLab (Archive) user '%s': Found topology file by suffix: '%s'", username, topoPathForClab)
				break // Use the first one found
			}
		}
	}

	if topoPathForClab == "" {
		log.Errorf("DeployLab (Archive) failed for user '%s': No '*.clab.yml' or '*.clab.yaml' file found in the root of the extracted archive in '%s'.", username, targetDir)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "No '*.clab.yml' or '*.clab.yaml' file found in the root of the archive."})
		_ = os.RemoveAll(targetDir)
		return
	}

	// --- Construct clab deploy args ---
	args := []string{"deploy", "--topo", topoPathForClab, "--format", "json"}
	// Add optional flags
	if reconfigure {
		// Note: We already removed the dir, but --reconfigure tells clab to also remove containers first
		args = append(args, "--reconfigure")
	}
	if maxWorkers > 0 {
		args = append(args, "--max-workers", strconv.Itoa(maxWorkers))
	}
	if exportTemplate != "" {
		args = append(args, "--export-template", exportTemplate)
	}
	if nodeFilter != "" {
		args = append(args, "--node-filter", nodeFilter)
	}
	if skipPostDeploy {
		args = append(args, "--skip-post-deploy")
	}
	if skipLabdirAcl {
		args = append(args, "--skip-labdir-acl")
	}

	// --- Execute clab deploy ---
	log.Infof("DeployLab (Archive) user '%s': Executing clab deploy for lab '%s' using topology '%s'...", username, labName, topoPathForClab)
	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	// --- Handle command execution results ---
	if stderr != "" {
		log.Warnf("DeployLab (Archive) user '%s', lab '%s': clab deploy stderr: %s", username, labName, stderr)
	}
	if err != nil {
		log.Errorf("DeployLab (Archive) failed for user '%s', lab '%s': clab deploy command execution error: %v", username, labName, err)
		errMsg := fmt.Sprintf("Failed to deploy lab '%s' from archive: %s", labName, err.Error())
		if stderr != "" && (strings.Contains(stderr, "level=error") || strings.Contains(stderr, "failed") || strings.Contains(stderr, "panic")) {
			errMsg += "\nstderr: " + stderr
		}
		// Don't remove targetDir here, deployment failed but extraction succeeded, user might want to inspect
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	log.Infof("DeployLab (Archive) user '%s': clab deploy for lab '%s' executed successfully.", username, labName)

	// --- Parse and return result ---
	var result interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		log.Warnf("DeployLab (Archive) user '%s', lab '%s': Output from clab was not valid JSON: %v. Returning as plain text.", username, labName, err)
		// Check if the non-JSON output indicates an error
		if strings.Contains(stdout, "level=error") || strings.Contains(stdout, "failed") {
			c.JSON(http.StatusInternalServerError, gin.H{"output": stdout, "warning": "Deployment finished but output indicates errors and was not valid JSON"})
		} else {
			c.JSON(http.StatusOK, gin.H{"output": stdout, "warning": "Output was not valid JSON"})
		}
		return
	}

	c.JSON(http.StatusOK, result)
}

// @Summary Destroy Lab
// @Description Destroys a lab by name, checking ownership via 'owner' field from clab inspect.
// @Description Optionally cleans up the lab directory (~/.clab/<labname>) if 'cleanup=true' is passed and the API deployed it from content.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Name of the lab to destroy" example="my-test-lab"
// @Param cleanup query boolean false "Remove lab directory (~/.clab/<labname>) after destroy (default: false)" example="true"
// @Param graceful query boolean false "Attempt graceful shutdown of containers (default: false)" example="true"
// @Param keepMgmtNet query boolean false "Keep the management network (default: false)" example="true"
// @Param nodeFilter query string false "Destroy only specific nodes (comma-separated)" example="srl1,srl2"
// @Success 200 {object} models.GenericSuccessResponse
// @Failure 400 {object} models.ErrorResponse "Invalid lab name or node filter"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found or not owned by user"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/labs/{labName} [delete]
func DestroyLabHandler(c *gin.Context) {
	username := c.GetString("username") // Authenticated user
	labName := c.Param("labName")

	// --- Validate Path Param ---
	if !isValidLabName(labName) {
		log.Warnf("DestroyLab failed for user '%s': Invalid characters in lab name '%s'", username, labName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name. Use alphanumeric, hyphen, underscore."})
		return
	}
	log.Debugf("DestroyLab user '%s': Attempting to destroy lab '%s'", username, labName)

	// --- Get & Validate Query Params ---
	cleanup := c.Query("cleanup") == "true"
	graceful := c.Query("graceful") == "true"
	keepMgmtNet := c.Query("keepMgmtNet") == "true"
	nodeFilter := c.Query("nodeFilter")

	if !isValidNodeFilter(nodeFilter) {
		log.Warnf("DestroyLab failed for user '%s', lab '%s': Invalid nodeFilter '%s'", username, labName, nodeFilter)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in nodeFilter. Use comma-separated alphanumeric, hyphen, underscore."})
		return
	}

	// --- Verify lab exists and belongs to the user via inspect + owner field check ---
	originalTopoPath, ownerCheckErr := verifyLabOwnership(c, username, labName) // Extract ownership check
	if ownerCheckErr != nil {
		// verifyLabOwnership already sent the response
		return
	}
	// Ownership confirmed

	// --- Execute clab destroy ---
	destroyArgs := []string{"destroy", "--name", labName}
	if graceful {
		destroyArgs = append(destroyArgs, "--graceful")
	}
	if keepMgmtNet {
		destroyArgs = append(destroyArgs, "--keep-mgmt-net")
	}
	if nodeFilter != "" {
		destroyArgs = append(destroyArgs, "--node-filter", nodeFilter)
	}
	// NOTE: --cleanup is handled *after* the command by removing the directory

	log.Infof("DestroyLab user '%s': Executing clab destroy for lab '%s' (cleanup=%t)...", username, labName, cleanup)
	_, stderr, err := clab.RunClabCommand(c.Request.Context(), username, destroyArgs...)

	// Handle clab destroy command result
	if err != nil {
		log.Errorf("DestroyLab failed for user '%s': clab destroy command failed for lab '%s': %v", username, labName, err)
		errMsg := fmt.Sprintf("Failed to destroy lab '%s': %s", labName, err.Error())
		if stderr != "" {
			errMsg += "\nstderr: " + stderr
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	// clab destroy succeeded
	log.Infof("Lab '%s' destroyed successfully via clab for user '%s'.", labName, username)
	if stderr != "" { // Log stderr even on success
		log.Warnf("DestroyLab user '%s': clab destroy stderr for lab '%s' (command succeeded): %s", username, labName, stderr)
	}

	// --- Attempt to Cleanup Topology Directory if requested AND if deployed via content ---
	if cleanup {
		// Only cleanup if we know the original path (meaning it was likely deployed via content by the API)
		// We get originalTopoPath from the verifyLabOwnership call which gets it from inspect.
		// We need to derive the *directory* from the path.
		if originalTopoPath != "" && !strings.HasPrefix(originalTopoPath, "http") && !strings.Contains(originalTopoPath, "://") { // Basic check it's a local path
			targetDir := filepath.Dir(originalTopoPath)
			// Sanity check: ensure the directory is within the expected ~/.clab structure
			usr, lookupErr := user.Lookup(username)
			expectedBase := ""
			if lookupErr == nil {
				expectedBase = filepath.Join(usr.HomeDir, ".clab")
			}

			if expectedBase != "" && strings.HasPrefix(targetDir, expectedBase) && targetDir != expectedBase { // Prevent deleting ~/.clab itself
				log.Infof("DestroyLab user '%s': Cleanup requested. Removing directory: %s", username, targetDir)
				cleanupErr := os.RemoveAll(targetDir)
				if cleanupErr != nil {
					// Log error but don't make the API call fail, main task (destroy) succeeded.
					log.Warnf("Failed to cleanup topology directory '%s' for user '%s' after destroy: %v. API server might lack permissions.", targetDir, username, cleanupErr)
				} else {
					log.Infof("Successfully cleaned up topology directory '%s' for user '%s'", targetDir, username)
				}
			} else {
				log.Warnf("DestroyLab user '%s': Cleanup requested but skipping directory removal for path '%s'. Reason: Path is not within expected ~/.clab structure or original path unknown/remote.", username, targetDir)
			}
		} else {
			log.Infof("DestroyLab user '%s': Cleanup requested but skipping directory removal. Reason: Lab likely deployed from URL or original path unknown.", username)
		}
	} else {
		log.Infof("DestroyLab user '%s': Cleanup not requested. Lab directory (if any) retained.", username)
	}

	c.JSON(http.StatusOK, models.GenericSuccessResponse{Message: fmt.Sprintf("Lab '%s' destroyed successfully", labName)})
}

// @Summary Redeploy Lab
// @Description Redeploys a lab by name, effectively running destroy and then deploy. Checks ownership.
// @Description Uses the original topology file path found during inspection.
// @Tags Labs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param labName path string true "Name of the lab to redeploy" example="my-test-lab"
// @Param redeploy_request body models.RedeployRequest true "Redeployment options"
// @Success 200 {object} object "Raw JSON output from 'clab redeploy' (or plain text on error)"
// @Failure 400 {object} models.ErrorResponse "Invalid lab name or options"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found or not owned by user"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/labs/{labName} [put]
func RedeployLabHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")

	// --- Validate Path Param ---
	if !isValidLabName(labName) {
		log.Warnf("RedeployLab failed for user '%s': Invalid characters in lab name '%s'", username, labName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}

	// --- Bind Request Body ---
	var req models.RedeployRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("RedeployLab failed for user '%s', lab '%s': Invalid request body: %v", username, labName, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	// --- Validate Optional Flags (from request body) ---
	if !isValidExportTemplate(req.ExportTemplate) {
		log.Warnf("RedeployLab failed for user '%s', lab '%s': Invalid exportTemplate '%s'", username, labName, req.ExportTemplate)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid exportTemplate."})
		return
	}
	// Add validation for network, ipv4Subnet, ipv6Subnet if needed (e.g., CIDR format)

	log.Debugf("RedeployLab user '%s': Attempting to redeploy lab '%s'", username, labName)

	// --- Verify lab exists, belongs to the user, and get original topology path ---
	originalTopoPath, ownerCheckErr := verifyLabOwnership(c, username, labName)
	if ownerCheckErr != nil {
		// verifyLabOwnership already sent the response
		return
	}
	if originalTopoPath == "" {
		log.Errorf("RedeployLab failed for user '%s', lab '%s': Could not determine original topology path from inspect output.", username, labName)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Could not determine original topology path needed for redeploy."})
		return
	}
	log.Debugf("RedeployLab user '%s', lab '%s': Using original topology path '%s'", username, labName, originalTopoPath)

	// --- Execute clab redeploy ---
	args := []string{"redeploy", "--topo", originalTopoPath, "--format", "json"} // Use original path

	// Add flags from request body
	if req.Cleanup {
		args = append(args, "--cleanup")
	}
	if req.Graceful {
		args = append(args, "--graceful")
	}
	if req.Graph {
		args = append(args, "--graph")
	}
	if req.Network != "" {
		args = append(args, "--network", req.Network)
	}
	if req.Ipv4Subnet != "" {
		args = append(args, "--ipv4-subnet", req.Ipv4Subnet)
	}
	if req.Ipv6Subnet != "" {
		args = append(args, "--ipv6-subnet", req.Ipv6Subnet)
	}
	if req.MaxWorkers > 0 {
		args = append(args, "--max-workers", strconv.Itoa(req.MaxWorkers))
	}
	if req.KeepMgmtNet {
		args = append(args, "--keep-mgmt-net")
	}
	if req.SkipPostDeploy {
		args = append(args, "--skip-post-deploy")
	}
	if req.ExportTemplate != "" {
		args = append(args, "--export-template", req.ExportTemplate)
	}
	if req.SkipLabdirAcl {
		args = append(args, "--skip-labdir-acl")
	}

	log.Infof("RedeployLab user '%s': Executing clab redeploy for lab '%s'...", username, labName)
	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	// Handle command execution results (similar to deploy)
	if stderr != "" {
		log.Warnf("RedeployLab user '%s', lab '%s': clab redeploy stderr: %s", username, labName, stderr)
	}
	if err != nil {
		log.Errorf("RedeployLab failed for user '%s', lab '%s': clab redeploy command execution error: %v", username, labName, err)
		errMsg := fmt.Sprintf("Failed to redeploy lab '%s': %s", labName, err.Error())
		if stderr != "" && (strings.Contains(stderr, "level=error") || strings.Contains(stderr, "failed") || strings.Contains(stderr, "panic")) {
			errMsg += "\nstderr: " + stderr
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	log.Infof("RedeployLab user '%s': clab redeploy for lab '%s' executed successfully.", username, labName)

	// Attempt to parse stdout as JSON and return it
	var result interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		log.Warnf("RedeployLab user '%s', lab '%s': Output from clab was not valid JSON: %v. Returning as plain text.", username, labName, err)
		if strings.Contains(stdout, "level=error") || strings.Contains(stdout, "failed") {
			c.JSON(http.StatusInternalServerError, gin.H{"output": stdout, "warning": "Redeployment finished but output indicates errors and was not valid JSON"})
		} else {
			c.JSON(http.StatusOK, gin.H{"output": stdout, "warning": "Output was not valid JSON"})
		}
		return
	}

	c.JSON(http.StatusOK, result)
}

// @Summary Inspect Lab
// @Description Get details about a specific running lab, checking ownership via 'owner' field. Supports '--details'.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Name of the lab to inspect" example="my-test-lab"
// @Param details query boolean false "Include full container details (like docker inspect)" example="true"
// @Success 200 {object} models.ClabInspectOutput "Standard JSON output from 'clab inspect'"
// @Success 200 {object} object "Raw JSON output if 'details=true' is used (structure matches 'docker inspect')"
// @Failure 400 {object} models.ErrorResponse "Invalid lab name"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found or not owned by user"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/labs/{labName} [get]
func InspectLabHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	details := c.Query("details") == "true"

	if !isValidLabName(labName) {
		log.Warnf("InspectLab failed for user '%s': Invalid characters in lab name '%s'", username, labName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}
	log.Debugf("InspectLab user '%s': Inspecting lab '%s' (details=%t)", username, labName, details)

	// --- Verify lab exists and belongs to the user (needed even if just inspecting) ---
	_, ownerCheckErr := verifyLabOwnership(c, username, labName)
	if ownerCheckErr != nil {
		// verifyLabOwnership already sent the response
		return
	}
	// Ownership confirmed

	// --- Execute clab inspect ---
	args := []string{"inspect", "--name", labName, "--format", "json"}
	if details {
		args = append(args, "--details")
	}

	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	if stderr != "" {
		log.Warnf("InspectLab user '%s': clab inspect stderr for lab '%s': %s", username, labName, stderr)
	}
	if err != nil {
		// Error handling copied from original InspectLabHandler, checking for "not found"
		errMsg := err.Error()
		if strings.Contains(stdout, "no containers found") ||
			strings.Contains(errMsg, "no containers found") ||
			strings.Contains(errMsg, "no containerlab labs found") ||
			strings.Contains(stderr, "no containers found") ||
			strings.Contains(stderr, "Could not find containers for lab") {
			log.Infof("InspectLab user '%s': Lab '%s' not found.", username, labName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' not found.", labName)})
			return
		}
		log.Errorf("InspectLab failed for user '%s': clab inspect command failed for lab '%s': %v", username, labName, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to inspect lab '%s': %s", labName, err.Error())})
		return
	}

	// --- Parse and Return Result ---
	if details {
		// For --details, the output structure is complex (like docker inspect).
		// Return raw JSON to avoid complex model mapping.
		var rawResult json.RawMessage
		if err := json.Unmarshal([]byte(stdout), &rawResult); err != nil {
			log.Errorf("InspectLab failed for user '%s': Failed to parse clab inspect --details JSON output for lab '%s': %v", username, labName, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to parse clab inspect --details output: " + err.Error()})
			return
		}
		log.Debugf("InspectLab user '%s': Inspection (with details) of lab '%s' successful.", username, labName)
		// Return the raw JSON directly. Gin handles marshalling json.RawMessage correctly.
		c.Data(http.StatusOK, "application/json", rawResult)
	} else {
		// Standard inspect output handling
		var result models.ClabInspectOutput
		if err := json.Unmarshal([]byte(stdout), &result); err != nil {
			log.Errorf("InspectLab failed for user '%s': Failed to parse clab inspect JSON output for lab '%s': %v", username, labName, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to parse clab inspect output: " + err.Error()})
			return
		}
		log.Debugf("InspectLab user '%s': Inspection of lab '%s' successful.", username, labName)
		c.JSON(http.StatusOK, result)
	}
}

// @Summary List Lab Interfaces
// @Description Get network interface details for nodes in a specific lab, checking ownership.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Name of the lab" example="my-test-lab"
// @Param node query string false "Filter interfaces for a specific node name" example="clab-my-test-lab-srl1"
// @Success 200 {object} models.ClabInspectInterfacesOutput "JSON output from 'clab inspect interfaces'"
// @Failure 400 {object} models.ErrorResponse "Invalid lab name or node name"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found or not owned by user"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/labs/{labName}/interfaces [get]
func InspectInterfacesHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	nodeFilter := c.Query("node") // Optional node name filter

	// --- Validate Path Param ---
	if !isValidLabName(labName) {
		log.Warnf("InspectInterfaces failed for user '%s': Invalid characters in lab name '%s'", username, labName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}
	// Basic validation for node filter if provided (allow containerlab default names)
	if nodeFilter != "" && !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(nodeFilter) {
		log.Warnf("InspectInterfaces failed for user '%s', lab '%s': Invalid characters in node query param '%s'", username, labName, nodeFilter)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in node query parameter."})
		return
	}

	log.Debugf("InspectInterfaces user '%s': Inspecting interfaces for lab '%s' (node filter: '%s')", username, labName, nodeFilter)

	// --- Verify lab exists and belongs to the user ---
	_, ownerCheckErr := verifyLabOwnership(c, username, labName)
	if ownerCheckErr != nil {
		return // verifyLabOwnership sent response
	}
	// Ownership confirmed

	// --- Execute clab inspect interfaces ---
	args := []string{"inspect", "interfaces", "--name", labName, "--format", "json"}
	if nodeFilter != "" {
		args = append(args, "--node", nodeFilter)
	}

	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	if stderr != "" {
		log.Warnf("InspectInterfaces user '%s': clab inspect interfaces stderr for lab '%s': %s", username, labName, stderr)
	}
	if err != nil {
		// Check for "not found" errors specifically for interfaces command if possible
		errMsg := err.Error()
		if strings.Contains(stdout, "no containers found") ||
			strings.Contains(errMsg, "no containers found") ||
			strings.Contains(errMsg, "no containerlab labs found") ||
			strings.Contains(stderr, "no containers found") ||
			strings.Contains(stderr, "Could not find containers for lab") {
			log.Infof("InspectInterfaces user '%s': Lab '%s' not found.", username, labName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' not found.", labName)})
			return
		}
		// Check if specific node wasn't found
		if nodeFilter != "" && (strings.Contains(stderr, "container not found") || strings.Contains(errMsg, "container not found")) {
			log.Infof("InspectInterfaces user '%s': Node '%s' not found in lab '%s'.", username, nodeFilter, labName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Node '%s' not found in lab '%s'.", nodeFilter, labName)})
			return
		}

		log.Errorf("InspectInterfaces failed for user '%s': clab inspect interfaces command failed for lab '%s': %v", username, labName, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to inspect interfaces for lab '%s': %s", labName, err.Error())})
		return
	}

	// --- Parse and Return Result ---
	var result models.ClabInspectInterfacesOutput
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		log.Errorf("InspectInterfaces failed for user '%s': Failed to parse clab inspect interfaces JSON output for lab '%s': %v", username, labName, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to parse clab inspect interfaces output: " + err.Error()})
		return
	}

	log.Debugf("InspectInterfaces user '%s': Inspection of interfaces for lab '%s' successful.", username, labName)
	c.JSON(http.StatusOK, result)
}

// @Summary List All Labs
// @Description Get details about all running labs, filtered by the 'owner' field matching the authenticated user (unless user is in SUPERUSER_GROUP).
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.ClabInspectOutput "Filtered JSON output from 'clab inspect --all'"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/labs [get]
func ListLabsHandler(c *gin.Context) {
	username := c.GetString("username") // Authenticated user

	// --- Check for Superuser Status ---
	isSuperuser := false
	if config.AppConfig.SuperuserGroup != "" {
		inGroup, err := auth.IsUserInGroup(username, config.AppConfig.SuperuserGroup)
		if err != nil {
			log.Errorf("ListLabs user '%s': Error checking superuser group membership for group '%s': %v. Proceeding with standard permissions.",
				username, config.AppConfig.SuperuserGroup, err)
		} else if inGroup {
			isSuperuser = true
			log.Infof("ListLabs user '%s': Identified as superuser (member of '%s'). Bypassing owner filtering.",
				username, config.AppConfig.SuperuserGroup)
		} else {
			log.Debugf("ListLabs user '%s': Not a member of superuser group '%s'. Applying owner filtering.",
				username, config.AppConfig.SuperuserGroup)
		}
	} else {
		log.Debugf("ListLabs user '%s': No SUPERUSER_GROUP configured. Applying owner filtering.", username)
	}
	// --- End Superuser Check ---

	log.Debugf("ListLabs user '%s': Listing labs via 'clab inspect --all'...", username)
	args := []string{"inspect", "--all", "--format", "json"}
	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	if stderr != "" {
		log.Warnf("ListLabs user '%s': clab inspect --all stderr: %s", username, stderr)
	}
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(stdout, "no containers found") ||
			strings.Contains(errMsg, "no containerlab labs found") ||
			strings.Contains(stderr, "no containers found") {
			log.Infof("ListLabs user '%s': No labs found via clab inspect.", username)
			c.JSON(http.StatusOK, models.ClabInspectOutput{Containers: []models.ClabContainerInfo{}}) // Return empty list
			return
		}
		log.Errorf("ListLabs failed for user '%s': clab inspect --all command failed: %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to list labs: %s", err.Error())})
		return
	}

	log.Debugf("ListLabs user '%s': inspect --all command successful, parsing...", username)

	var fullResult models.ClabInspectOutput
	if err := json.Unmarshal([]byte(stdout), &fullResult); err != nil {
		log.Errorf("ListLabs failed for user '%s': Failed to parse clab inspect --all JSON output: %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to parse clab inspect output: " + err.Error()})
		return
	}

	// --- Filter Results (or don't, if superuser) ---
	var finalResult models.ClabInspectOutput

	if isSuperuser {
		log.Debugf("ListLabs user '%s': Superuser returning all %d containers from %d labs.", username, len(fullResult.Containers), countUniqueLabs(fullResult.Containers))
		finalResult = fullResult
	} else {
		filteredContainers := []models.ClabContainerInfo{}
		labsFoundForUser := make(map[string]bool)

		for _, cont := range fullResult.Containers {
			if cont.Owner == username {
				filteredContainers = append(filteredContainers, cont)
				if !labsFoundForUser[cont.LabName] {
					labsFoundForUser[cont.LabName] = true
					log.Debugf("ListLabs user '%s': Found lab '%s' owned by user.", username, cont.LabName)
				}
			} else {
				_, checked := labsFoundForUser[cont.LabName]
				if !checked && cont.Owner != "" {
					log.Debugf("ListLabs user '%s': Filtering out lab '%s' owned by '%s'.", username, cont.LabName, cont.Owner)
					labsFoundForUser[cont.LabName] = false
				}
			}
		}

		ownedLabCount := 0
		for _, owned := range labsFoundForUser {
			if owned {
				ownedLabCount++
			}
		}

		log.Infof("ListLabs user '%s': Found %d containers belonging to %d labs owned by the user.", username, len(filteredContainers), ownedLabCount)
		finalResult.Containers = filteredContainers
	}
	// --- End Filtering ---

	c.JSON(http.StatusOK, finalResult)
}

// @Summary Save Lab Configuration
// @Description Saves the running configuration for nodes in a specific lab. Checks ownership.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Name of the lab to save configuration for" example="my-test-lab"
// @Param nodeFilter query string false "Save config only for specific nodes (comma-separated)" example="srl1,srl2"
// @Success 200 {object} models.SaveConfigResponse "Configuration save command executed, includes detailed output."
// @Failure 400 {object} models.ErrorResponse "Invalid lab name or node filter"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found or not owned by user"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/labs/{labName}/save [post]
func SaveLabConfigHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	nodeFilter := c.Query("nodeFilter")

	// --- Validate Inputs ---
	if !isValidLabName(labName) {
		log.Warnf("SaveLabConfig failed for user '%s': Invalid lab name '%s'", username, labName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}
	if !isValidNodeFilter(nodeFilter) {
		log.Warnf("SaveLabConfig failed for user '%s', lab '%s': Invalid nodeFilter '%s'", username, labName, nodeFilter)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in nodeFilter."})
		return
	}
	log.Debugf("SaveLabConfig user '%s': Attempting to save config for lab '%s' (filter: '%s')", username, labName, nodeFilter)

	// --- Verify Ownership ---
	originalTopoPath, ownerCheckErr := verifyLabOwnership(c, username, labName)
	if ownerCheckErr != nil {
		return
	}
	if originalTopoPath == "" {
		log.Errorf("SaveLabConfig failed for user '%s', lab '%s': Could not determine original topology path from inspect output.", username, labName)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Could not determine original topology path needed for save."})
		return
	}
	// Ownership confirmed

	// --- Execute clab save ---
	args := []string{"save", "-t", originalTopoPath}
	if nodeFilter != "" {
		args = append(args, "--node-filter", nodeFilter)
	}

	log.Infof("SaveLabConfig user '%s': Executing clab save for lab '%s' using topology '%s'...", username, labName, originalTopoPath)
	_, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	// Handle command execution results
	// Log stderr regardless of error, as it contains the output
	if stderr != "" {
		log.Infof("SaveLabConfig user '%s', lab '%s': clab save output (stderr): %s", username, labName, stderr) // Log as Info now
	}
	if err != nil {
		log.Errorf("SaveLabConfig failed for user '%s', lab '%s': clab save command execution error: %v", username, labName, err)
		errMsg := fmt.Sprintf("Failed to save config for lab '%s': %s", labName, err.Error())
		// Append stderr *if* it seems like an actual error beyond normal output
		if stderr != "" && (strings.Contains(stderr, "level=error") || strings.Contains(stderr, "failed") || strings.Contains(stderr, "panic")) {
			errMsg += "\nstderr: " + stderr
		} else if stderr != "" { // Include normal stderr in error response if command failed
			errMsg += "\nOutput:\n" + stderr
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	log.Infof("SaveLabConfig user '%s': clab save for lab '%s' executed successfully.", username, labName)

	// --- Use the new response model ---
	c.JSON(http.StatusOK, models.SaveConfigResponse{
		Message: fmt.Sprintf("Configuration save command executed successfully for lab '%s'.", labName),
		Output:  stderr, // Include the captured stderr content
	})
}

// @Summary Execute Command in Lab
// @Description Executes a command on nodes within a specific lab. Checks ownership. Supports filtering by a single node name.
// @Tags Labs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param labName path string true "Name of the lab where the command should be executed" example="my-test-lab"
// @Param nodeFilter query string false "Execute only on this specific node (must match container name, e.g., clab-my-test-lab-srl1)" example="clab-my-test-lab-srl1"
// @Param format query string false "Output format ('plain' or 'json'). Default is 'json'." example="json"
// @Param exec_request body models.ExecRequest true "Command to execute"
// @Success 200 {object} models.ExecResponse "Structured output (if format=json)"
// @Success 200 {string} string "Plain text output (if format=plain)"
// @Failure 400 {object} models.ErrorResponse "Invalid input (lab name, node filter, format, request body)"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found or not owned by user"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/labs/{labName}/exec [post]
func ExecCommandHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	nodeFilter := c.Query("nodeFilter") // Expecting a single container name here
	outputFormat := c.DefaultQuery("format", "json")

	// --- Validate Inputs ---
	if !isValidLabName(labName) {
		log.Warnf("ExecCommand failed for user '%s': Invalid lab name '%s'", username, labName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}
	if nodeFilter != "" && !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(nodeFilter) {
		log.Warnf("ExecCommand failed for user '%s', lab '%s': Invalid characters in nodeFilter query param '%s'", username, labName, nodeFilter)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in nodeFilter query parameter (expecting single container name)."})
		return
	}
	if outputFormat != "plain" && outputFormat != "json" {
		log.Warnf("ExecCommand failed for user '%s', lab '%s': Invalid format query param '%s'", username, labName, outputFormat)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid format query parameter. Use 'plain' or 'json'."})
		return
	}

	var req models.ExecRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("ExecCommand failed for user '%s', lab '%s': Invalid request body: %v", username, labName, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}
	if strings.TrimSpace(req.Command) == "" {
		log.Warnf("ExecCommand failed for user '%s', lab '%s': Command cannot be empty", username, labName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Command cannot be empty."})
		return
	}

	log.Debugf("ExecCommand user '%s': Attempting to execute on lab '%s' (node filter: '%s', format: '%s')", username, labName, nodeFilter, outputFormat)

	// --- Verify Ownership ---
	originalTopoPath, ownerCheckErr := verifyLabOwnership(c, username, labName)
	if ownerCheckErr != nil {
		return // verifyLabOwnership sent response
	}

	// --- Execute clab exec ---
	args := []string{"exec"}
	if nodeFilter != "" {
		// Use --label filter for single node targeting via container name
		args = append(args, "--label", fmt.Sprintf("clab-node-longname=%s", nodeFilter))
	} else {
		// Target all nodes in the lab using the topology file
		if originalTopoPath == "" {
			log.Errorf("ExecCommand failed for user '%s', lab '%s': Cannot execute on all nodes as original topology path is unknown.", username, labName)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Cannot determine topology path to target all nodes for exec."})
			return
		}
		args = append(args, "--topo", originalTopoPath)
	}

	args = append(args, "--cmd", req.Command)
	if outputFormat == "json" {
		args = append(args, "--format", "json")
	} // 'plain' is the default for clab exec

	log.Infof("ExecCommand user '%s': Executing clab exec for lab '%s'...", username, labName)
	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	// --- Handle command execution results ---
	if err != nil {
		log.Warnf("ExecCommand user '%s', lab '%s': clab exec command returned error: %v. Stderr: %s, Stdout: %s", username, labName, err, stderr, stdout)
		// Don't return 500 immediately for plain format if it might be the command failing inside the container
	} else if stderr != "" && outputFormat == "plain" { // Log stderr if plain format, even on success, as it contains the output.
		log.Infof("ExecCommand user '%s', lab '%s': clab exec stderr (contains plain output): %s", username, labName, stderr)
	} else if stderr != "" && outputFormat == "json" { // Log stderr for JSON format only if it's unexpected (exit code 0 usually means no stderr)
		log.Warnf("ExecCommand user '%s', lab '%s': clab exec stderr (json format, exit code 0): %s", username, labName, stderr)
	}

	// --- Process output based on format ---
	if outputFormat == "json" {
		// Declare result using the ExecResponse type
		var result models.ExecResponse
		if jsonErr := json.Unmarshal([]byte(stdout), &result); jsonErr != nil {
			// Parsing failed
			log.Errorf("ExecCommand user '%s', lab '%s': Failed to parse clab exec JSON output: %v. Stdout: %s, Stderr: %s", username, labName, jsonErr, stdout, stderr)
			// Return 500 because the API failed to process valid clab output (or clab output was invalid)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":  "Failed to parse clab exec JSON output.",
				"stdout": stdout, // Include raw output for debugging
				"stderr": stderr,
			})
			return
		}
		// Parsing succeeded
		log.Infof("ExecCommand user '%s': clab exec for lab '%s' (json format) successful.", username, labName)
		// Return 200 even if the command *inside* the container failed (result will show non-zero return code)
		c.JSON(http.StatusOK, result)

	} else { // plain format
		// For plain format, clab aggregates stdout/stderr from containers into its *stderr*.
		// If clab itself reported an error (err != nil), something went wrong with clab execution.
		if err != nil {
			// Return 500 as clab itself failed. Include stderr (which might contain clab errors) and stdout.
			responseText := fmt.Sprintf("Clab Error: %s\nStderr:\n%s\nStdout:\n%s", err.Error(), stderr, stdout)
			c.String(http.StatusInternalServerError, responseText)
		} else {
			// Success (exit code 0 from clab). Return clab's stderr as it contains the aggregated output.
			log.Infof("ExecCommand user '%s': clab exec for lab '%s' (plain format) successful, returning stderr content.", username, labName)
			c.String(http.StatusOK, stderr) // Return stderr content for plain format success
		}
	}
}

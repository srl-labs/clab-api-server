// internal/api/handlers.go
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

	"github.com/FloSch62/clab-api/internal/auth"
	"github.com/FloSch62/clab-api/internal/clab"
	"github.com/FloSch62/clab-api/internal/config"
	"github.com/FloSch62/clab-api/internal/models"
)

// isValidLabName checks for potentially harmful characters in lab names.
var labNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func isValidLabName(name string) bool {
	if name == "" || len(name) > 64 { // Added length check
		return false
	}
	return labNameRegex.MatchString(name)
}

// isValidNodeFilter checks the node filter format (basic check)
func isValidNodeFilter(filter string) bool {
	if filter == "" {
		return true // Empty is valid (no filter)
	}
	// Check for potentially unsafe characters, allow comma, alphanumeric, hyphen, underscore
	return regexp.MustCompile(`^[a-zA-Z0-9_,-]+$`).MatchString(filter)
}

// isValidExportTemplate checks the export template format (basic check)
func isValidExportTemplate(template string) bool {
	if template == "" {
		return true // Empty is valid (use default)
	}
	if template == "__full" {
		return true // Special value
	}
	// Basic check: prevent path traversal, allow alphanumeric, underscore, hyphen, dot
	// This is NOT a foolproof validation for file paths, but a basic sanity check.
	// It assumes the template is relative or just a name.
	if strings.Contains(template, "..") || strings.HasPrefix(template, "/") {
		return false
	}
	return regexp.MustCompile(`^[a-zA-Z0-9_./-]+$`).MatchString(template)
}

// LoginHandler - Handles user authentication (No changes needed)
// @Summary Login
// @Description Authenticate user and return JWT token
// @Tags Auth
// @Accept json
// @Produce json
// @Param credentials body models.LoginRequest true "User Credentials"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Invalid credentials"
// @Failure 500 {object} models.ErrorResponse "Internal server error (PAM config?)"
// @Router /login [post]
func LoginHandler(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("Login failed: Invalid request body: %v", err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	valid, err := auth.ValidateCredentials(req.Username, req.Password)
	if err != nil {
		log.Errorf("Login failed for user '%s': Error during credential validation: %v", req.Username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Error validating credentials: " + err.Error()})
		return
	}

	if !valid {
		log.Infof("Login failed for user '%s': Invalid username or password", req.Username)
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{Error: "Invalid username or password"})
		return
	}

	token, err := auth.GenerateJWT(req.Username)
	if err != nil {
		log.Errorf("Login successful for user '%s', but failed to generate token: %v", req.Username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to generate token: " + err.Error()})
		return
	}

	log.Infof("User '%s' logged in successfully", req.Username)
	c.JSON(http.StatusOK, models.LoginResponse{Token: token})
}

// @Summary Deploy Lab
// @Description Deploys a containerlab topology from either embedded content or a remote URL (Git/HTTP).
// @Description If deploying from content, saves the file to ~/.clab/<labname>/ and sets ownership (requires API server privileges).
// @Description If deploying from URL, containerlab handles fetching; the API does not save the file locally.
// @Tags Labs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param deploy_request body models.DeployRequest true "Deployment details (topology content or URL, and options)"
// @Success 200 {object} object "Raw JSON output from 'clab deploy' (or plain text on error)"
// @Failure 400 {object} models.ErrorResponse "Invalid input (e.g., missing content/URL, invalid flags, invalid name)"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error (e.g., file system errors, clab execution failed)"
// @Router /api/v1/labs [post]
func DeployLabHandler(c *gin.Context) {
	username := c.GetString("username") // Authenticated user

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
		log.Warnf("DeployLab failed for user '%s': Request must include either 'topologyContent' or 'topologySourceUrl'", username)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Request must include either 'topologyContent' or 'topologySourceUrl'"})
		return
	}
	if hasContent && hasUrl {
		log.Warnf("DeployLab failed for user '%s': Request cannot include both 'topologyContent' and 'topologySourceUrl'", username)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Request cannot include both 'topologyContent' and 'topologySourceUrl'"})
		return
	}

	// --- Validate Optional Flags ---
	if req.LabNameOverride != "" && !isValidLabName(req.LabNameOverride) {
		log.Warnf("DeployLab failed for user '%s': Invalid characters in labNameOverride '%s'", username, req.LabNameOverride)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in labNameOverride. Use alphanumeric, hyphen, underscore."})
		return
	}
	if !isValidNodeFilter(req.NodeFilter) {
		log.Warnf("DeployLab failed for user '%s': Invalid characters in nodeFilter '%s'", username, req.NodeFilter)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in nodeFilter. Use comma-separated alphanumeric, hyphen, underscore."})
		return
	}
	if !isValidExportTemplate(req.ExportTemplate) {
		log.Warnf("DeployLab failed for user '%s': Invalid exportTemplate '%s'", username, req.ExportTemplate)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid exportTemplate. Avoid '..' and absolute paths."})
		return
	}

	// --- Prepare Base Arguments ---
	args := []string{"deploy", "--format", "json"} // Always use JSON format for API parsing

	// --- Handle Topology Source and Lab Name ---
	var labName string // Will hold the determined lab name for logging/cleanup reference
	var topoPathForClab string

	if hasUrl {
		log.Infof("DeployLab user '%s': Deploying from URL: %s", username, req.TopologySourceUrl)
		// Validate URL format minimally
		_, err := url.ParseRequestURI(req.TopologySourceUrl)
		// Allow user/repo format as well (basic check)
		isShortcut := !strings.Contains(req.TopologySourceUrl, "/") && !strings.Contains(req.TopologySourceUrl, ":")
		if err != nil && !isShortcut && !strings.HasPrefix(req.TopologySourceUrl, "http") { // Allow simple user/repo
			// More robust URL validation could be added
			log.Warnf("DeployLab failed for user '%s': Invalid topologySourceUrl format: %s", username, req.TopologySourceUrl)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid topologySourceUrl format"})
			return
		}
		topoPathForClab = req.TopologySourceUrl
		// Lab name: Use override if provided, otherwise let clab determine it (API won't know it beforehand)
		if req.LabNameOverride != "" {
			labName = req.LabNameOverride
			log.Debugf("DeployLab user '%s': Using lab name override '%s' for URL deployment", username, labName)
		} else {
			labName = "<determined_by_clab_from_url>" // Placeholder for logging
			log.Debugf("DeployLab user '%s': Lab name will be determined by containerlab from URL '%s'", username, req.TopologySourceUrl)
		}
	} else { // hasContent
		log.Infof("DeployLab user '%s': Deploying from provided topology content.", username)
		trimmedContent := strings.TrimSpace(req.TopologyContent)

		// --- Get User Home Directory AND UID/GID ---
		usr, err := user.Lookup(username)
		if err != nil {
			log.Errorf("DeployLab failed for user '%s': Could not find user details: %v", username, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Could not determine user details."})
			return
		}
		homeDir := usr.HomeDir
		uid, err := strconv.Atoi(usr.Uid)
		if err != nil {
			log.Errorf("DeployLab failed for user '%s': Could not convert UID '%s' to int: %v", username, usr.Uid, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Could not process user UID."})
			return
		}
		gid, err := strconv.Atoi(usr.Gid)
		if err != nil {
			log.Errorf("DeployLab failed for user '%s': Could not convert GID '%s' to int: %v", username, usr.Gid, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Could not process user GID."})
			return
		}
		log.Debugf("DeployLab user '%s': Found user details (uid: %d, gid: %d, home: %s)", username, uid, gid, homeDir)

		// --- Parse Topology to Extract Original Lab Name ---
		var topoData map[string]interface{}
		err = yaml.Unmarshal([]byte(trimmedContent), &topoData)
		if err != nil {
			log.Warnf("DeployLab failed for user '%s': Could not parse topology YAML: %v", username, err)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid topology YAML: " + err.Error()})
			return
		}

		originalLabNameValue, ok := topoData["name"]
		if !ok {
			log.Warnf("DeployLab failed for user '%s': Topology YAML is missing the top-level 'name' field.", username)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Topology YAML must contain a top-level 'name' field."})
			return
		}
		originalLabName, ok := originalLabNameValue.(string)
		if !ok || originalLabName == "" {
			log.Warnf("DeployLab failed for user '%s': Topology 'name' field is not a non-empty string.", username)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Topology 'name' field must be a non-empty string."})
			return
		}
		if !isValidLabName(originalLabName) {
			log.Warnf("DeployLab failed for user '%s': Invalid characters in extracted lab name '%s'", username, originalLabName)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in topology 'name'. Use alphanumeric, hyphen, underscore."})
			return
		}
		log.Debugf("DeployLab user '%s': Extracted original lab name '%s' from content", username, originalLabName)

		// Determine the effective lab name (override or original)
		if req.LabNameOverride != "" {
			labName = req.LabNameOverride
			log.Debugf("DeployLab user '%s': Using lab name override '%s'", username, labName)
		} else {
			labName = originalLabName
			log.Debugf("DeployLab user '%s': Using lab name '%s' from topology content", username, labName)
		}

		// --- Construct Paths using ORIGINAL name for consistency ---
		clabUserDir := filepath.Join(homeDir, ".clab")
		// Save under the name defined *inside* the topology file
		targetDir := filepath.Join(clabUserDir, originalLabName)
		targetFilePath := filepath.Join(targetDir, originalLabName+".clab.yml") // Standard naming convention
		topoPathForClab = targetFilePath                                        // Use this path for the clab command

		// --- Create Directory & Set Ownership ---
		log.Debugf("DeployLab user '%s': Ensuring directory exists: '%s'", username, targetDir)
		err = os.MkdirAll(targetDir, 0750) // Permissions: user(rwx), group(rx), other(-)
		if err != nil {
			log.Errorf("DeployLab failed for user '%s': Failed to create directory '%s': %v.", username, targetDir, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to create lab directory: %s.", err.Error())})
			return
		}
		log.Debugf("DeployLab user '%s': Setting ownership of directory '%s' to uid %d, gid %d", username, targetDir, uid, gid)
		err = os.Chown(targetDir, uid, gid)
		if err != nil {
			log.Errorf("DeployLab failed for user '%s': Failed to chown directory '%s' to uid %d, gid %d: %v. Check API server privileges.", username, targetDir, uid, gid, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to set ownership on lab directory: %s. API server requires privileges (e.g., run as root).", err.Error())})
			return
		}
		log.Infof("Set ownership of directory '%s' to user '%s' (uid %d, gid %d)", targetDir, username, uid, gid)

		// --- Write Topology File & Set Ownership ---
		log.Debugf("DeployLab user '%s': Writing topology file: '%s'", username, targetFilePath)
		err = os.WriteFile(targetFilePath, []byte(trimmedContent), 0640) // Permissions: user(rw), group(r), other(-)
		if err != nil {
			log.Errorf("DeployLab failed for user '%s': Failed to write topology file '%s': %v.", username, targetFilePath, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to write topology file: %s.", err.Error())})
			return
		}
		log.Debugf("DeployLab user '%s': Setting ownership of file '%s' to uid %d, gid %d", username, targetFilePath, uid, gid)
		err = os.Chown(targetFilePath, uid, gid)
		if err != nil {
			log.Errorf("DeployLab failed for user '%s': Failed to chown file '%s' to uid %d, gid %d: %v. Check API server privileges.", username, targetFilePath, uid, gid, err)
			_ = os.Remove(targetFilePath) // Attempt cleanup
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to set ownership on topology file: %s. API server requires privileges (e.g., run as root).", err.Error())})
			return
		}
		log.Infof("Saved topology and set ownership for user '%s' lab '%s' to '%s'", username, originalLabName, targetFilePath)
	}

	// --- Add Topology Path/URL to Args ---
	args = append(args, "--topo", topoPathForClab)

	// --- Add Optional Flags to Args ---
	if req.LabNameOverride != "" {
		args = append(args, "--name", req.LabNameOverride)
	}
	if req.Reconfigure {
		args = append(args, "--reconfigure")
	}
	if req.MaxWorkers > 0 {
		args = append(args, "--max-workers", strconv.Itoa(req.MaxWorkers))
	}
	if req.ExportTemplate != "" {
		args = append(args, "--export-template", req.ExportTemplate)
	}
	if req.NodeFilter != "" {
		args = append(args, "--node-filter", req.NodeFilter)
	}
	if req.SkipPostDeploy {
		args = append(args, "--skip-post-deploy")
	}
	if req.SkipLabdirAcl {
		args = append(args, "--skip-labdir-acl")
	}
	// Note: --runtime and --timeout are handled globally or in RunClabCommand

	// --- Execute clab deploy ---
	log.Infof("DeployLab user '%s': Executing clab deploy for lab '%s'...", username, labName) // Use determined labName for logging
	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	// Handle command execution results
	if stderr != "" {
		log.Warnf("DeployLab user '%s', lab '%s': clab deploy stderr: %s", username, labName, stderr)
	}
	if err != nil {
		log.Errorf("DeployLab failed for user '%s', lab '%s': clab deploy command execution error: %v", username, labName, err)
		errMsg := fmt.Sprintf("Failed to deploy lab '%s': %s", labName, err.Error())
		// Attempt to include stderr if it provides useful info
		if stderr != "" && (strings.Contains(stderr, "level=error") || strings.Contains(stderr, "failed") || strings.Contains(stderr, "panic")) {
			errMsg += "\nstderr: " + stderr
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	log.Infof("DeployLab user '%s': clab deploy for lab '%s' executed successfully.", username, labName)

	// Attempt to parse stdout as JSON and return it
	var result interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		log.Warnf("DeployLab user '%s', lab '%s': Output from clab was not valid JSON: %v. Returning as plain text.", username, labName, err)
		// Check if output suggests errors despite exit code 0
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
// @Success 200 {object} object "Raw JSON output if 'details=true' is used (structure matches 'docker inspect')" // <--- CHANGE THIS LINE
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
	// We don't strictly *need* the topo path here, but the ownership check is essential.
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
		var rawResult json.RawMessage // Keep using json.RawMessage in Go code
		if err := json.Unmarshal([]byte(stdout), &rawResult); err != nil {
			log.Errorf("InspectLab failed for user '%s': Failed to parse clab inspect --details JSON output for lab '%s': %v", username, labName, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to parse clab inspect --details output: " + err.Error()})
			return
		}
		log.Debugf("InspectLab user '%s': Inspection (with details) of lab '%s' successful.", username, labName)
		// Return the raw JSON directly. Gin handles marshalling json.RawMessage correctly.
		c.Data(http.StatusOK, "application/json", rawResult) // Use c.Data for raw bytes
		// OR, less ideally but might work if c.Data causes issues:
		// c.JSON(http.StatusOK, rawResult)
	} else {
		// ... standard inspect output handling ...
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
		// (Assuming similar error messages as inspect)
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

// ListLabsHandler - No changes needed, already uses owner field and superuser logic
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

// --- Helper Functions ---

// verifyLabOwnership checks if a lab exists and is owned by the user.
// Returns the original topology path (if found) and nil error on success.
// Sends appropriate HTTP error response and returns non-nil error on failure.
func verifyLabOwnership(c *gin.Context, username, labName string) (string, error) {
	log.Debugf("Verifying ownership for user '%s', lab '%s'", username, labName)
	inspectArgs := []string{"inspect", "--name", labName, "--format", "json"}
	// Use a background context for this internal check, don't rely on incoming request context timeout necessarily
	// ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	// defer cancel()
	// Using request context might be better to cancel if client disconnects
	ctx := c.Request.Context()

	inspectStdout, inspectStderr, inspectErr := clab.RunClabCommand(ctx, username, inspectArgs...) // username for logging

	if inspectStderr != "" {
		log.Warnf("Ownership check (via inspect) stderr for user '%s', lab '%s': %s", username, labName, inspectStderr)
	}
	if inspectErr != nil {
		errMsg := inspectErr.Error()
		if strings.Contains(inspectStdout, "no containers found") ||
			strings.Contains(errMsg, "no containers found") ||
			strings.Contains(errMsg, "no containerlab labs found") ||
			strings.Contains(inspectStderr, "no containers found") ||
			strings.Contains(inspectStderr, "Could not find containers for lab") {
			log.Infof("Ownership check failed for user '%s': Lab '%s' not found.", username, labName)
			err := fmt.Errorf("lab '%s' not found", labName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
			return "", err
		}
		log.Errorf("Ownership check failed for user '%s': Failed to inspect lab '%s': %v", username, labName, inspectErr)
		err := fmt.Errorf("failed to inspect lab '%s' for ownership check: %w", labName, inspectErr)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return "", err
	}

	var inspectResult models.ClabInspectOutput
	if err := json.Unmarshal([]byte(inspectStdout), &inspectResult); err != nil {
		log.Errorf("Ownership check failed for user '%s': Could not parse inspect output for lab '%s'. Output: %s, Error: %v", username, labName, inspectStdout, err)
		err := fmt.Errorf("could not parse inspect output for lab '%s'", labName)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return "", err
	}

	if len(inspectResult.Containers) == 0 {
		log.Warnf("Ownership check failed for user '%s': Inspect for lab '%s' succeeded but returned no containers.", username, labName)
		err := fmt.Errorf("lab '%s' not found (no containers returned)", labName)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
		return "", err
	}

	actualOwner := inspectResult.Containers[0].Owner
	originalTopoPath := inspectResult.Containers[0].LabPath // Get the topology path

	if actualOwner != username {
		// Check superuser status ONLY if ownership check fails
		isSuperuser := false
		if config.AppConfig.SuperuserGroup != "" {
			inGroup, groupErr := auth.IsUserInGroup(username, config.AppConfig.SuperuserGroup)
			if groupErr != nil {
				log.Errorf("Ownership check failed for user '%s', lab '%s': Error checking superuser group membership: %v", username, labName, groupErr)
				// Fall through to deny access, as we couldn't confirm superuser status
			} else if inGroup {
				isSuperuser = true
				log.Infof("Ownership check bypass for user '%s' on lab '%s' (owned by '%s'): User is superuser.", username, labName, actualOwner)
			}
		}

		if !isSuperuser {
			log.Warnf("Ownership check failed for user '%s': Attempted to access lab '%s' but it is owned by '%s'. Access denied.", username, labName, actualOwner)
			err := fmt.Errorf("lab '%s' not found or not owned by user", labName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()}) // Use 404 for security (don't reveal existence)
			return "", err
		}
	}

	log.Debugf("Ownership confirmed for user '%s' on lab '%s' (Owner: '%s', Original Path: '%s').", username, labName, actualOwner, originalTopoPath)
	return originalTopoPath, nil // Success
}

// Helper function to count unique lab names in a list of containers
func countUniqueLabs(containers []models.ClabContainerInfo) int {
	uniqueLabs := make(map[string]struct{})
	for _, c := range containers {
		if c.LabName != "" {
			uniqueLabs[c.LabName] = struct{}{}
		}
	}
	return len(uniqueLabs)
}

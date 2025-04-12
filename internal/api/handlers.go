package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"io/ioutil" // Needed for TempFile creation
	"os"
	"os/user"
	"path/filepath"
	"regexp" // For more robust validation
	"strings"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"
	// Adjust import paths if your module path is different
	"github.com/yourusername/clab-api/internal/auth"
	"github.com/yourusername/clab-api/internal/clab"
	"github.com/yourusername/clab-api/internal/models"
)

// @Summary Login
// @Description Authenticate user and return JWT token
// @Tags Auth
// @Accept json
// @Produce json
// @Param credentials body models.LoginRequest true "User Credentials"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Invalid credentials"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /login [post]
func LoginHandler(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("Login failed: Invalid request body: %v", err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	// Use the improved validation function
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
// @Description Deploys a containerlab topology for the authenticated user
// @Tags Labs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param deploy_request body models.DeployRequest true "Topology Content"
// @Success 200 {object} object "Raw JSON output from 'clab deploy' (or plain text on error)"
// @Failure 400 {object} models.ErrorResponse "Invalid input (e.g., empty topology content)"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error (e.g., failed to create temp file, clab execution failed)"
// @Router /api/v1/labs [post]
func DeployLabHandler(c *gin.Context) {
	username := c.GetString("username") // Get username from auth middleware context

	var req models.DeployRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("DeployLab failed for user '%s': Invalid request body: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	if strings.TrimSpace(req.TopologyContent) == "" {
		log.Warnf("DeployLab failed for user '%s': Topology content cannot be empty", username)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Topology content cannot be empty"})
		return
	}

	// Get user's home directory to create the temp file in their context
	usr, err := user.Lookup(username)
	if err != nil {
		log.Errorf("DeployLab failed for user '%s': Failed to lookup user home directory: %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to lookup user home directory"})
		return
	}
	homeDir := usr.HomeDir

	// Create a temporary file in the user's home directory to hold the topology content
	// Suffix is important for clab
	tempFile, err := ioutil.TempFile(homeDir, "api-*.clab.yaml")
	if err != nil {
		log.Errorf("DeployLab failed for user '%s': Failed to create temporary topology file: %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to create temporary topology file: " + err.Error()})
		return
	}
	// Ensure the temp file is cleaned up
	defer os.Remove(tempFile.Name()) // Defer removal *after* error checking

	log.Debugf("DeployLab user '%s': Created temporary topology file '%s'", username, tempFile.Name())

	// Write the topology content to the temporary file
	if _, err := tempFile.Write([]byte(req.TopologyContent)); err != nil {
		log.Errorf("DeployLab failed for user '%s': Failed to write to temporary topology file '%s': %v", username, tempFile.Name(), err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to write temporary topology file: " + err.Error()})
		return
	}
	if err := tempFile.Close(); err != nil { // Close the file before clab uses it
		log.Errorf("DeployLab failed for user '%s': Failed to close temporary topology file '%s': %v", username, tempFile.Name(), err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to close temporary topology file: " + err.Error()})
		return
	}

	// Prepare clab arguments
	// Use the temporary file path. Add --reconfigure for consistency.
	args := []string{"deploy", "--topo", tempFile.Name(), "--format", "json", "--reconfigure"}

	// Execute clab command
	log.Infof("DeployLab user '%s': Executing clab deploy...", username)
	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	// Handle command execution results
	if stderr != "" {
		// Log stderr even if command might have succeeded (could contain warnings)
		log.Warnf("DeployLab user '%s': clab command stderr: %s", username, stderr)
	}
	if err != nil {
		log.Errorf("DeployLab failed for user '%s': clab command execution error: %v", username, err)
		// stderr might already be in the error message from RunClabCommand
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to deploy lab: %s", err.Error())})
		return
	}

	log.Infof("DeployLab user '%s': clab deploy executed successfully.", username)

	// Attempt to parse stdout as JSON and return it
	var result interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		log.Warnf("DeployLab user '%s': Output from clab was not valid JSON: %v. Returning as plain text.", username, err)
		// If not JSON, return as plain text object
		c.JSON(http.StatusOK, gin.H{"output": stdout, "warning": "Output was not valid JSON"})
		return
	}

	// Return the parsed JSON result
	c.JSON(http.StatusOK, result)
}

// @Summary Destroy Lab
// @Description Destroys a specific containerlab lab by name for the authenticated user
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Name of the lab to destroy" example="my-test-lab"
// @Success 200 {object} models.GenericSuccessResponse
// @Failure 400 {object} models.ErrorResponse "Invalid lab name"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/labs/{labName} [delete]
func DestroyLabHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")

	// Validate lab name format
	if !isValidLabName(labName) {
		log.Warnf("DestroyLab failed for user '%s': Invalid characters in lab name '%s'", username, labName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name. Use alphanumeric, hyphen, underscore."})
		return
	}
	log.Debugf("DestroyLab user '%s': Attempting to destroy lab '%s'", username, labName)

	// --- Find the topology file associated with the lab name via 'clab inspect' ---
	log.Debugf("DestroyLab user '%s': Inspecting lab '%s' to find topology file...", username, labName)
	inspectArgs := []string{"inspect", "--name", labName, "--format", "json"}
	inspectStdout, inspectStderr, inspectErr := clab.RunClabCommand(c.Request.Context(), username, inspectArgs...)

	if inspectStderr != "" {
		log.Warnf("DestroyLab user '%s': clab inspect stderr for lab '%s': %s", username, labName, inspectStderr)
	}
	if inspectErr != nil {
		// Check common "not found" messages in error or stdout
		errMsg := inspectErr.Error()
		if strings.Contains(inspectStdout, "no containers found") ||
		   strings.Contains(errMsg, "no containers found") ||
		   strings.Contains(errMsg, "no containerlab labs found") ||
		   strings.Contains(inspectStderr, "no containers found"){
			log.Infof("DestroyLab user '%s': Lab '%s' not found during inspection.", username, labName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' not found or has no running containers.", labName)})
			return
		}
		// Other inspect error
		log.Errorf("DestroyLab failed for user '%s': Failed to inspect lab '%s': %v", username, labName, inspectErr)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to inspect lab before destroying: %s", inspectErr.Error())})
		return
	}
	log.Debugf("DestroyLab user '%s': Inspection of lab '%s' successful.", username, labName)

	// --- Parse inspect output to find the topology file path ---
	var inspectResult models.ClabInspectOutput // Use a struct for better parsing
	if err := json.Unmarshal([]byte(inspectStdout), &inspectResult); err != nil || len(inspectResult.Containers) == 0 {
		log.Errorf("DestroyLab failed for user '%s': Could not parse inspect output or find containers for lab '%s'. Output: %s", username, labName, inspectStdout)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Could not determine topology file for lab '%s' from inspect output.", labName)})
		return
	}

	// Use the topology path from the first container (should be consistent within a lab)
	topologyPath := inspectResult.Containers[0].LabPath // This is often the relative path used in 'deploy'

	// --- Determine the absolute path for the destroy command ---
	// clab destroy usually works best with the same path reference used during deploy.
	// If the stored LabPath is absolute, use it. If relative, make it absolute based on the user's home dir.
	var destroyTopoPath string
	if filepath.IsAbs(topologyPath) {
		// Security check: Ensure absolute path is within expected bounds (e.g., user's home)
		// This is tricky as clab might store paths outside home if run manually.
		// For API context, we primarily expect paths relative to home.
		// We'll rely on the initial deploy SanitizePath for safety.
		destroyTopoPath = topologyPath
		log.Debugf("DestroyLab user '%s': Using absolute topology path from inspect: '%s'", username, destroyTopoPath)
	} else {
		// Assume relative path is relative to user's home (where we run commands)
		usr, err := user.Lookup(username)
		if err != nil {
			log.Errorf("DestroyLab failed for user '%s': Failed to lookup user home directory: %v", username, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to lookup user home directory"})
			return
		}
		// Re-sanitize the path derived from inspect output to be safe
		cleanRelativePath := filepath.Clean(topologyPath)
		if strings.HasPrefix(cleanRelativePath, "..") || strings.HasPrefix(cleanRelativePath, "/") {
             log.Warnf("DestroyLab user '%s': Invalid relative path '%s' found in inspect output for lab '%s'", username, topologyPath, labName)
             c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Invalid topology path found for lab '%s'", labName)})
             return
        }
		destroyTopoPath = filepath.Join(usr.HomeDir, cleanRelativePath)
		log.Debugf("DestroyLab user '%s': Resolved relative topology path '%s' to '%s'", username, topologyPath, destroyTopoPath)
	}


	// --- Execute clab destroy ---
	log.Infof("DestroyLab user '%s': Executing clab destroy for topology '%s'...", username, destroyTopoPath)
	// Use --cleanup to remove the lab directory artifacts
	destroyArgs := []string{"destroy", "--topo", destroyTopoPath, "--cleanup"}

	_, stderr, err := clab.RunClabCommand(c.Request.Context(), username, destroyArgs...)

	if stderr != "" {
		log.Warnf("DestroyLab user '%s': clab destroy stderr for lab '%s': %s", username, labName, stderr)
	}
	if err != nil {
		log.Errorf("DestroyLab failed for user '%s': clab destroy command failed for lab '%s': %v", username, labName, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to destroy lab '%s': %s", labName, err.Error())})
		return
	}

	log.Infof("DestroyLab user '%s': Lab '%s' destroyed successfully.", username, labName)
	c.JSON(http.StatusOK, models.GenericSuccessResponse{Message: fmt.Sprintf("Lab '%s' destroyed successfully", labName)})
}

// @Summary Inspect Lab
// @Description Get details about a specific running lab for the authenticated user
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Name of the lab to inspect" example="my-test-lab"
// @Success 200 {object} object "Raw JSON output from 'clab inspect'"
// @Failure 400 {object} models.ErrorResponse "Invalid lab name"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/labs/{labName} [get]
func InspectLabHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")

	if !isValidLabName(labName) {
		log.Warnf("InspectLab failed for user '%s': Invalid characters in lab name '%s'", username, labName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name. Use alphanumeric, hyphen, underscore."})
		return
	}
	log.Debugf("InspectLab user '%s': Inspecting lab '%s'", username, labName)

	args := []string{"inspect", "--name", labName, "--format", "json"}

	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	if stderr != "" {
		log.Warnf("InspectLab user '%s': clab inspect stderr for lab '%s': %s", username, labName, stderr)
	}
	if err != nil {
		errMsg := err.Error()
		// Check common "not found" messages
		if strings.Contains(stdout, "no containers found") ||
		   strings.Contains(errMsg, "no containers found") ||
		   strings.Contains(errMsg, "no containerlab labs found") ||
		   strings.Contains(stderr, "no containers found"){
			log.Infof("InspectLab user '%s': Lab '%s' not found.", username, labName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' not found or has no running containers.", labName)})
			return
		}
		log.Errorf("InspectLab failed for user '%s': clab inspect command failed for lab '%s': %v", username, labName, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to inspect lab '%s': %s", labName, err.Error())})
		return
	}

	log.Debugf("InspectLab user '%s': Inspection of lab '%s' successful.", username, labName)

	var result interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		log.Errorf("InspectLab failed for user '%s': Failed to parse clab inspect JSON output for lab '%s': %v", username, labName, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to parse clab inspect output: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// @Summary List All Labs
// @Description Get details about all running labs for the authenticated user (filtered by owner)
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.ClabInspectOutput "Filtered JSON output from 'clab inspect --all'"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/labs [get]
func ListLabsHandler(c *gin.Context) {
	username := c.GetString("username")
	log.Debugf("ListLabs user '%s': Listing all labs...", username)

	// Use inspect --all. Clab's JSON output includes an "Owner" field (usually the username).
	// We execute the command as the user, but Docker might show containers from other users.
	// Therefore, we *must* filter the JSON output based on the Owner field matching the authenticated user.
	args := []string{"inspect", "--all", "--format", "json"}

	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	if stderr != "" {
		log.Warnf("ListLabs user '%s': clab inspect --all stderr: %s", username, stderr)
	}
	if err != nil {
		errMsg := err.Error()
		// Check if the error is simply "no labs found" - return empty list in this case.
		if strings.Contains(stdout, "no containers found") ||
		   strings.Contains(errMsg, "no containerlab labs found") ||
		   strings.Contains(stderr, "no containers found") {
			log.Infof("ListLabs user '%s': No labs found.", username)
			// Return the standard structure but with an empty Containers slice
			c.JSON(http.StatusOK, models.ClabInspectOutput{Containers: []models.ClabContainerInfo{}})
			return
		}
		log.Errorf("ListLabs failed for user '%s': clab inspect --all command failed: %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to list labs: %s", err.Error())})
		return
	}

	log.Debugf("ListLabs user '%s': inspect --all command successful, parsing and filtering...", username)

	// Parse the full output
	var fullResult models.ClabInspectOutput
	if err := json.Unmarshal([]byte(stdout), &fullResult); err != nil {
		log.Errorf("ListLabs failed for user '%s': Failed to parse clab inspect --all JSON output: %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to parse clab inspect output: " + err.Error()})
		return
	}

	// Filter the containers by owner
	filteredContainers := []models.ClabContainerInfo{}
	for _, cont := range fullResult.Containers {
		if cont.Owner == username {
			filteredContainers = append(filteredContainers, cont)
		} else {
			log.Debugf("ListLabs user '%s': Filtering out container '%s' owned by '%s'", username, cont.Name, cont.Owner)
		}
	}

	// Return the filtered result
	log.Infof("ListLabs user '%s': Found %d labs owned by user.", username, len(filteredContainers))
	c.JSON(http.StatusOK, models.ClabInspectOutput{Containers: filteredContainers})
}

// @Summary List Topologies
// @Description Lists available .clab.yml/.clab.yaml files in the user's home directory (non-recursive)
// @Tags Topologies
// @Security BearerAuth
// @Produce json
// @Success 200 {array} models.TopologyListItem
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/topologies [get]
func ListTopologiesHandler(c *gin.Context) {
	username := c.GetString("username")
	log.Debugf("ListTopologies user '%s': Listing topology files...", username)

	usr, err := user.Lookup(username)
	if err != nil {
		log.Errorf("ListTopologies failed for user '%s': Failed to lookup user home directory: %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to lookup user home directory"})
		return
	}
	homeDir := usr.HomeDir

	var files []models.TopologyListItem

	// Read directory entries directly instead of walking
	dirEntries, err := os.ReadDir(homeDir)
	if err != nil {
		log.Errorf("ListTopologies failed for user '%s': Failed to read home directory '%s': %v", username, homeDir, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to read user's home directory: " + err.Error()})
		return
	}

	for _, entry := range dirEntries {
		// Skip directories and hidden files/folders
		if !entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			// Check for .clab.yml or .clab.yaml suffix
			if strings.HasSuffix(entry.Name(), ".clab.yml") || strings.HasSuffix(entry.Name(), ".clab.yaml") {
				files = append(files, models.TopologyListItem{
					Filename: entry.Name(),
					// Path is relative to home for clarity in API response
					RelativePath: entry.Name(),
				})
			}
		}
	}

	log.Infof("ListTopologies user '%s': Found %d topology files in home directory.", username, len(files))
	c.JSON(http.StatusOK, files)
}

// isValidLabName checks for potentially harmful characters in lab names.
// Allows alphanumeric, hyphen, underscore. Prevents path manipulation chars.
var labNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func isValidLabName(name string) bool {
	if name == "" || len(name) > 64 { // Add length limit for sanity
		return false
	}
	// Use regex for stricter validation
	return labNameRegex.MatchString(name)
	// Old basic check: return !strings.ContainsAny(name, "/\\;\"'`|&<>()$!*?[]# \t\n\r")
}
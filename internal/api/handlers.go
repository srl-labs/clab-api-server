// internal/api/handlers.go
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
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
	if name == "" || len(name) > 64 {
		return false
	}
	return labNameRegex.MatchString(name)
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
// @Description Deploys a containerlab topology, saving the file to the user's ~/.clab/<labname>/ directory and setting ownership to the authenticated user.
// @Description **Requires the API server process to run with privileges (e.g., as root or via sudo) sufficient to change file ownership (chown).**
// @Tags Labs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param deploy_request body models.DeployRequest true "Topology Content (YAML string)"
// @Success 200 {object} object "Raw JSON output from 'clab deploy' (or plain text on error)"
// @Failure 400 {object} models.ErrorResponse "Invalid input (e.g., empty/invalid topology, missing name, invalid lab name)"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error (e.g., permission denied for chown, clab execution failed)"
// @Router /api/v1/labs [post]
func DeployLabHandler(c *gin.Context) {
	username := c.GetString("username") // Authenticated user

	var req models.DeployRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("DeployLab failed for user '%s': Invalid request body: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	trimmedContent := strings.TrimSpace(req.TopologyContent)
	if trimmedContent == "" {
		log.Warnf("DeployLab failed for user '%s': Topology content cannot be empty", username)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Topology content cannot be empty"})
		return
	}

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

	// --- Parse Topology to Extract Lab Name ---
	var topoData map[string]interface{}
	err = yaml.Unmarshal([]byte(trimmedContent), &topoData)
	if err != nil {
		log.Warnf("DeployLab failed for user '%s': Could not parse topology YAML: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid topology YAML: " + err.Error()})
		return
	}

	labNameValue, ok := topoData["name"]
	if !ok {
		log.Warnf("DeployLab failed for user '%s': Topology YAML is missing the top-level 'name' field.", username)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Topology YAML must contain a top-level 'name' field."})
		return
	}
	labName, ok := labNameValue.(string)
	if !ok || labName == "" {
		log.Warnf("DeployLab failed for user '%s': Topology 'name' field is not a non-empty string.", username)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Topology 'name' field must be a non-empty string."})
		return
	}

	// --- Validate Lab Name ---
	if !isValidLabName(labName) {
		log.Warnf("DeployLab failed for user '%s': Invalid characters in extracted lab name '%s'", username, labName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in topology 'name'. Use alphanumeric, hyphen, underscore."})
		return
	}
	log.Debugf("DeployLab user '%s': Extracted lab name '%s'", username, labName)

	// --- Construct Paths ---
	// ~/.clab/<labname>/<labname>.clab.yml
	clabUserDir := filepath.Join(homeDir, ".clab")
	targetDir := filepath.Join(clabUserDir, labName)
	targetFilePath := filepath.Join(targetDir, labName+".clab.yml") // Standard naming convention

	// --- Create Directory ---
	// Permissions 0750: user(rwx), group(rx), other(-) initially set by API server user
	log.Debugf("DeployLab user '%s': Ensuring directory exists: '%s'", username, targetDir)
	err = os.MkdirAll(targetDir, 0750)
	if err != nil {
		log.Errorf("DeployLab failed for user '%s': Failed to create directory '%s': %v.", username, targetDir, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to create lab directory: %s.", err.Error())})
		return
	}

	// --- Change Directory Ownership ---
	log.Debugf("DeployLab user '%s': Setting ownership of directory '%s' to uid %d, gid %d", username, targetDir, uid, gid)
	err = os.Chown(targetDir, uid, gid)
	if err != nil {
		log.Errorf("DeployLab failed for user '%s': Failed to chown directory '%s' to uid %d, gid %d: %v. Check API server privileges.", username, targetDir, uid, gid, err)
		// Clean up the potentially wrongly-owned directory? Maybe not, could contain previous user data if MkdirAll didn't create it.
		// For now, fail the request as ownership is critical.
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to set ownership on lab directory: %s. API server requires privileges (e.g., run as root).", err.Error())})
		return
	}
	log.Infof("Set ownership of directory '%s' to user '%s' (uid %d, gid %d)", targetDir, username, uid, gid)

	// --- Write Topology File ---
	// Permissions 0640: user(rw), group(r), other(-) initially set by API server user
	log.Debugf("DeployLab user '%s': Writing topology file: '%s'", username, targetFilePath)
	err = os.WriteFile(targetFilePath, []byte(trimmedContent), 0640)
	if err != nil {
		log.Errorf("DeployLab failed for user '%s': Failed to write topology file '%s': %v.", username, targetFilePath, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to write topology file: %s.", err.Error())})
		return
	}

	// --- Change File Ownership ---
	log.Debugf("DeployLab user '%s': Setting ownership of file '%s' to uid %d, gid %d", username, targetFilePath, uid, gid)
	err = os.Chown(targetFilePath, uid, gid)
	if err != nil {
		log.Errorf("DeployLab failed for user '%s': Failed to chown file '%s' to uid %d, gid %d: %v. Check API server privileges.", username, targetFilePath, uid, gid, err)
		// Clean up the wrongly-owned file?
		_ = os.Remove(targetFilePath) // Attempt cleanup, ignore error
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to set ownership on topology file: %s. API server requires privileges (e.g., run as root).", err.Error())})
		return
	}
	log.Infof("Saved topology and set ownership for user '%s' lab '%s' to '%s'", username, labName, targetFilePath)

	// --- Execute clab deploy ---
	// Use the persistent file path.
	args := []string{"deploy", "--topo", targetFilePath, "--format", "json", "--reconfigure"}
	log.Infof("DeployLab user '%s': Executing clab deploy using '%s'...", username, targetFilePath)
	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...) // username for logging

	// Handle command execution results
	if stderr != "" {
		log.Warnf("DeployLab user '%s', lab '%s': clab deploy stderr: %s", username, labName, stderr)
	}
	if err != nil {
		log.Errorf("DeployLab failed for user '%s', lab '%s': clab deploy command execution error: %v", username, labName, err)
		errMsg := fmt.Sprintf("Failed to deploy lab '%s': %s", labName, err.Error())
		if stderr != "" {
			errMsg += "\nstderr: " + stderr
		}
		// File ownership was set correctly, but deploy failed. Leave the file.
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	log.Infof("DeployLab user '%s': clab deploy for lab '%s' executed successfully.", username, labName)

	// Attempt to parse stdout as JSON and return it
	var result interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		log.Warnf("DeployLab user '%s', lab '%s': Output from clab was not valid JSON: %v. Returning as plain text.", username, labName, err)
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
// @Description Destroys a lab by name and attempts to remove the corresponding topology directory (~/.clab/<labname>).
// @Description Checks ownership via 'owner' field from clab inspect.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Name of the lab to destroy" example="my-test-lab"
// @Success 200 {object} models.GenericSuccessResponse
// @Failure 400 {object} models.ErrorResponse "Invalid lab name"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found or not owned by user"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/labs/{labName} [delete]
func DestroyLabHandler(c *gin.Context) {
	username := c.GetString("username") // Authenticated user
	labName := c.Param("labName")

	if !isValidLabName(labName) {
		log.Warnf("DestroyLab failed for user '%s': Invalid characters in lab name '%s'", username, labName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name. Use alphanumeric, hyphen, underscore."})
		return
	}
	log.Debugf("DestroyLab user '%s': Attempting to destroy lab '%s'", username, labName)

	// --- Verify lab exists and belongs to the user via inspect + owner field check ---
	log.Debugf("DestroyLab user '%s': Inspecting lab '%s' to verify ownership...", username, labName)
	inspectArgs := []string{"inspect", "--name", labName, "--format", "json"}
	inspectStdout, inspectStderr, inspectErr := clab.RunClabCommand(c.Request.Context(), username, inspectArgs...)

	if inspectStderr != "" {
		log.Warnf("DestroyLab user '%s': clab inspect stderr for lab '%s': %s", username, labName, inspectStderr)
	}
	if inspectErr != nil {
		errMsg := inspectErr.Error()
		if strings.Contains(inspectStdout, "no containers found") ||
			strings.Contains(errMsg, "no containers found") ||
			strings.Contains(errMsg, "no containerlab labs found") ||
			strings.Contains(inspectStderr, "no containers found") ||
			strings.Contains(inspectStderr, "Could not find containers for lab") {
			log.Infof("DestroyLab user '%s': Lab '%s' not found during inspection.", username, labName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' not found.", labName)})
			return
		}
		log.Errorf("DestroyLab failed for user '%s': Failed to inspect lab '%s' before destroy: %v", username, labName, inspectErr)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to inspect lab before destroying: %s", inspectErr.Error())})
		return
	}

	var inspectResult models.ClabInspectOutput
	if err := json.Unmarshal([]byte(inspectStdout), &inspectResult); err != nil {
		log.Errorf("DestroyLab failed for user '%s': Could not parse inspect output for lab '%s'. Output: %s, Error: %v", username, labName, inspectStdout, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Could not parse inspect output for lab '%s'.", labName)})
		return
	}

	if len(inspectResult.Containers) == 0 {
		log.Warnf("DestroyLab user '%s': Inspect for lab '%s' succeeded but returned no containers.", username, labName)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' not found (no containers returned).", labName)})
		return
	}

	actualOwner := inspectResult.Containers[0].Owner
	if actualOwner != username {
		log.Warnf("DestroyLab user '%s': Attempted to destroy lab '%s' but it is owned by '%s' (based on 'owner' field). Access denied.", username, labName, actualOwner)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' not found or not owned by user.", labName)})
		return
	}
	log.Debugf("DestroyLab user '%s': Ownership confirmed for lab '%s' via 'owner' field.", username, labName)
	// --- End Verification ---

	// --- Execute clab destroy ---
	log.Infof("DestroyLab user '%s': Executing clab destroy --name %s --cleanup...", username, labName)
	destroyArgs := []string{"destroy", "--name", labName, "--cleanup"}
	_, stderr, err := clab.RunClabCommand(c.Request.Context(), username, destroyArgs...) // username for logging

	// Handle clab destroy command result
	if err != nil {
		// clab destroy failed
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

	// --- Attempt to Cleanup Topology Directory ---
	log.Infof("Attempting to clean up topology directory for lab '%s', user '%s'.", labName, username)
	usr, lookupErr := user.Lookup(username)
	if lookupErr != nil {
		log.Warnf("Could not lookup user '%s' to cleanup topology directory: %v", username, lookupErr)
		// Don't fail the overall request, clab destroy succeeded.
	} else {
		targetDir := filepath.Join(usr.HomeDir, ".clab", labName)
		log.Debugf("Removing directory: %s", targetDir)
		cleanupErr := os.RemoveAll(targetDir)
		if cleanupErr != nil {
			// Log error but don't make the API call fail, main task (destroy) succeeded.
			log.Warnf("Failed to cleanup topology directory '%s' for user '%s' after destroy: %v. API server might lack permissions.", targetDir, username, cleanupErr)
		} else {
			log.Infof("Successfully cleaned up topology directory '%s' for user '%s'", targetDir, username)
		}
	}

	c.JSON(http.StatusOK, models.GenericSuccessResponse{Message: fmt.Sprintf("Lab '%s' destroyed successfully", labName)})
}

// InspectLabHandler - No changes needed, already uses owner field
// @Summary Inspect Lab
// @Description Get details about a specific running lab (checks ownership via 'owner' field from clab inspect)
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Name of the lab to inspect" example="my-test-lab"
// @Success 200 {object} models.ClabInspectOutput "Raw JSON output from 'clab inspect' for the specific lab"
// @Failure 400 {object} models.ErrorResponse "Invalid lab name"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found or not owned by user"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/labs/{labName} [get]
func InspectLabHandler(c *gin.Context) {
	username := c.GetString("username") // Authenticated user
	labName := c.Param("labName")

	if !isValidLabName(labName) {
		log.Warnf("InspectLab failed for user '%s': Invalid characters in lab name '%s'", username, labName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name. Use alphanumeric, hyphen, underscore."})
		return
	}
	log.Debugf("InspectLab user '%s': Inspecting lab '%s'", username, labName)

	args := []string{"inspect", "--name", labName, "--format", "json"}
	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...) // username for logging

	if stderr != "" {
		log.Warnf("InspectLab user '%s': clab inspect stderr for lab '%s': %s", username, labName, stderr)
	}
	if err != nil {
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

	// Parse the output to verify ownership via owner field
	var result models.ClabInspectOutput
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		log.Errorf("InspectLab failed for user '%s': Failed to parse clab inspect JSON output for lab '%s': %v", username, labName, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to parse clab inspect output: " + err.Error()})
		return
	}

	if len(result.Containers) == 0 {
		log.Warnf("InspectLab user '%s': Inspect for lab '%s' succeeded but returned no containers.", username, labName)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' not found (no containers returned).", labName)})
		return
	}

	// *** Check the Owner field ***
	actualOwner := result.Containers[0].Owner
	if actualOwner != username {
		log.Warnf("InspectLab user '%s': Attempted to inspect lab '%s' but it is owned by '%s' (based on 'owner' field). Access denied.", username, labName, actualOwner)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' not found or not owned by user.", labName)})
		return
	}

	log.Debugf("InspectLab user '%s': Inspection of lab '%s' successful, ownership confirmed via 'owner' field.", username, labName)
	c.JSON(http.StatusOK, result)
}

// ListLabsHandler - No changes needed, already uses owner field
// @Summary List All Labs
// @Description Get details about all running labs, filtered by the 'owner' field matching the authenticated user
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
			// Log the error but proceed as a non-superuser
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
	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...) // username for logging

	if stderr != "" {
		log.Warnf("ListLabs user '%s': clab inspect --all stderr: %s", username, stderr)
	}
	if err != nil {
		errMsg := err.Error()
		// Check if the error indicates no labs exist at all
		if strings.Contains(stdout, "no containers found") ||
			strings.Contains(errMsg, "no containerlab labs found") ||
			strings.Contains(stderr, "no containers found") {
			log.Infof("ListLabs user '%s': No labs found via clab inspect.", username)
			c.JSON(http.StatusOK, models.ClabInspectOutput{Containers: []models.ClabContainerInfo{}}) // Return empty list
			return
		}
		// Otherwise, it's a real error
		log.Errorf("ListLabs failed for user '%s': clab inspect --all command failed: %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to list labs: %s", err.Error())})
		return
	}

	log.Debugf("ListLabs user '%s': inspect --all command successful, parsing...", username)

	// Parse the full output
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
		finalResult = fullResult // Superuser gets everything
	} else {
		// Filter the containers based on the owner field for regular users
		filteredContainers := []models.ClabContainerInfo{}
		labsFoundForUser := make(map[string]bool) // Keep track of unique lab names found for the user

		for _, cont := range fullResult.Containers {
			// Check the Owner field
			if cont.Owner == username {
				// Add the container if it belongs to the user
				filteredContainers = append(filteredContainers, cont)
				// Mark the lab name as found for this user
				if !labsFoundForUser[cont.LabName] {
					labsFoundForUser[cont.LabName] = true
					log.Debugf("ListLabs user '%s': Found lab '%s' owned by user.", username, cont.LabName)
				}
			} else {
				// Log only once per lab that doesn't belong to the user for clarity
				_, checked := labsFoundForUser[cont.LabName]
				if !checked && cont.Owner != "" { // Avoid logging for labs potentially not managed by clab-api
					log.Debugf("ListLabs user '%s': Filtering out lab '%s' owned by '%s'.", username, cont.LabName, cont.Owner)
					labsFoundForUser[cont.LabName] = false // Mark as checked, but not owned by user
				}
			}
		}

		// Count how many labs were actually owned by the user
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

// internal/api/handlers.go
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"io/ioutil" // Still needed for TempFile
	"os"
	// "os/user" // No longer needed here
	"path/filepath"
	"regexp"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3" // Import YAML library for modifying topology

	"github.com/FloSch62/clab-api/internal/auth"
	"github.com/FloSch62/clab-api/internal/clab"
	"github.com/FloSch62/clab-api/internal/models"
)

const apiOwnerLabel = "clab-api.owner" // Docker label key

// isValidLabName checks for potentially harmful characters in lab names.
// Allows alphanumeric, hyphen, underscore. Prevents path manipulation chars.
var labNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func isValidLabName(name string) bool {
	if name == "" || len(name) > 64 { // Add length limit for sanity
		return false
	}
	return labNameRegex.MatchString(name)
}

// LoginHandler - No changes needed here, relies on ValidateCredentials
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

	// Use the improved validation function (now using PAM)
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

// addOwnerLabelToTopology attempts to parse YAML, add the owner label, and return modified YAML
func addOwnerLabelToTopology(yamlContent, ownerUsername string) (string, error) {
	var topo map[string]interface{}
	err := yaml.Unmarshal([]byte(yamlContent), &topo)
	if err != nil {
		return "", fmt.Errorf("failed to parse topology YAML: %w", err)
	}

	// Ensure 'labels' map exists at the top level
	if _, ok := topo["labels"]; !ok {
		topo["labels"] = make(map[string]interface{})
	}

	labelsMap, ok := topo["labels"].(map[string]interface{})
	if !ok {
		// It exists but isn't a map, which is weird YAML. Try to overwrite? Or error?
		log.Warnf("Topology 'labels' field is not a map, overwriting. Original type: %T", topo["labels"])
		labelsMap = make(map[string]interface{})
		topo["labels"] = labelsMap
		// Alternatively: return "", fmt.Errorf("topology 'labels' field is not a map")
	}

	// Add or overwrite the owner label
	labelsMap[apiOwnerLabel] = ownerUsername

	// Marshal back to YAML
	modifiedYamlBytes, err := yaml.Marshal(topo)
	if err != nil {
		return "", fmt.Errorf("failed to marshal modified topology YAML: %w", err)
	}

	return string(modifiedYamlBytes), nil
}


// @Summary Deploy Lab
// @Description Deploys a containerlab topology for the authenticated user (runs as API server user, labeled with owner)
// @Tags Labs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param deploy_request body models.DeployRequest true "Topology Content"
// @Success 200 {object} object "Raw JSON output from 'clab deploy' (or plain text on error)"
// @Failure 400 {object} models.ErrorResponse "Invalid input (e.g., empty topology content, invalid YAML)"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error (e.g., failed to create temp file, clab execution failed)"
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

	// --- Add Owner Label ---
	modifiedTopoContent, err := addOwnerLabelToTopology(trimmedContent, username)
	if err != nil {
		log.Warnf("DeployLab failed for user '%s': Could not add owner label to topology: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("Failed to process topology YAML: %s", err.Error())})
		return
	}
	log.Debugf("DeployLab user '%s': Added owner label to topology.", username)
	// --- End Add Owner Label ---


	// Create a temporary file in a system temp location (e.g., /tmp) accessible by the API server user
	// Suffix is important for clab
	tempFile, err := ioutil.TempFile("", "api-*.clab.yaml") // Use system temp dir
	if err != nil {
		log.Errorf("DeployLab failed for user '%s': Failed to create temporary topology file: %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to create temporary topology file: " + err.Error()})
		return
	}
	defer os.Remove(tempFile.Name()) // Defer removal *after* error checking

	log.Debugf("DeployLab user '%s': Created temporary topology file '%s'", username, tempFile.Name())

	// Write the *modified* topology content to the temporary file
	if _, err := tempFile.Write([]byte(modifiedTopoContent)); err != nil { // Use modified content
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
	// Add the label via command line as well (might be redundant but safer)
	// Note: Check if clab 'deploy' supports --label directly. If not, rely on the label in the topo file.
	// As of recent versions, `clab deploy` doesn't seem to have a global --label flag like `docker run`.
	// Relying on the label within the topology file (added above) is the primary method.
	args := []string{"deploy", "--topo", tempFile.Name(), "--format", "json", "--reconfigure"}

	// Execute clab command (runs as API server user)
	log.Infof("DeployLab user '%s': Executing clab deploy...", username)
	// Pass username for logging purposes, not execution context
	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	// Handle command execution results
	if stderr != "" {
		log.Warnf("DeployLab user '%s': clab command stderr: %s", username, stderr)
	}
	if err != nil {
		log.Errorf("DeployLab failed for user '%s': clab command execution error: %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to deploy lab: %s", err.Error())})
		return
	}

	log.Infof("DeployLab user '%s': clab deploy executed successfully.", username)

	// Attempt to parse stdout as JSON and return it
	var result interface{}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		log.Warnf("DeployLab user '%s': Output from clab was not valid JSON: %v. Returning as plain text.", username, err)
		c.JSON(http.StatusOK, gin.H{"output": stdout, "warning": "Output was not valid JSON"})
		return
	}

	c.JSON(http.StatusOK, result)
}


// @Summary Destroy Lab
// @Description Destroys a specific containerlab lab by name (identified by label for the authenticated user)
// @Description Note: This attempts cleanup using the lab name. If the topology defined unique resources (e.g., networks) not automatically tied to the lab name by clab, they might be orphaned.
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

	// --- Verify lab exists and belongs to the user via inspect + label check ---
	log.Debugf("DestroyLab user '%s': Inspecting lab '%s' to verify ownership...", username, labName)
	// Inspect the specific lab name. We don't need --all here.
	inspectArgs := []string{"inspect", "--name", labName, "--format", "json"}
	inspectStdout, inspectStderr, inspectErr := clab.RunClabCommand(c.Request.Context(), username, inspectArgs...) // username for logging

	if inspectStderr != "" {
		log.Warnf("DestroyLab user '%s': clab inspect stderr for lab '%s': %s", username, labName, inspectStderr)
	}
	if inspectErr != nil {
		errMsg := inspectErr.Error()
		if strings.Contains(inspectStdout, "no containers found") ||
		   strings.Contains(errMsg, "no containers found") ||
		   strings.Contains(errMsg, "no containerlab labs found") ||
		   strings.Contains(inspectStderr, "no containers found") {
			log.Infof("DestroyLab user '%s': Lab '%s' not found during inspection.", username, labName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' not found.", labName)})
			return
		}
		log.Errorf("DestroyLab failed for user '%s': Failed to inspect lab '%s' before destroy: %v", username, labName, inspectErr)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to inspect lab before destroying: %s", inspectErr.Error())})
		return
	}

	// Parse inspect output to check the label
	var inspectResult models.ClabInspectOutput
	if err := json.Unmarshal([]byte(inspectStdout), &inspectResult); err != nil || len(inspectResult.Containers) == 0 {
		log.Errorf("DestroyLab failed for user '%s': Could not parse inspect output or find containers for lab '%s'. Output: %s", username, labName, inspectStdout)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Could not parse inspect output for lab '%s'.", labName)})
		return
	}

	// Check the label on the first container (should be consistent)
	ownerLabelValue := ""
	if len(inspectResult.Containers) > 0 && inspectResult.Containers[0].Labels != nil {
		ownerLabelValue = inspectResult.Containers[0].Labels[apiOwnerLabel]
	}

	if ownerLabelValue != username {
		log.Warnf("DestroyLab user '%s': Attempted to destroy lab '%s' but it is owned by '%s' (or label missing).", username, labName, ownerLabelValue)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' not found or not owned by user.", labName)}) // Treat as not found from user's perspective
		return
	}
	log.Debugf("DestroyLab user '%s': Ownership confirmed for lab '%s'.", username, labName)
	// --- End Verification ---


	// --- Execute clab destroy ---
	// Use --name and --cleanup. This is often sufficient, but might leave orphaned resources
	// if the original topology file defined them and clab can't find/remove them by name alone.
	// We no longer have easy access to the original temp topology file.
	log.Infof("DestroyLab user '%s': Executing clab destroy --name %s --cleanup...", username, labName)
	destroyArgs := []string{"destroy", "--name", labName, "--cleanup"}

	// Pass username for logging
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
// @Description Get details about a specific running lab (checks ownership via label)
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

	// Pass username for logging
	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	if stderr != "" {
		log.Warnf("InspectLab user '%s': clab inspect stderr for lab '%s': %s", username, labName, stderr)
	}
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(stdout, "no containers found") ||
		   strings.Contains(errMsg, "no containers found") ||
		   strings.Contains(errMsg, "no containerlab labs found") ||
		   strings.Contains(stderr, "no containers found") {
			log.Infof("InspectLab user '%s': Lab '%s' not found.", username, labName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' not found.", labName)})
			return
		}
		log.Errorf("InspectLab failed for user '%s': clab inspect command failed for lab '%s': %v", username, labName, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to inspect lab '%s': %s", labName, err.Error())})
		return
	}

	// Parse the output to verify ownership via label
	var result models.ClabInspectOutput // Use struct to access labels
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		log.Errorf("InspectLab failed for user '%s': Failed to parse clab inspect JSON output for lab '%s': %v", username, labName, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to parse clab inspect output: " + err.Error()})
		return
	}

	// Check label
	ownerLabelValue := ""
	// Ensure containers exist and labels map exists before accessing
	if len(result.Containers) > 0 && result.Containers[0].Labels != nil {
		ownerLabelValue = result.Containers[0].Labels[apiOwnerLabel]
	}

	if ownerLabelValue != username {
		log.Warnf("InspectLab user '%s': Attempted to inspect lab '%s' but it is owned by '%s' (or label missing).", username, labName, ownerLabelValue)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' not found or not owned by user.", labName)}) // Treat as not found from user's perspective
		return
	}

	log.Debugf("InspectLab user '%s': Inspection of lab '%s' successful, ownership confirmed.", username, labName)
	// Return the full parsed result (which is ClabInspectOutput type)
	c.JSON(http.StatusOK, result)
}


// @Summary List All Labs
// @Description Get details about all running labs labeled for the authenticated user
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.ClabInspectOutput "Filtered JSON output from 'clab inspect --all'"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/labs [get]
func ListLabsHandler(c *gin.Context) {
	username := c.GetString("username") // Authenticated user
	log.Debugf("ListLabs user '%s': Listing all labs and filtering...", username)

	// Get all labs run by the API server user. Filtering happens *after*.
	args := []string{"inspect", "--all", "--format", "json"}

	// Pass username for logging
	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	if stderr != "" {
		log.Warnf("ListLabs user '%s': clab inspect --all stderr: %s", username, stderr)
	}
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(stdout, "no containers found") ||
		   strings.Contains(errMsg, "no containerlab labs found") ||
		   strings.Contains(stderr, "no containers found") {
			log.Infof("ListLabs user '%s': No labs found at all.", username)
			c.JSON(http.StatusOK, models.ClabInspectOutput{Containers: []models.ClabContainerInfo{}}) // Return empty list
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

	// Filter the containers based on the owner label
	filteredContainers := []models.ClabContainerInfo{}
	labsFound := make(map[string]bool) // Track labs already added

	for _, cont := range fullResult.Containers {
		// Check if the container has the owner label and it matches the user
		ownerLabelValue := ""
		if cont.Labels != nil {
			ownerLabelValue = cont.Labels[apiOwnerLabel]
		}

		if ownerLabelValue == username {
			// Add all containers belonging to this lab if we haven't added the lab yet
			if !labsFound[cont.LabName] {
				log.Debugf("ListLabs user '%s': Found lab '%s' owned by user, adding its containers.", username, cont.LabName)
				// Find all other containers for the *same lab* from the full result
				for _, labCont := range fullResult.Containers {
					if labCont.LabName == cont.LabName {
						// Double-check label consistency (optional but good practice)
						innerOwner := ""
						if labCont.Labels != nil {
							innerOwner = labCont.Labels[apiOwnerLabel]
						}
						if innerOwner == username {
							filteredContainers = append(filteredContainers, labCont)
						} else {
							log.Warnf("ListLabs user '%s': Container '%s' in lab '%s' has inconsistent owner label ('%s' vs expected '%s'). Skipping.", username, labCont.Name, labCont.LabName, innerOwner, username)
						}
					}
				}
				labsFound[cont.LabName] = true // Mark lab as added
			}
		} else {
			// Log only once per lab that doesn't match
			if _, checked := labsFound[cont.LabName]; !checked {
				log.Debugf("ListLabs user '%s': Filtering out lab '%s' owned by '%s' (or label missing/mismatch).", username, cont.LabName, ownerLabelValue)
				labsFound[cont.LabName] = true // Mark as checked/filtered out
			}
		}
	}


	log.Infof("ListLabs user '%s': Found %d labs owned by user.", username, len(labsFound)) // Count unique labs found
	c.JSON(http.StatusOK, models.ClabInspectOutput{Containers: filteredContainers})
}


// @Summary List Topologies
// @Description Lists available .clab.yml/.clab.yaml files (Not implemented in sudoless mode - Requires defining a storage strategy)
// @Tags Topologies
// @Security BearerAuth
// @Produce json
// @Success 501 {object} models.ErrorResponse "Not Implemented"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Router /api/v1/topologies [get]
func ListTopologiesHandler(c *gin.Context) {
	username := c.GetString("username")
	log.Warnf("ListTopologies user '%s': Endpoint not implemented in sudoless mode.", username)
	// This endpoint needs a defined strategy for where user topologies are stored
	// when the API server runs as a central user. Options:
	// 1. Upload topologies via another API endpoint.
	// 2. Define a directory structure accessible by the API server user, e.g., /etc/clab-api/topologies/<username>/
	// For now, return Not Implemented.
	c.JSON(http.StatusNotImplemented, models.ErrorResponse{Error: "Listing stored topologies is not implemented in this configuration."})

	/* // Example implementation if using a predefined path structure:
	   topologyBaseDir := "/etc/clab-api/topologies" // Make this configurable
	   userTopoDir := filepath.Join(topologyBaseDir, username)

	   log.Debugf("ListTopologies user '%s': Listing topology files from '%s'", username, userTopoDir)

	   var files []models.TopologyListItem
	   dirEntries, err := os.ReadDir(userTopoDir) // Read the specific user's subdir
	   if err != nil {
	       if os.IsNotExist(err) {
	           log.Infof("ListTopologies user '%s': No topology directory found at '%s'", username, userTopoDir)
	           c.JSON(http.StatusOK, []models.TopologyListItem{}) // Return empty list
	           return
	       }
	       log.Errorf("ListTopologies failed for user '%s': Failed to read directory '%s': %v", username, userTopoDir, err)
	       c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to read topologies directory: " + err.Error()})
	       return
	   }

	   for _, entry := range dirEntries {
	       if !entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
	           if strings.HasSuffix(entry.Name(), ".clab.yml") || strings.HasSuffix(entry.Name(), ".clab.yaml") {
	               files = append(files, models.TopologyListItem{
	                   Filename:     entry.Name(),
	                   RelativePath: entry.Name(), // Path relative to the user's topology dir
	               })
	           }
	       }
	   }
	   log.Infof("ListTopologies user '%s': Found %d topology files in '%s'.", username, len(files), userTopoDir)
	   c.JSON(http.StatusOK, files)
	*/
}
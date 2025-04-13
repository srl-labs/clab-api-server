// internal/api/helpers.go
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

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

// verifyLabOwnership checks if a lab exists and is owned by the user.
// Returns the original topology path (if found) and nil error on success.
// Sends appropriate HTTP error response and returns non-nil error on failure.
func verifyLabOwnership(c *gin.Context, username, labName string) (string, error) {
	log.Debugf("Verifying ownership for user '%s', lab '%s'", username, labName)
	inspectArgs := []string{"inspect", "--name", labName, "--format", "json"}
	// Use request context to potentially cancel if client disconnects
	ctx := c.Request.Context()

	inspectStdout, inspectStderr, inspectErr := clab.RunClabCommand(ctx, username, inspectArgs...) // username for logging

	if inspectStderr != "" {
		log.Warnf("Ownership check (via inspect) stderr for user '%s', lab '%s': %s", username, labName, inspectStderr)
	}
	if inspectErr != nil {
		errMsg := inspectErr.Error()
		// Check various "not found" messages from clab output/error
		if strings.Contains(inspectStdout, "no containers found") ||
			strings.Contains(errMsg, "no containers found") ||
			strings.Contains(errMsg, "no containerlab labs found") ||
			strings.Contains(inspectStderr, "no containers found") || // <-- Corrected
			strings.Contains(inspectStderr, "Could not find containers for lab") { // <-- Corrected
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
		// This case might occur if inspect runs but finds no matching containers (e.g., lab exists but has no nodes?)
		log.Warnf("Ownership check failed for user '%s': Inspect for lab '%s' succeeded but returned no containers.", username, labName)
		err := fmt.Errorf("lab '%s' not found (no containers returned)", labName)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
		return "", err
	}

	// Use the owner and path from the *first* container found for the lab
	actualOwner := inspectResult.Containers[0].Owner
	originalTopoPath := inspectResult.Containers[0].LabPath

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
			// Use 404 for security (don't reveal existence if not owned)
			err := fmt.Errorf("lab '%s' not found or not owned by user", labName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
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

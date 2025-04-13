// internal/api/info_handlers.go
package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// @Summary Get Containerlab Version
// @Description Retrieves the installed containerlab version information by running 'clab version'.
// @Tags Version
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.VersionResponse "Containerlab version details"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/version [get]
func GetVersionHandler(c *gin.Context) {
	username := c.GetString("username") // For logging context
	log.Debugf("GetVersion user '%s': Requesting containerlab version info...", username)

	args := []string{"version"}
	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	if stderr != "" {
		log.Warnf("GetVersion user '%s': 'clab version' stderr: %s", username, stderr)
	}
	if err != nil {
		log.Errorf("GetVersion failed for user '%s': 'clab version' command execution error: %v", username, err)
		errMsg := fmt.Sprintf("Failed to get containerlab version: %s", err.Error())
		if stderr != "" {
			errMsg += "\nstderr: " + stderr
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	log.Infof("GetVersion user '%s': Successfully retrieved containerlab version info.", username)
	c.JSON(http.StatusOK, models.VersionResponse{VersionInfo: strings.TrimSpace(stdout)}) // Trim potential whitespace
}

// @Summary Check for Containerlab Updates
// @Description Checks if a newer version of containerlab is available by running 'clab version check'.
// @Tags Version
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.VersionCheckResponse "Result of the version check"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/version/check [get]
func CheckVersionHandler(c *gin.Context) {
	username := c.GetString("username") // For logging context
	log.Debugf("CheckVersion user '%s': Requesting containerlab version check...", username)

	args := []string{"version", "check"}
	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	if stderr != "" {
		log.Warnf("CheckVersion user '%s': 'clab version check' stderr: %s", username, stderr)
	}
	if err != nil {
		log.Errorf("CheckVersion failed for user '%s': 'clab version check' command execution error: %v", username, err)
		errMsg := fmt.Sprintf("Failed to check for containerlab updates: %s", err.Error())
		if stderr != "" {
			errMsg += "\nstderr: " + stderr
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	log.Infof("CheckVersion user '%s': Successfully performed containerlab version check.", username)
	c.JSON(http.StatusOK, models.VersionCheckResponse{CheckResult: strings.TrimSpace(stdout)}) // Trim potential whitespace
}

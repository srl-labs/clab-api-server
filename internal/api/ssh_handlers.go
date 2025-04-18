// internal/api/ssh_handlers.go
package api

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/models"
	"github.com/srl-labs/clab-api-server/internal/ssh"
)

// Global SSH manager instance
var sshManager *ssh.SSHManager

// InitSSHManager initializes the SSH manager
func InitSSHManager() {
	sshManager = ssh.NewSSHManager(
		ssh.DefaultSSHBasePort,
		ssh.DefaultSSHMaxPort,
		ssh.DefaultSSHCleanupTick,
		ssh.DefaultSSHSessionTimeout,
	)
}

// ShutdownSSHManager gracefully shuts down the SSH manager
func ShutdownSSHManager() {
	if sshManager != nil {
		sshManager.Shutdown()
	}
}

// @Summary Request SSH Access to Lab Node
// @Description Creates temporary SSH access to a specific lab node, returning connection details
// @Tags SSH Access
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param labName path string true "Lab name" example="my-lab"
// @Param nodeName path string true "Node name within the lab (not the full container name)" example="srl1"
// @Param sshRequest body models.SSHAccessRequest false "SSH access parameters"
// @Success 200 {object} models.SSHAccessResponse "SSH connection details"
// @Failure 400 {object} models.ErrorResponse "Invalid request parameters"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden (not owner of the lab)"
// @Failure 404 {object} models.ErrorResponse "Lab or node not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/nodes/{nodeName}/ssh [post]
func RequestSSHAccessHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	nodeName := c.Param("nodeName")

	// Validate inputs
	if !isValidLabName(labName) {
		log.Warnf("SSH Access failed for user '%s': Invalid lab name '%s'", username, labName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name format."})
		return
	}

	if !isValidNodeName(nodeName) {
		log.Warnf("SSH Access failed for user '%s': Invalid node name '%s'", username, nodeName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid node name format."})
		return
	}

	// Parse request
	var req models.SSHAccessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Empty request is fine, we'll use defaults
		if err != io.EOF {
			log.Warnf("SSH Access failed for user '%s': Invalid request body: %v", username, err)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request format: " + err.Error()})
			return
		}
	}

	// Set defaults and validate request parameters
	sshUsername := req.SSHUsername
	if sshUsername == "" {
		sshUsername = "admin" // Most network devices use admin or root
	}

	duration := ssh.DefaultSSHSessionTimeout
	if req.Duration != "" {
		var err error
		duration, err = time.ParseDuration(req.Duration)
		if err != nil {
			log.Warnf("SSH Access failed for user '%s': Invalid duration '%s'", username, req.Duration)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid duration format. Use values like '1h', '30m'."})
			return
		}

		if duration > ssh.MaxSSHSessionDuration {
			duration = ssh.MaxSSHSessionDuration
		}
	}

	// Verify lab ownership
	_, err := verifyLabOwnership(c, username, labName)
	if err != nil {
		// verifyLabOwnership already sent response
		return
	}

	// Get container (node) details
	// Construct the full container name as clab-<labName>-<nodeName>
	containerName := fmt.Sprintf("clab-%s-%s", labName, nodeName)
	containerInfo, err := verifyContainerOwnership(c, username, containerName)
	if err != nil {
		// verifyContainerOwnership already sent response
		return
	}

	// Extract container IP for SSH access
	containerIP := containerInfo.IPv4Address
	if containerIP == "" {
		log.Warnf("SSH Access failed for user '%s': Container '%s' has no IPv4 address", username, containerName)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Container has no IPv4 address for SSH access."})
		return
	}

	// Extract IP without CIDR notation if present
	if strings.Contains(containerIP, "/") {
		containerIP = strings.Split(containerIP, "/")[0]
	}

	// Standard SSH port is 22, but some containers might use different ports
	// This could be made configurable per node type
	containerPort := 22

	// Create SSH session
	session, err := sshManager.CreateSession(
		username,
		labName,
		nodeName,
		sshUsername,
		containerIP,
		containerPort,
		duration,
	)

	if err != nil {
		log.Errorf("SSH Access failed for user '%s': Failed to create SSH session: %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to create SSH access: " + err.Error()})
		return
	}

	// Get API server host
	apiServerHost := getAPIServerHost(c.Request)

	// Build response
	response := models.SSHAccessResponse{
		Port:       session.Port,
		Host:       apiServerHost,
		Username:   sshUsername,
		Expiration: session.Expiration,
		Command:    fmt.Sprintf("ssh -p %d %s@%s", session.Port, sshUsername, apiServerHost),
	}

	log.Infof("SSH access granted for user '%s' to lab '%s', node '%s' on port %d until %s",
		username, labName, nodeName, session.Port, session.Expiration.Format(time.RFC3339))

	c.JSON(http.StatusOK, response)
}

// @Summary List SSH Sessions
// @Description Lists all active SSH sessions for the authenticated user
// @Tags SSH Access
// @Security BearerAuth
// @Produce json
// @Success 200 {array} models.SSHSessionInfo "List of active SSH sessions"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Router /api/v1/ssh/sessions [get]
func ListSSHSessionsHandler(c *gin.Context) {
	username := c.GetString("username")
	isSuperuser := isSuperuser(username)

	sessions := sshManager.ListSessions(username, isSuperuser)

	c.JSON(http.StatusOK, sessions)
}

// @Summary Terminate SSH Session
// @Description Terminates a specific SSH session by port
// @Tags SSH Access
// @Security BearerAuth
// @Produce json
// @Param port path int true "SSH session port to terminate" example="2222"
// @Success 200 {object} models.GenericSuccessResponse "Session terminated successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid port parameter"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden (not owner of the session)"
// @Failure 404 {object} models.ErrorResponse "Session not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/ssh/sessions/{port} [delete]
func TerminateSSHSessionHandler(c *gin.Context) {
	username := c.GetString("username")

	port, err := strconv.Atoi(c.Param("port"))
	if err != nil {
		log.Warnf("Terminate SSH session failed for user '%s': Invalid port '%s'", username, c.Param("port"))
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid port parameter."})
		return
	}

	// Get session
	session, exists := sshManager.GetSession(port)
	if !exists {
		log.Warnf("Terminate SSH session failed for user '%s': Session on port %d not found", username, port)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: "SSH session not found."})
		return
	}

	// Check ownership
	if session.ApiUsername != username && !isSuperuser(username) {
		log.Warnf("Terminate SSH session failed for user '%s': Attempted to terminate session owned by '%s'",
			username, session.ApiUsername)
		c.JSON(http.StatusForbidden, models.ErrorResponse{Error: "You don't have permission to terminate this SSH session."})
		return
	}

	// Terminate session
	err = sshManager.TerminateSession(port)
	if err != nil {
		log.Errorf("Terminate SSH session failed for user '%s', port %d: %v", username, port, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to terminate SSH session: " + err.Error()})
		return
	}

	log.Infof("SSH session on port %d terminated by user '%s'", port, username)
	c.JSON(http.StatusOK, models.GenericSuccessResponse{Message: "SSH session terminated successfully."})
}

// Helper function to get API server host, respecting proxies and headers
func getAPIServerHost(r *http.Request) string {
	// Try X-Forwarded-Host header first (common with proxies)
	forwardedHost := r.Header.Get("X-Forwarded-Host")
	if forwardedHost != "" {
		return forwardedHost
	}

	// Fall back to Host header
	host := r.Host

	// If Host includes a port and we're using HTTP/HTTPS standard ports, remove it
	if strings.Contains(host, ":") {
		// Remove port if it's a standard port
		hostParts := strings.Split(host, ":")
		if len(hostParts) == 2 {
			if r.TLS != nil && hostParts[1] == "443" {
				// HTTPS on standard port
				return hostParts[0]
			} else if r.TLS == nil && hostParts[1] == "80" {
				// HTTP on standard port
				return hostParts[0]
			}
		}
	}

	return host
}

// Helper function for validating node names
func isValidNodeName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}

	// Similar to labNameRegex but might be different for your specific needs
	return labNameRegex.MatchString(name)
}

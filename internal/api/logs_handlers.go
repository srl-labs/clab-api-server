// internal/api/logs_handlers.go
package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/models"
)

// @Summary Get Node Logs
// @Description Get logs from a specific lab node (container)
// @Tags Logs
// @Security BearerAuth
// @Produce plain,json,octet-stream
// @Param labName path string true "Name of the lab" example="my-lab"
// @Param nodeName path string true "Full name of the container (node)" example="clab-my-lab-srl1"
// @Param tail query int false "Number of lines to show from the end of logs (default all)" example="100"
// @Param follow query boolean false "Follow log output (stream logs)" example="false"
// @Param format query string false "Output format ('plain' or 'json'). Default is 'plain'." example="plain"
// @Success 200 {string} string "Container logs (when format=plain)"
// @Success 200 {object} models.LogsResponse "Container logs (when format=json)"
// @Failure 400 {object} models.ErrorResponse "Invalid input (lab name, node filter, etc.)"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden (not owner of the lab)"
// @Failure 404 {object} models.ErrorResponse "Lab or node not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/nodes/{nodeName}/logs [get]
func GetNodeLogsHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	containerName := c.Param("nodeName")
	outputFormat := c.DefaultQuery("format", "plain")
	tailQuery := c.DefaultQuery("tail", "all")
	sinceQuery := c.Query("since")
	untilQuery := c.Query("until")
	follow := c.Query("follow") == "true"

	// --- Validate Inputs ---
	if !isValidLabName(labName) {
		log.Warnf("GetNodeLogs failed for user '%s': Invalid lab name '%s'", username, labName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}

	if !isValidContainerName(containerName) {
		log.Warnf("GetNodeLogs failed for user '%s': Invalid container name '%s'", username, containerName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid container name format."})
		return
	}

	if outputFormat != "plain" && outputFormat != "json" {
		log.Warnf("GetNodeLogs failed for user '%s': Invalid format '%s'", username, outputFormat)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid format parameter. Use 'plain' or 'json'."})
		return
	}

	// Process tail parameter
	var tailLines string
	if tailQuery != "all" {
		tail, err := strconv.Atoi(tailQuery)
		if err != nil || tail < 0 {
			log.Warnf("GetNodeLogs failed for user '%s': Invalid tail parameter '%s'", username, tailQuery)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'tail' parameter. Use a positive number or 'all'."})
			return
		}
		tailLines = tailQuery
	}

	// Process since and until parameters (validate time formats or durations)
	parsedSince := ""
	if sinceQuery != "" {
		// Try to parse as duration first (e.g., "10m", "1h")
		if duration, err := time.ParseDuration(sinceQuery); err == nil {
			parsedSince = time.Now().Add(-duration).Format(time.RFC3339)
		} else if _, err := time.Parse(time.RFC3339, sinceQuery); err == nil {
			// Valid RFC3339 timestamp
			parsedSince = sinceQuery
		} else {
			log.Warnf("GetNodeLogs failed for user '%s': Invalid since parameter '%s'", username, sinceQuery)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'since' parameter. Use RFC3339 timestamp or duration (e.g., '30m')."})
			return
		}
	}

	parsedUntil := ""
	if untilQuery != "" {
		// Try to parse as duration first (e.g., "10m", "1h")
		if duration, err := time.ParseDuration(untilQuery); err == nil {
			parsedUntil = time.Now().Add(-duration).Format(time.RFC3339)
		} else if _, err := time.Parse(time.RFC3339, untilQuery); err == nil {
			// Valid RFC3339 timestamp
			parsedUntil = untilQuery
		} else {
			log.Warnf("GetNodeLogs failed for user '%s': Invalid until parameter '%s'", username, untilQuery)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'until' parameter. Use RFC3339 timestamp or duration (e.g., '30m')."})
			return
		}
	}

	log.Debugf("GetNodeLogs user '%s': Fetching logs for lab '%s', container '%s'", username, labName, containerName)

	// --- Verify Container Ownership ---
	_, err := verifyContainerOwnership(c, username, containerName)
	if err != nil {
		// verifyContainerOwnership already sent response (404 or 500)
		return
	}

	// Get container ID for direct Docker/Podman call to get logs
	containerInfo, err := getContainerInfo(c, username, containerName)
	if err != nil {
		// getContainerInfo should already log errors
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to get container info: %s", err.Error())})
		return
	}

	containerID := containerInfo.ID
	if containerID == "" {
		log.Errorf("GetNodeLogs failed for user '%s': Container '%s' has no ID", username, containerName)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Container has no ID for logs retrieval."})
		return
	}

	// --- Execute Docker/Podman command to get logs ---
	// First, determine if running under Docker or Podman
	containerRuntime, err := getContainerRuntime(c, username)
	if err != nil {
		log.Errorf("GetNodeLogs failed for user '%s': Could not determine container runtime: %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Could not determine container runtime: %s", err.Error())})
		return
	}

	// Build command to get logs based on runtime and parameters
	args := []string{containerRuntime, "logs"}

	if tailLines != "" && tailLines != "all" {
		args = append(args, "--tail", tailLines)
	}

	if parsedSince != "" {
		args = append(args, "--since", parsedSince)
	}

	if parsedUntil != "" {
		args = append(args, "--until", parsedUntil)
	}

	// Add timestamps for better context
	args = append(args, "--timestamps")

	// Add container ID as the last argument
	args = append(args, containerID)

	log.Infof("GetNodeLogs user '%s': Executing %s logs for container '%s'", username, containerRuntime, containerName)

	// Determine if we should stream logs or fetch once
	if follow {
		// --- Stream Logs ---
		c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")

		// Set up a context that will be canceled when the client disconnects
		ctx, cancel := context.WithCancel(c.Request.Context())
		defer cancel()

		// Add --follow flag for streaming
		streamCmd := append(args, "--follow")

		// Execute command directly for streaming
		// We can't use RunClabCommand here because we need to stream the output
		cmd := exec.CommandContext(ctx, streamCmd[0], streamCmd[1:]...)

		// Get pipes for stdout and stderr
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Errorf("GetNodeLogs failed for user '%s': Could not create stdout pipe: %v", username, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Could not create stdout pipe: %s", err.Error())})
			return
		}

		stderr, err := cmd.StderrPipe()
		if err != nil {
			log.Errorf("GetNodeLogs failed for user '%s': Could not create stderr pipe: %v", username, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Could not create stderr pipe: %s", err.Error())})
			return
		}

		// Start the command
		if err := cmd.Start(); err != nil {
			log.Errorf("GetNodeLogs failed for user '%s': Could not start command: %v", username, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Could not start command: %s", err.Error())})
			return
		}

		// Use WaitGroup to ensure we capture all stderr output
		var wg sync.WaitGroup
		wg.Add(1)

		// Capture stderr in a separate goroutine
		var stderrOutput strings.Builder
		go func() {
			defer wg.Done()
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				stderrOutput.WriteString(scanner.Text() + "\n")
			}
		}()

		// Stream the logs line by line
		scanner := bufio.NewScanner(stdout)
		c.Stream(func(w io.Writer) bool {
			if !scanner.Scan() {
				return false
			}
			line := scanner.Text() + "\n"
			w.Write([]byte(line))
			return true
		})

		// Wait for stderr goroutine to finish
		wg.Wait()

		// Check for command errors
		if err := cmd.Wait(); err != nil {
			log.Errorf("GetNodeLogs command error for user '%s', container '%s': %v. Stderr: %s",
				username, containerName, err, stderrOutput.String())
			// Don't send an error response here since we've already started streaming
		}

		// Check for scanner errors
		if err := scanner.Err(); err != nil {
			log.Errorf("GetNodeLogs scanner error for user '%s', container '%s': %v",
				username, containerName, err)
		}

		return
	} else {
		// --- Fetch Logs Once ---
		// Execute the first element as the command and pass the rest as arguments
		cmd := args[0]
		cmdArgs := args[1:]

		// We can use exec.Command directly for better control over the execution
		stdout, stderr, err := runCommand(c.Request.Context(), cmd, cmdArgs...)

		if stderr != "" {
			log.Warnf("GetNodeLogs stderr for user '%s', container '%s': %s", username, containerName, stderr)
		}

		if err != nil {
			log.Errorf("GetNodeLogs failed for user '%s', container '%s': %v", username, containerName, err)
			errMsg := fmt.Sprintf("Failed to get logs for container '%s': %s", containerName, err.Error())
			if stderr != "" {
				errMsg += "\nstderr: " + stderr
			}
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
			return
		}

		log.Infof("GetNodeLogs success for user '%s', container '%s'", username, containerName)

		// Return logs based on requested format
		if outputFormat == "json" {
			// Format as JSON
			response := models.LogsResponse{
				ContainerName: containerName,
				Logs:          stdout,
			}
			c.JSON(http.StatusOK, response)
		} else {
			// Plain text output
			c.Header("Content-Type", "text/plain; charset=utf-8")
			c.String(http.StatusOK, stdout)
		}
	}
}

// getContainerInfo gets detailed information about a container using docker/podman inspect
func getContainerInfo(c *gin.Context, username string, containerName string) (*models.ContainerLogInfo, error) {
	containerRuntime, err := getContainerRuntime(c, username)
	if err != nil {
		return nil, err
	}

	// Run docker/podman inspect command with the exec package directly
	args := []string{"inspect", containerName}
	stdout, stderr, err := runCommand(c.Request.Context(), containerRuntime, args...)

	if err != nil {
		log.Errorf("getContainerInfo failed for container '%s': %v. Stderr: %s",
			containerName, err, stderr)
		return nil, fmt.Errorf("container inspect failed: %w", err)
	}

	// Parse the output (basic JSON parsing for now)
	var containers []map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &containers); err != nil {
		log.Errorf("getContainerInfo failed to parse JSON for container '%s': %v",
			containerName, err)
		return nil, fmt.Errorf("failed to parse container inspect output: %w", err)
	}

	if len(containers) == 0 {
		return nil, fmt.Errorf("no container info found for: %s", containerName)
	}

	// Extract the container ID
	containerID, ok := containers[0]["Id"].(string)
	if !ok {
		return nil, fmt.Errorf("could not extract container ID from inspect output")
	}

	return &models.ContainerLogInfo{
		Name: containerName,
		ID:   containerID,
	}, nil
}

// getContainerRuntime determines if the system is using Docker or Podman
func getContainerRuntime(c *gin.Context, username string) (string, error) {
	// Try Docker first
	dockerOut, _, dockerErr := runCommand(c.Request.Context(), "docker", "version", "--format", "{{.Server.Version}}")
	if dockerErr == nil && dockerOut != "" {
		return "docker", nil
	}

	// If Docker failed, try Podman
	podmanOut, _, podmanErr := runCommand(c.Request.Context(), "podman", "version", "--format", "{{.Version}}")
	if podmanErr == nil && podmanOut != "" {
		return "podman", nil
	}

	log.Errorf("Could not determine container runtime (docker/podman). Docker error: %v, Podman error: %v",
		dockerErr, podmanErr)
	return "", fmt.Errorf("no supported container runtime (docker/podman) found")
}

// runCommand executes a command and returns stdout, stderr, and error
func runCommand(ctx context.Context, command string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, command, args...)

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	return stdout.String(), stderr.String(), err
}

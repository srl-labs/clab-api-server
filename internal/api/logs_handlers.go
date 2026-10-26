// internal/api/logs_handlers.go
package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
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

// @Summary Get node logs
// @Description Returns logs for a lab node.
// @Description
// @Description **Notes**
// @Description - When `follow=true`, the response streams as NDJSON (one JSON object per line) until the client disconnects or after 12 hours.
// @Description - Streamed lines carry `stream` (`stdout` or `stderr`). A blank line is sent every 25 seconds while the node is quiet, so clients can tell a quiet node from a lost connection.
// @Tags Logs
// @Security BearerAuth
// @Produce json,application/x-ndjson
// @Param labName path string true "Name of the lab" example="my-lab"
// @Param nodeName path string true "Full name of the container (node)" example="clab-my-lab-srl1"
// @Param tail query string false "Number of lines to show from the end of logs (default all). Use an integer or 'all'." example="100" default(all)
// @Param follow query boolean false "Follow log output (stream logs as NDJSON). Note: In Swagger UI, streaming may not display correctly." example="false"
// @Success 200 {object} models.LogsResponse "Container logs (follow=false). When follow=true, response is NDJSON stream of LogLine objects."
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
	tailQuery := c.DefaultQuery("tail", "all")
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

	log.Debugf("GetNodeLogs user '%s': Fetching logs for lab '%s', container '%s'", username, labName, containerName)

	// --- First verify that the lab exists and user has permission ---
	_, err := verifyLabOwnership(c, username, labName)
	if err != nil {
		// verifyLabOwnership already sent response (404 or 403)
		return
	}

	// --- Next, verify the container name follows the expected format for the lab ---
	expectedPrefix := "clab-" + labName + "-"
	if !strings.HasPrefix(containerName, expectedPrefix) {
		log.Warnf("GetNodeLogs failed for user '%s': Container '%s' does not belong to lab '%s'",
			username, containerName, labName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error: fmt.Sprintf("Container '%s' does not belong to lab '%s'", containerName, labName),
		})
		return
	}

	// --- Now verify container ownership and existence ---
	containerInfo, err := verifyContainerOwnership(c, username, containerName)
	if err != nil {
		// verifyContainerOwnership already sent response (404 or 500)
		return
	}

	// Get container ID for direct Docker/Podman call to get logs
	containerID := containerInfo.ContainerID
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

	// Add timestamps for better context
	args = append(args, "--timestamps")

	// Add container ID as the last argument
	args = append(args, containerID)

	log.Infof("GetNodeLogs user '%s': Executing %s logs for container '%s'", username, containerRuntime, containerName)

	// Determine if we should stream logs or fetch once
	if follow {
		streamNodeLogs(c, username, containerName, append(args, "--follow"))
		return
	}

	// --- Fetch Logs Once ---
	// The runtime CLI writes the container's stderr to its own stderr, so both
	// go into the logs, in the order the CLI writes them. exec.Cmd writes to
	// one shared writer from one goroutine at a time.
	var output strings.Builder
	logsCmd := exec.CommandContext(c.Request.Context(), args[0], args[1:]...)
	logsCmd.Stdout = &output
	logsCmd.Stderr = &output

	if err := logsCmd.Run(); err != nil {
		log.Errorf("GetNodeLogs failed for user '%s', container '%s': %v", username, containerName, err)
		errMsg := fmt.Sprintf("Failed to get logs for container '%s': %s", containerName, err.Error())
		if detail := strings.TrimSpace(output.String()); detail != "" {
			errMsg += "\noutput: " + detail
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	log.Infof("GetNodeLogs success for user '%s', container '%s'", username, containerName)

	// Return logs as JSON
	response := models.LogsResponse{
		ContainerName: containerName,
		Logs:          output.String(),
	}
	c.JSON(http.StatusOK, response)
}

const (
	logsFollowTimeout      = 12 * time.Hour
	logsScannerMaxLineSize = 1024 * 1024
)

type streamedLogLine struct {
	stream string
	line   string
}

// streamNodeLogs runs `<runtime> logs --follow` and streams stdout and stderr as NDJSON
// lines, with heartbeats while the container is quiet.
func streamNodeLogs(c *gin.Context, username, containerName string, args []string) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), logsFollowTimeout)
	defer cancel()

	// We can't use RunClabCommand here because we need to stream the output
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
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
	if err := cmd.Start(); err != nil {
		log.Errorf("GetNodeLogs failed for user '%s': Could not start command: %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Could not start command: %s", err.Error())})
		return
	}

	// The runtime CLI writes the container's stderr to its own stderr, so both
	// pipes carry log lines.
	lines := make(chan streamedLogLine)
	var readers sync.WaitGroup
	scan := func(stream string, pipe io.Reader) {
		defer readers.Done()
		scanner := bufio.NewScanner(pipe)
		scanner.Buffer(make([]byte, 0, 64*1024), logsScannerMaxLineSize)
		for scanner.Scan() {
			select {
			case lines <- streamedLogLine{stream: stream, line: scanner.Text()}:
			case <-ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil && ctx.Err() == nil {
			log.Warnf("GetNodeLogs %s scanner error for user '%s', container '%s': %v",
				stream, username, containerName, err)
		}
	}
	readers.Add(2)
	go scan("stdout", stdout)
	go scan("stderr", stderr)
	go func() {
		readers.Wait()
		close(lines)
	}()

	c.Writer.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Status(http.StatusOK)
	c.Writer.WriteHeaderNow()

	writer := bufio.NewWriter(c.Writer)
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		cancel()
		_ = cmd.Wait()
		return
	}
	flusher.Flush()

	heartbeat := time.NewTicker(ndjsonStreamHeartbeatInterval)
	defer heartbeat.Stop()

stream:
	for {
		select {
		case <-ctx.Done():
			break stream
		case <-heartbeat.C:
			if !writeNDJSONHeartbeat(writer, flusher) {
				break stream
			}
		case entry, open := <-lines:
			if !open {
				break stream
			}
			payload, err := json.Marshal(models.LogLine{
				ContainerName: containerName,
				Line:          entry.line,
				Stream:        entry.stream,
			})
			if err != nil {
				log.Errorf("GetNodeLogs failed to marshal log line for user '%s': %v", username, err)
				continue
			}
			if !writeNDJSONLine(writer, flusher, string(payload)) {
				break stream
			}
		}
	}

	// Stop the command when the client left; drain so the readers finish.
	cancel()
	for range lines {
	}
	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		log.Warnf("GetNodeLogs command ended for user '%s', container '%s': %v", username, containerName, err)
	} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		log.Infof("Streaming logs ended for user '%s', container '%s' after %s", username, containerName, logsFollowTimeout)
	}
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

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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/clab"
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
	var tail *int64
	if tailQuery != "all" {
		lines, err := strconv.ParseInt(tailQuery, 10, 64)
		if err != nil || lines < 0 {
			log.Warnf("GetNodeLogs failed for user '%s': Invalid tail parameter '%s'", username, tailQuery)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid 'tail' parameter. Use a positive number or 'all'."})
			return
		}
		tail = &lines
	}

	log.Debugf("GetNodeLogs user '%s': Fetching logs for lab '%s', container '%s'", username, labName, containerName)

	// --- First verify that the lab exists and user has permission ---
	if _, err := verifyLabOwnership(c, username, labName); err != nil {
		// verifyLabOwnership already sent response (404 or 403)
		return
	}

	// A container of another lab is a client error, not a missing node.
	if hasDifferentDefaultContainerlabPrefix(labName, containerName) {
		log.Warnf("GetNodeLogs failed for user '%s': Container '%s' does not belong to lab '%s'",
			username, containerName, labName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error: fmt.Sprintf("Container '%s' does not belong to lab '%s'", containerName, labName),
		})
		return
	}

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	lookupCtx, lookupCancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
	container, err := resolveLabNodeContainer(lookupCtx, svc, username, labName, containerName)
	lookupCancel()
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("container '%s' not found", containerName)})
		return
	}
	containerInfo := clab.ContainerToClabContainerInfo(*container)
	if containerInfo.LabName != labName || !canAccessLab(username, &containerInfo) {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("container '%s' not found or not owned by user", containerName)})
		return
	}

	logsOpts := clab.NodeLogsOptions{
		Username:   username,
		LabName:    labName,
		NodeName:   resolveTopologyNodeName(labName, container),
		Tail:       tail,
		Timestamps: true,
	}

	log.Infof("GetNodeLogs user '%s': Reading %s logs of container '%s'", username, clab.RuntimeKind(), containerName)

	// Determine if we should stream logs or fetch once
	if follow {
		logsOpts.Follow = true
		streamNodeLogs(c, svc, username, containerName, logsOpts)
		return
	}

	// --- Fetch Logs Once ---
	// stdout and stderr go into one text, in the order the runtime writes them.
	output := &lockedBuffer{}
	if err := svc.NodeLogs(c.Request.Context(), logsOpts, output, output); err != nil {
		log.Errorf("GetNodeLogs failed for user '%s', container '%s': %v", username, containerName, err)
		errMsg := fmt.Sprintf("Failed to get logs for container '%s': %s", containerName, err.Error())
		c.JSON(serviceErrorStatus(err, http.StatusInternalServerError), models.ErrorResponse{Error: errMsg})
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

// lockedBuffer collects output that two streams may write at the same time.
type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

const (
	logsFollowTimeout      = 12 * time.Hour
	logsScannerMaxLineSize = 1024 * 1024
)

type streamedLogLine struct {
	stream string
	line   string
}

// streamNodeLogs follows a node's log through the runtime and streams stdout and stderr
// as NDJSON lines, with heartbeats while the node is quiet.
func streamNodeLogs(c *gin.Context, svc *clab.Service, username, containerName string, opts clab.NodeLogsOptions) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), logsFollowTimeout)
	defer cancel()

	stdout, stdoutWriter := io.Pipe()
	stderr, stderrWriter := io.Pipe()
	followErr := make(chan error, 1)
	go func() {
		err := svc.NodeLogs(ctx, opts, stdoutWriter, stderrWriter)
		_ = stdoutWriter.CloseWithError(io.EOF)
		_ = stderrWriter.CloseWithError(io.EOF)
		followErr <- err
	}()

	// Both pipes carry log lines: the runtime writes the container's stderr to stderr.
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
		_ = stdout.Close()
		_ = stderr.Close()
		if err := <-followErr; err != nil {
			log.Debugf("GetNodeLogs follow ended for user '%s': %v", username, err)
		}
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

	// Stop following when the client left; drain so the readers finish.
	cancel()
	_ = stdout.Close()
	_ = stderr.Close()
	for range lines {
	}
	if err := <-followErr; err != nil && ctx.Err() == nil {
		log.Warnf("GetNodeLogs follow ended for user '%s', container '%s': %v", username, containerName, err)
	} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		log.Infof("Streaming logs ended for user '%s', container '%s' after %s", username, containerName, logsFollowTimeout)
	}
}

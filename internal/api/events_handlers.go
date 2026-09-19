// internal/api/events_handlers.go
package api

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"
	clabcore "github.com/srl-labs/containerlab/core"
	clabevents "github.com/srl-labs/containerlab/core/events"
	clabruntime "github.com/srl-labs/containerlab/runtime"

	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

const (
	eventsScannerMaxBytes   = 1024 * 1024
	eventsRuntimeTimeout    = 5 * time.Minute
	labOwnershipCacheTTL    = 15 * time.Second
	labOwnershipLookupLimit = 10 * time.Second
)

type labOwnershipEntry struct {
	allowed   bool
	expiresAt time.Time
}

type clabEventJSON struct {
	Attributes map[string]string `json:"attributes"`
}

// @Summary Stream containerlab events
// @Description Streams containerlab events in real time as NDJSON (one JSON object per line).
// @Description
// @Description **Notes**
// @Description - The response stays open until the client disconnects.
// @Description
// @Description **Examples**
// @Description NDJSON (one JSON object per line):
// @Description ```json
// @Description {"time":1706918400,"type":"container","action":"start","attributes":{"name":"clab-mylab-srl1","lab":"mylab","clab-node-name":"srl1","clab-node-kind":"nokia_srlinux"}}
// @Description {"time":1706918405,"type":"container","action":"start","attributes":{"name":"clab-mylab-srl2","lab":"mylab","clab-node-name":"srl2","clab-node-kind":"nokia_srlinux"}}
// @Description ```
// @Description
// @Description
// @Description Interface stats (interfaceStats=true):
// @Description ```json
// @Description {"time":1706918410,"type":"interface-stats","action":"stats","attributes":{"name":"clab-mylab-srl1","lab":"mylab","interface":"e1-1","rx_bytes":123456,"tx_bytes":654321}}
// @Description ```
// @Tags Events
// @Security BearerAuth
// @Produce application/x-ndjson
// @Param initialState query boolean false "Include initial snapshot events when the stream starts." default(false)
// @Param interfaceStats query boolean false "Include interface stats events." default(false)
// @Param interfaceStatsInterval query string false "Interval for interface stats collection (e.g., 10s). Requires interfaceStats=true." default(10s)
// @Success 200 {object} models.EventResponse "Event stream - NDJSON (one JSON object per line)"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/events [get]
func StreamEventsHandler(c *gin.Context) {
	username := c.GetString("username")
	isSuperuserUser := isSuperuser(username)

	initialState, err := parseBoolQuery(c, "initialState", false)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid initialState parameter. Use true or false."})
		return
	}

	interfaceStats, err := parseBoolQuery(c, "interfaceStats", false)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid interfaceStats parameter. Use true or false."})
		return
	}

	interfaceStatsInterval := c.Query("interfaceStatsInterval")
	var statsInterval time.Duration
	if interfaceStatsInterval != "" {
		if !interfaceStats {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "interfaceStatsInterval requires interfaceStats=true."})
			return
		}
		if !isValidDurationString(interfaceStatsInterval) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid interfaceStatsInterval parameter. Use a valid duration like 10s."})
			return
		}
		parsedInterval, parseErr := time.ParseDuration(interfaceStatsInterval)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid interfaceStatsInterval parameter. Use a valid duration like 10s."})
			return
		}
		statsInterval = parsedInterval
	}

	runtime := strings.TrimSpace(config.AppConfig.ClabRuntime)
	if runtime == "" {
		runtime = "docker"
	}

	log.Infof("StreamEvents user '%s': Starting containerlab events stream (initialState=%v, interfaceStats=%v, interval=%s)",
		username, initialState, interfaceStats, interfaceStatsInterval)

	c.Writer.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
	c.Writer.Header().Set("Cache-Control", "no-cache")

	ctx, cancel := context.WithCancel(c.Request.Context())
	defer cancel()

	notifyChan := c.Writer.CloseNotify()
	go func() {
		<-notifyChan
		log.Infof("StreamEvents user '%s': Client disconnected", username)
		cancel()
	}()

	streamReader, streamWriter := io.Pipe()
	eventsOpts := clabevents.Options{
		Format:                "json",
		Runtime:               runtime,
		IncludeInitialState:   initialState,
		IncludeInterfaceStats: interfaceStats,
		StatsInterval:         statsInterval,
		ClabOptions: []clabcore.ClabOption{
			clabcore.WithTimeout(eventsRuntimeTimeout),
			clabcore.WithRuntime(runtime, &clabruntime.RuntimeConfig{Timeout: eventsRuntimeTimeout}),
		},
		Writer: streamWriter,
	}

	streamErrCh := make(chan error, 1)
	go func() {
		err := clabevents.Stream(ctx, eventsOpts)
		if err != nil {
			_ = streamWriter.CloseWithError(err)
		} else {
			_ = streamWriter.Close()
		}
		streamErrCh <- err
	}()

	// Ensure the client receives headers immediately, even if no events arrive yet.
	c.Status(http.StatusOK)
	c.Writer.WriteHeaderNow()
	if flusher, ok := c.Writer.(http.Flusher); ok {
		flusher.Flush()
	}
	// Send a keep-alive newline so clients don't block waiting for the first byte.
	if _, err := io.WriteString(c.Writer, "\n"); err != nil {
		cancel()
		return
	}
	if flusher, ok := c.Writer.(http.Flusher); ok {
		flusher.Flush()
	}

	ownershipCache := make(map[string]labOwnershipEntry)
	allowedLab := func(lab string) bool {
		if isSuperuserUser {
			return true
		}
		if lab == "" {
			return false
		}
		now := time.Now()
		if entry, ok := ownershipCache[lab]; ok && now.Before(entry.expiresAt) {
			return entry.allowed
		}
		ctx, cancel := context.WithTimeout(context.Background(), labOwnershipLookupLimit)
		defer cancel()
		info, exists, lookupErr := getLabInfo(ctx, username, lab)
		allowed := false
		if lookupErr == nil && exists && info != nil {
			allowed = canAccessLab(username, info)
		}
		ownershipCache[lab] = labOwnershipEntry{
			allowed:   allowed,
			expiresAt: now.Add(labOwnershipCacheTTL),
		}
		return allowed
	}

	scanner := bufio.NewScanner(streamReader)
	scanner.Buffer(make([]byte, 0, 64*1024), eventsScannerMaxBytes)

	scanLines := make(chan string)
	scanErrCh := make(chan error, 1)
	go func() {
		defer close(scanLines)
		defer func() {
			scanErrCh <- scanner.Err()
		}()
		for scanner.Scan() {
			select {
			case scanLines <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
	}()

	writer := bufio.NewWriter(c.Writer)
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		return
	}
	heartbeat := time.NewTicker(ndjsonStreamHeartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			if !writeNDJSONHeartbeat(writer, flusher) {
				return
			}
		case line, ok := <-scanLines:
			if !ok {
				cancel()
				if err := <-streamErrCh; err != nil && ctx.Err() == nil {
					log.Warnf("StreamEvents user '%s': Events stream ended with error: %v", username, err)
				}
				if err := <-scanErrCh; err != nil && ctx.Err() == nil {
					log.Errorf("StreamEvents user '%s': Scanner error: %v", username, err)
				}
				return
			}
			if !isSuperuserUser {
				labName, ok := extractLabFromEventLine(line)
				if !ok || !allowedLab(labName) {
					continue
				}
			}
			if !writeNDJSONLine(writer, flusher, line) {
				return
			}
		}
	}
}

func parseBoolQuery(c *gin.Context, name string, defaultValue bool) (bool, error) {
	raw := c.Query(name)
	if raw == "" {
		return defaultValue, nil
	}
	return strconv.ParseBool(raw)
}

func extractLabFromEventLine(line string) (string, bool) {
	return extractLabFromJSONLine(line)
}

func extractLabFromJSONLine(line string) (string, bool) {
	var evt clabEventJSON
	if err := json.Unmarshal([]byte(line), &evt); err != nil {
		return "", false
	}
	if evt.Attributes == nil {
		return "", false
	}
	if lab := evt.Attributes["lab"]; lab != "" {
		return lab, true
	}
	if lab := evt.Attributes["containerlab"]; lab != "" {
		return lab, true
	}
	return "", false
}

// Plain-text event parsing removed; NDJSON-only output is supported.

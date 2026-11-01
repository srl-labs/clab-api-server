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
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"
	clabconst "github.com/srl-labs/containerlab/constants"
	clabevents "github.com/srl-labs/containerlab/core/events"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	clabtypes "github.com/srl-labs/containerlab/types"

	"github.com/srl-labs/clab-api-server/internal/clab"
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

	streamOpts := clabevents.Options{
		Format:                "json",
		Runtime:               runtime,
		IncludeInitialState:   initialState,
		IncludeInterfaceStats: interfaceStats,
		StatsInterval:         statsInterval,
	}
	scanLines, streamErrCh := startEventStreams(ctx, GetClabService(), username, streamOpts)

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
				return
			}
			if !isSuperuserUser {
				if !canAccessEventLine(username, line, allowedLab) {
					continue
				}
			}
			if !writeNDJSONLine(writer, flusher, line) {
				return
			}
		}
	}
}

// Container events retain their trusted runtime labels after deletion. Checking
// the live lab at that point can suppress destroy events or reuse a cached grant
// for a different lab that later takes the same name.
func canAccessEventLine(username, line string, allowedLab func(string) bool) bool {
	var evt clabEventJSON
	if err := json.Unmarshal([]byte(line), &evt); err != nil {
		return false
	}
	lab := evt.Attributes["lab"]
	if lab == "" {
		lab = evt.Attributes["containerlab"]
	}
	if lab == "" {
		return false
	}
	owner := evt.Attributes["clab-owner"]
	path := evt.Attributes["clab-topo-file"]
	if path == "" {
		path = evt.Attributes["lab-path"]
	}
	if owner != "" && path != "" {
		return owner == username || isSharedLabPath(path)
	}
	// Interface events and older runtimes may not include ownership labels.
	return allowedLab(lab)
}

func parseBoolQuery(c *gin.Context, name string, defaultValue bool) (bool, error) {
	raw := c.Query(name)
	if raw == "" {
		return defaultValue, nil
	}
	return strconv.ParseBool(raw)
}

// eventsScopeRefresh is how often a lab runtime events stream looks for labs the user
// gained or lost, and starts or stops their streams.
var eventsScopeRefresh = 10 * time.Second

// startEventStreams streams containerlab events as JSON lines. A container runtime has one
// stream over every lab; a lab runtime has one stream per lab scope of the user (its
// namespace, as the user), started and stopped as labs come and go. The error channel
// gets one value once every stream ended.
func startEventStreams(
	ctx context.Context,
	svc *clab.Service,
	username string,
	opts clabevents.Options,
) (<-chan string, <-chan error) {
	lines := make(chan string)
	done := make(chan error, 1)

	var verifier *eventRecordVerifier
	if clab.IsLabRuntime() && svc != nil {
		verifier = newEventRecordVerifier(svc)
	}
	runStream := func(ctx context.Context, scope *clab.LabScope) error {
		streamOpts := opts
		streamOpts.ClabOptions = clab.EventClabOptions(scope, eventsRuntimeTimeout)
		reader, writer := io.Pipe()
		streamOpts.Writer = writer
		errCh := make(chan error, 1)
		go func() {
			err := clabevents.Stream(ctx, streamOpts)
			_ = writer.CloseWithError(err)
			errCh <- err
		}()
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 0, 64*1024), eventsScannerMaxBytes)
		for scanner.Scan() {
			line := scanner.Text()
			if verifier != nil {
				var ok bool
				if line, ok = verifier.verify(ctx, line); !ok {
					continue
				}
			}
			select {
			case lines <- line:
			case <-ctx.Done():
				_ = reader.Close()
				if err := <-errCh; err != nil {
					log.Debugf("events stream ended after the client left: %v", err)
				}
				return nil
			}
		}
		_ = reader.Close()
		if err := <-errCh; err != nil {
			return err
		}
		return scanner.Err()
	}

	if !clab.IsLabRuntime() || svc == nil {
		go func() {
			err := runStream(ctx, nil)
			close(lines)
			done <- err
		}()
		return lines, done
	}

	go func() {
		var wg sync.WaitGroup
		running := map[string]context.CancelFunc{}
		// ended reports streams that stopped on their own, so a later refresh restarts them.
		ended := make(chan string, 16)
		refresh := func() {
			scopes, err := svc.EventScopes(ctx, username)
			if err != nil {
				log.Warnf("StreamEvents user '%s': listing labs failed: %v", username, err)
				return
			}
			wanted := map[string]bool{}
			for _, scope := range scopes {
				key := scope.Namespace + "/" + scope.LabName
				wanted[key] = true
				if _, ok := running[key]; ok {
					continue
				}
				streamCtx, cancel := context.WithCancel(ctx)
				running[key] = cancel
				wg.Add(1)
				go func(scope clab.LabScope, key string) {
					defer wg.Done()
					if err := runStream(streamCtx, &scope); err != nil && streamCtx.Err() == nil {
						log.Warnf("StreamEvents user '%s': stream of %s ended: %v", username, key, err)
					}
					if streamCtx.Err() == nil {
						select {
						case ended <- key:
						case <-ctx.Done():
						}
					}
				}(scope, key)
			}
			for key, cancel := range running {
				if !wanted[key] {
					cancel()
					delete(running, key)
				}
			}
		}

		refresh()
		ticker := time.NewTicker(eventsScopeRefresh)
		defer ticker.Stop()
	loop:
		for {
			select {
			case <-ctx.Done():
				break loop
			case <-ticker.C:
				refresh()
			case key := <-ended:
				if cancel, ok := running[key]; ok {
					cancel()
					delete(running, key)
				}
			}
		}
		for _, cancel := range running {
			cancel()
		}
		wg.Wait()
		close(lines)
		done <- nil
	}()
	return lines, done
}

// eventRecordTTL is how long an events stream reuses what the server verified about a lab's
// owner and topology file.
const eventRecordTTL = 10 * time.Second

// eventRecordVerifier gives lab runtime container events the owner and topology file inspect
// reports: on c9s containerlab takes clab-owner and clab-topo-file from the Topology, which
// the lab's user can edit, so the stream corrects them from the server's records the way a
// listing does (clab.Service.VerifyLabRecords).
type eventRecordVerifier struct {
	svc *clab.Service

	mu    sync.Mutex
	cache map[string]verifiedEventRecord
}

type verifiedEventRecord struct {
	owner, topoFile string
	expiresAt       time.Time
}

func newEventRecordVerifier(svc *clab.Service) *eventRecordVerifier {
	return &eventRecordVerifier{svc: svc, cache: map[string]verifiedEventRecord{}}
}

// verify returns the event line with its clab-owner and clab-topo-file as the server's records
// have them; a line that needs no change is returned as it is. It reports false for an event
// whose records could not be checked, which the stream leaves out.
func (v *eventRecordVerifier) verify(ctx context.Context, line string) (string, bool) {
	var event map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		return line, true
	}
	var attributes map[string]string
	if raw, ok := event["attributes"]; !ok || json.Unmarshal(raw, &attributes) != nil {
		return line, true
	}
	namespace := attributes["namespace"]
	owner, hasOwner := attributes[clabconst.Owner]
	topoFile, hasTopoFile := attributes[clabconst.TopoFile]
	if namespace == "" || (!hasOwner && !hasTopoFile) {
		return line, true
	}
	lab := attributes[clabconst.Containerlab]
	if lab == "" {
		lab = attributes["lab"]
	}

	key := strings.Join([]string{namespace, lab, owner, topoFile}, "\x00")
	now := time.Now()
	v.mu.Lock()
	record, cached := v.cache[key]
	v.mu.Unlock()
	if !cached || !now.Before(record.expiresAt) {
		container := clabruntime.GenericContainer{
			Labels: map[string]string{
				clabconst.Containerlab: lab,
				clabconst.Owner:        owner,
				clabconst.TopoFile:     topoFile,
			},
			Workload: &clabtypes.LabRuntimeWorkload{Namespace: namespace},
		}
		containers := []clabruntime.GenericContainer{container}
		if err := v.svc.VerifyLabRecords(ctx, containers); err != nil {
			log.Warnf("events: leaving out an event of lab '%s' in namespace %s: its owner and topology file could not be checked: %v",
				lab, namespace, err)
			return "", false
		}
		record = verifiedEventRecord{
			owner:     containers[0].Labels[clabconst.Owner],
			topoFile:  containers[0].Labels[clabconst.TopoFile],
			expiresAt: now.Add(eventRecordTTL),
		}
		v.mu.Lock()
		v.cache[key] = record
		v.mu.Unlock()
	}
	if record.owner == owner && record.topoFile == topoFile {
		return line, true
	}
	if hasOwner || record.owner != "" {
		attributes[clabconst.Owner] = record.owner
	}
	if hasTopoFile {
		attributes[clabconst.TopoFile] = record.topoFile
	}
	raw, err := json.Marshal(attributes)
	if err != nil {
		return "", false
	}
	event["attributes"] = raw
	rewritten, err := json.Marshal(event)
	if err != nil {
		return "", false
	}
	return string(rewritten), true
}

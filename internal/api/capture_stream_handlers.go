// internal/api/capture_stream_handlers.go
package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"
	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	clabnames "github.com/srl-labs/containerlab/names"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/srl-labs/clab-api-server/internal/capture"
	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/kube"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// Lab runtime packet capture (plan 3.3): the containerlab library captures lab link
// interfaces through clabwire and writes one merged pcapng stream. The server delivers it as a
// chunked HTTP response, and writes it into the pipe of a Wireshark VNC session.

const (
	// maxCaptureTargets bounds the interfaces of one capture.
	maxCaptureTargets = 64
	// minCaptureSnapLength and maxCaptureSnapLength are the library's snap length bounds.
	minCaptureSnapLength = 64
	maxCaptureSnapLength = 1 << 20
	// captureResolveTimeout bounds checking the targets before a capture starts.
	captureResolveTimeout = 2 * time.Minute
)

// errInvalidCaptureTarget marks a capture target the lab cannot capture (400).
var errInvalidCaptureTarget = errors.New("invalid capture target")

// errNodeNotRunning marks a capture target on a node without a running pod (409).
var errNodeNotRunning = errors.New("node is not running")

// requireLabRuntimeCapture guards the lab runtime capture routes: they need a lab runtime
// (c9s), which captures through clabwire. With Docker and Podman, captures go through
// Edgeshark (the packetflix and wireshark-vnc-sessions routes).
func requireLabRuntimeCapture() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !clab.IsLabRuntime() {
			c.AbortWithStatusJSON(http.StatusNotImplemented, models.ErrorResponse{
				Error: fmt.Sprintf("packet capture streams need the lab runtime c9s; this server runs %s, use Edgeshark (capture/packetflix)", clab.RuntimeKind()),
			})
			return
		}
		c.Next()
	}
}

// parseCaptureTarget parses "<node>:<interface>". The node ends at the first colon, so
// interfaces such as 1/1/3 or ethernet-1/1 need no quoting.
func parseCaptureTarget(raw string) (capture.Target, error) {
	node, iface, found := strings.Cut(strings.TrimSpace(raw), ":")
	if !found || node == "" || iface == "" {
		return capture.Target{}, fmt.Errorf("%w: %q is not <node>:<interface>", errInvalidCaptureTarget, raw)
	}
	return checkCaptureTarget(node, iface)
}

// checkCaptureTarget checks the form of a node and interface name.
func checkCaptureTarget(node, iface string) (capture.Target, error) {
	node, iface = strings.TrimSpace(node), strings.TrimSpace(iface)
	if !isValidNodeName(node) {
		return capture.Target{}, fmt.Errorf("%w: invalid node name %q", errInvalidCaptureTarget, node)
	}
	if iface == "" || len(iface) > 128 || !interfaceNameRx.MatchString(iface) {
		return capture.Target{}, fmt.Errorf("%w: invalid interface name %q", errInvalidCaptureTarget, iface)
	}
	return capture.Target{Node: node, Interface: iface}, nil
}

// captureLimits are the optional bounds of a capture.
type captureLimits struct {
	duration    time.Duration
	packetLimit int
	snapLength  int
}

func parseCaptureDuration(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	duration, err := time.ParseDuration(raw)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("invalid duration %q: use a positive Go duration such as 30s or 5m", raw)
	}
	return duration, nil
}

func parsePositiveInt(name, raw string, minValue, maxValue int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minValue || value > maxValue {
		return 0, fmt.Errorf("invalid %s %q: use a number from %d to %d", name, raw, minValue, maxValue)
	}
	return value, nil
}

// parseCaptureQuery reads the targets and limits of a stream request.
func parseCaptureQuery(c *gin.Context) ([]capture.Target, captureLimits, error) {
	rawTargets := c.QueryArray("target")
	if len(rawTargets) == 0 {
		return nil, captureLimits{}, fmt.Errorf("%w: at least one target=<node>:<interface> is required", errInvalidCaptureTarget)
	}
	if len(rawTargets) > maxCaptureTargets {
		return nil, captureLimits{}, fmt.Errorf("%w: at most %d targets per capture", errInvalidCaptureTarget, maxCaptureTargets)
	}
	targets := make([]capture.Target, 0, len(rawTargets))
	for _, raw := range rawTargets {
		target, err := parseCaptureTarget(raw)
		if err != nil {
			return nil, captureLimits{}, err
		}
		targets = append(targets, target)
	}

	var limits captureLimits
	var err error
	if limits.duration, err = parseCaptureDuration(c.Query("duration")); err != nil {
		return nil, captureLimits{}, err
	}
	if limits.packetLimit, err = parsePositiveInt("packetLimit", c.Query("packetLimit"), 1, 1<<31-1); err != nil {
		return nil, captureLimits{}, err
	}
	if limits.snapLength, err = parsePositiveInt("snapLength", c.Query("snapLength"), minCaptureSnapLength, maxCaptureSnapLength); err != nil {
		return nil, captureLimits{}, err
	}
	return targets, limits, nil
}

// captureNodeMatches reports whether a requested node name names the node the library lists:
// the topology spelling, or the sanitized name c9s gives the node.
func captureNodeMatches(listed, requested string) bool {
	return listed == requested || clabnames.SanitizeName(listed) == clabnames.SanitizeName(requested)
}

// matchCaptureTargets checks targets against the interfaces the lab can capture and returns
// them as the library names them (node as the topology spells it, interface name instead of
// alias). An interface may be requested once.
func matchCaptureTargets(available []clablabruntime.CaptureInterface, targets []capture.Target) ([]capture.Target, error) {
	resolved := make([]capture.Target, 0, len(targets))
	seen := map[capture.Target]bool{}
	for _, target := range targets {
		var match *clablabruntime.CaptureInterface
		var capturable []string
		for idx := range available {
			entry := &available[idx]
			if !captureNodeMatches(entry.Node, target.Node) {
				continue
			}
			name := entry.Interface
			if entry.Alias != "" {
				name += " (" + entry.Alias + ")"
			}
			capturable = append(capturable, name)
			if match == nil && (entry.Interface == target.Interface || (entry.Alias != "" && entry.Alias == target.Interface)) {
				match = entry
			}
		}
		if match == nil {
			if len(capturable) == 0 {
				return nil, fmt.Errorf("%w: node %q has no capturable lab link interface", errInvalidCaptureTarget, target.Node)
			}
			return nil, fmt.Errorf("%w: interface %q of node %q is not a capturable lab link interface; capturable: %s",
				errInvalidCaptureTarget, target.Interface, target.Node, strings.Join(capturable, ", "))
		}
		normalized := capture.Target{Node: match.Node, Interface: match.Interface}
		if seen[normalized] {
			return nil, fmt.Errorf("%w: interface %q of node %q is requested more than once", errInvalidCaptureTarget, match.Interface, target.Node)
		}
		seen[normalized] = true
		resolved = append(resolved, normalized)
	}
	return resolved, nil
}

// resolveCaptureTargets checks targets against the lab, as the user, before a capture starts.
func resolveCaptureTargets(ctx context.Context, svc *clab.Service, username, labName string, targets []capture.Target) ([]capture.Target, error) {
	nodes := make([]string, 0, len(targets))
	seen := map[string]bool{}
	for _, target := range targets {
		if !seen[target.Node] {
			seen[target.Node] = true
			nodes = append(nodes, target.Node)
		}
	}
	available, err := svc.LabCaptureInterfaces(ctx, username, labName, nodes...)
	if err != nil {
		return nil, classifyLabCaptureError(err)
	}
	return matchCaptureTargets(available, targets)
}

// classifyLabCaptureError marks the library's errors for targets the lab cannot capture. The
// library reports them as text: a node the lab does not have, and a node without a pod.
func classifyLabCaptureError(err error) error {
	message := err.Error()
	switch {
	case strings.Contains(message, "was not found in c9s lab"):
		return fmt.Errorf("%w: %w", errInvalidCaptureTarget, err)
	case strings.Contains(message, "has no pod"):
		return fmt.Errorf("%w: %w", errNodeNotRunning, err)
	}
	return err
}

// isForbidden reports a Kubernetes authorization failure of the user's identity.
func isForbidden(err error) bool {
	if apierrors.IsForbidden(err) {
		return true
	}
	return strings.Contains(err.Error(), " is forbidden: ")
}

// captureErrorStatus maps an error before a capture started to an HTTP status.
func captureErrorStatus(err error) int {
	switch {
	case errors.Is(err, errInvalidCaptureTarget):
		return http.StatusBadRequest
	case errors.Is(err, errNodeNotRunning), errors.Is(err, kube.ErrAmbiguousLab):
		return http.StatusConflict
	case errors.Is(err, clab.ErrLabNotFound):
		return http.StatusNotFound
	case isForbidden(err):
		return http.StatusForbidden
	case isUnsupportedByLabRuntime(err), errors.Is(err, clablabruntime.ErrUnsupportedRuntimeVersion):
		return http.StatusNotImplemented
	}
	return http.StatusInternalServerError
}

func libraryCaptureTargets(targets []capture.Target) []clablabruntime.CaptureTarget {
	out := make([]clablabruntime.CaptureTarget, 0, len(targets))
	for _, target := range targets {
		out = append(out, clablabruntime.CaptureTarget{Node: target.Node, Interface: target.Interface})
	}
	return out
}

func captureInterfaceNames(targets []capture.Target) []string {
	names := make([]string, 0, len(targets))
	for _, target := range targets {
		names = append(names, target.Node+":"+target.Interface)
	}
	return names
}

// ListCaptureInterfacesHandler lists the interfaces a lab runtime captures.
// @Summary List capturable interfaces
// @Description Lists the lab link interfaces of the lab's running nodes that packet capture accepts, with the far end of each link. Lab runtime c9s only; the management interface is not capturable. Runs as the signed-in user.
// @Tags Capture
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab name" example="my-lab"
// @Success 200 {array} models.CaptureInterfaceInfo "Capturable interfaces, ordered by node and interface"
// @Failure 400 {object} models.ErrorResponse "Invalid lab name"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden by Kubernetes RBAC"
// @Failure 404 {object} models.ErrorResponse "Lab not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Failure 501 {object} models.ErrorResponse "The server's runtime is not c9s"
// @Router /api/v1/labs/{labName}/capture/interfaces [get]
func ListCaptureInterfacesHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name format."})
		return
	}
	if _, err := verifyLabOwnership(c, username, labName); err != nil {
		return
	}
	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "containerlab service not initialized"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), captureResolveTimeout)
	defer cancel()
	available, err := svc.LabCaptureInterfaces(ctx, username, labName)
	if err != nil {
		err = classifyLabCaptureError(err)
		c.JSON(captureErrorStatus(err), models.ErrorResponse{Error: fmt.Sprintf("Failed to list the capturable interfaces of lab '%s': %v", labName, err)})
		return
	}
	response := make([]models.CaptureInterfaceInfo, 0, len(available))
	for _, entry := range available {
		response = append(response, models.CaptureInterfaceInfo{
			Node:          entry.Node,
			Interface:     entry.Interface,
			Alias:         entry.Alias,
			PeerNode:      entry.PeerNode,
			PeerInterface: entry.PeerInterface,
		})
	}
	c.JSON(http.StatusOK, response)
}

// captureHTTPWriter sends the capture as the response body: the status and headers go out
// with the first byte, and every write is flushed, so the client gets packets as they come.
type captureHTTPWriter struct {
	writer  gin.ResponseWriter
	headers func(http.Header)
	started bool
}

func (w *captureHTTPWriter) start() {
	if w.started {
		return
	}
	w.started = true
	w.headers(w.writer.Header())
	w.writer.WriteHeader(http.StatusOK)
	w.writer.WriteHeaderNow()
}

func (w *captureHTTPWriter) Write(p []byte) (int, error) {
	w.start()
	n, err := w.writer.Write(p)
	if err != nil {
		return n, err
	}
	w.writer.Flush()
	return n, nil
}

// captureFileName names a downloaded capture: <lab>-<UTC timestamp>.pcapng.
func captureFileName(labName string, now time.Time) string {
	return fmt.Sprintf("%s-%s.pcapng", labName, now.UTC().Format("20060102T150405Z"))
}

// StreamCaptureHandler streams a lab runtime packet capture as pcapng.
// @Summary Stream a packet capture
// @Description Captures lab link interfaces of a lab runtime (c9s) lab, as the signed-in user, and streams one pcapng section as it is produced: chunked, flushed per block. The section has one interface per target, named <node>:<interface>, before any packet; packets are in timestamp order. The stream ends when the duration passed, the packet limit was reached, or the client disconnects, which stops the capture in the lab. Errors before the first byte are JSON; later ones end the stream. Captures longer than clabwire's 1 h limit are chained by containerlab without duplicates.
// @Tags Capture
// @Security BearerAuth
// @Produce application/x-pcapng
// @Produce json
// @Param labName path string true "Lab name" example="my-lab"
// @Param target query []string true "Interface to capture, <node>:<interface> (the interface name or its alias); repeat for several" collectionFormat(multi) example="srl1:e1-1"
// @Param duration query string false "Capture duration (Go duration, e.g. 30s); default: until the client disconnects" example="30s"
// @Param packetLimit query int false "Stop after this many packets across all targets" example=1000
// @Param snapLength query int false "Bytes kept per packet, 64 to 1048576 (default 262144)" example=262144
// @Param download query string false "1: send Content-Disposition: attachment; filename=<lab>-<timestamp>.pcapng" Enums(1)
// @Success 200 {file} file "pcapng stream"
// @Failure 400 {object} models.ErrorResponse "Invalid target, duration or limit"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden by Kubernetes RBAC"
// @Failure 404 {object} models.ErrorResponse "Lab not found"
// @Failure 409 {object} models.ErrorResponse "A target node is not running"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Failure 501 {object} models.ErrorResponse "The server's runtime is not c9s"
// @Router /api/v1/labs/{labName}/capture/stream [get]
func StreamCaptureHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name format."})
		return
	}
	targets, limits, err := parseCaptureQuery(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}
	download := c.Query("download") == "1" || strings.EqualFold(c.Query("download"), "true")

	if _, err := verifyLabOwnership(c, username, labName); err != nil {
		return
	}
	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "containerlab service not initialized"})
		return
	}

	resolveCtx, cancelResolve := context.WithTimeout(c.Request.Context(), captureResolveTimeout)
	targets, err = resolveCaptureTargets(resolveCtx, svc, username, labName, targets)
	cancelResolve()
	if err != nil {
		c.JSON(captureErrorStatus(err), models.ErrorResponse{Error: err.Error()})
		return
	}

	writer := &captureHTTPWriter{writer: c.Writer, headers: func(header http.Header) {
		header.Set("Content-Type", "application/x-pcapng")
		header.Set("Cache-Control", "no-cache, no-store")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Accel-Buffering", "no")
		if download {
			header.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", captureFileName(labName, time.Now())))
		}
	}}
	log.Infof("Capture of lab '%s' by user '%s' started: %s", labName, username, strings.Join(captureInterfaceNames(targets), ", "))
	started := time.Now()
	// The request context ends when the client disconnects, which stops the capture.
	err = svc.CaptureLab(c.Request.Context(), clab.LabCaptureOptions{
		Username:    username,
		LabName:     labName,
		Targets:     libraryCaptureTargets(targets),
		Duration:    limits.duration,
		PacketLimit: limits.packetLimit,
		SnapLength:  limits.snapLength,
	}, writer)
	switch {
	case err != nil && !writer.started:
		err = classifyLabCaptureError(err)
		c.JSON(captureErrorStatus(err), models.ErrorResponse{Error: fmt.Sprintf("Capture of lab '%s' failed: %v", labName, err)})
		return
	case err != nil:
		log.Warnf("Capture of lab '%s' by user '%s' ended with an error after %s: %v", labName, username, time.Since(started).Round(time.Millisecond), err)
	default:
		log.Infof("Capture of lab '%s' by user '%s' ended after %s", labName, username, time.Since(started).Round(time.Millisecond))
	}
	writer.start()
}

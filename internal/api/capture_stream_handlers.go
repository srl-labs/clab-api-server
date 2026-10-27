// internal/api/capture_stream_handlers.go
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	clabnames "github.com/srl-labs/containerlab/names"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/srl-labs/clab-api-server/internal/capture"
	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/kube"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// Lab runtime packet capture (plan 3.3): the containerlab library captures lab link
// interfaces through clabwire and writes one merged pcapng stream. The server delivers it as a
// chunked HTTP response, or over a Packetflix-compatible websocket that a single-use ticket
// opens, for clients that cannot send a bearer token (cshargextcap's packetflix: URL handler
// and the Wireshark VNC container).

const (
	// maxCaptureTargets bounds the interfaces of one capture.
	maxCaptureTargets = 64
	// minCaptureSnapLength and maxCaptureSnapLength are the library's snap length bounds.
	minCaptureSnapLength = 64
	maxCaptureSnapLength = 1 << 20
	// captureResolveTimeout bounds checking the targets before a capture starts.
	captureResolveTimeout = 2 * time.Minute
	// packetflixWriteTimeout bounds one websocket message to a slow client.
	packetflixWriteTimeout = 30 * time.Second
	// packetflixCloseWait is how long the server waits for the client to answer its close.
	packetflixCloseWait = 5 * time.Second
	// packetflixTargetType is the target type the packetflix: URL's container parameter
	// carries; cshargextcap writes it into the capture's section comment.
	packetflixTargetType = "c9s-lab"
	// captureTicketPath is where tickets are redeemed: /api/v1/capture/packetflix/<ticket>.
	captureTicketPath = "/api/v1/capture/packetflix/"
)

// errInvalidCaptureTarget marks a capture target the lab cannot capture (400).
var errInvalidCaptureTarget = errors.New("invalid capture target")

// errNodeNotRunning marks a capture target on a node without a running pod (409).
var errNodeNotRunning = errors.New("node is not running")

var (
	captureTicketsMu sync.Mutex
	captureTickets   = capture.NewTicketStore(capture.DefaultTicketTTL)
)

// captureTicketStore returns the store that mints and redeems capture tickets.
func captureTicketStore() *capture.TicketStore {
	captureTicketsMu.Lock()
	defer captureTicketsMu.Unlock()
	return captureTickets
}

// setCaptureTicketStore replaces the ticket store (tests).
func setCaptureTicketStore(store *capture.TicketStore) {
	captureTicketsMu.Lock()
	defer captureTicketsMu.Unlock()
	captureTickets = store
}

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

// resolveCaptureTargets checks targets against the lab, as the user, before a capture starts
// or a ticket is minted.
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

// CreateCaptureTicketHandler mints a single-use capture ticket.
// @Summary Create a capture ticket
// @Description Mints a single-use ticket for a lab runtime (c9s) capture of the given targets, bound to the signed-in user and the lab. It expires 60 s after creation. Redeeming it at /api/v1/capture/packetflix/{ticket} opens a Packetflix-compatible websocket without a bearer token, for Edgeshark's packetflix: URL handler (cshargextcap) and the Wireshark VNC container. packetflixUri carries the container query parameter cshargextcap requires; the server ignores it.
// @Tags Capture
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param labName path string true "Lab name" example="my-lab"
// @Param ticket_request body models.CaptureTicketRequest true "Targets and optional duration"
// @Success 201 {object} models.CaptureTicketResponse "Ticket"
// @Failure 400 {object} models.ErrorResponse "Invalid target or duration"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden by Kubernetes RBAC"
// @Failure 404 {object} models.ErrorResponse "Lab not found"
// @Failure 409 {object} models.ErrorResponse "A target node is not running"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Failure 501 {object} models.ErrorResponse "The server's runtime is not c9s"
// @Router /api/v1/labs/{labName}/capture/tickets [post]
func CreateCaptureTicketHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name format."})
		return
	}
	var req models.CaptureTicketRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}
	if len(req.Targets) > maxCaptureTargets {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("at most %d targets per capture", maxCaptureTargets)})
		return
	}
	targets := make([]capture.Target, 0, len(req.Targets))
	for _, raw := range req.Targets {
		target, err := checkCaptureTarget(raw.Node, raw.Interface)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
			return
		}
		targets = append(targets, target)
	}
	duration, err := parseCaptureDuration(req.Duration)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
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
	targets, err = resolveCaptureTargets(ctx, svc, username, labName, targets)
	if err != nil {
		c.JSON(captureErrorStatus(err), models.ErrorResponse{Error: err.Error()})
		return
	}

	ticket, err := captureTicketStore().Mint(capture.TicketGrant{
		Username: username, LabName: labName, Targets: targets, Duration: duration,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}
	scheme, host := publicEndpoint(c.Request)
	c.JSON(http.StatusCreated, models.CaptureTicketResponse{
		Ticket:        ticket.ID,
		PacketflixURI: packetflixTicketURI(scheme, host, ticket.ID, labName, targets),
		ExpiresAt:     ticket.ExpiresAt.UTC(),
	})
}

// packetflixTicketURI is the packetflix: URL of a ticket. cshargextcap refuses a URL without
// the container query parameter (a JSON capture target) and fills in the interfaces to
// capture from its network-interfaces when no nif parameter is given; the server ignores both
// and captures what the ticket grants. cshargextcap dials <path>/capture, which the server
// serves as well.
func packetflixTicketURI(scheme, host, ticket, labName string, targets []capture.Target) string {
	container, _ := json.Marshal(map[string]any{
		"name":               labName,
		"type":               packetflixTargetType,
		"network-interfaces": captureInterfaceNames(targets),
	})
	return fmt.Sprintf("packetflix:%s://%s%s%s?container=%s",
		scheme, host, captureTicketPath, url.PathEscape(ticket), url.QueryEscape(string(container)))
}

// validHostRx accepts host[:port], with an IPv6 literal in brackets.
var validHostRx = regexp.MustCompile(`^(\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9.-]+)(:[0-9]{1,5})?$`)

// publicEndpoint returns the websocket scheme (ws or wss) and host[:port] clients reach this
// server at: the request's, or the X-Forwarded-Proto and X-Forwarded-Host of a proxy listed in
// TRUSTED_PROXIES.
func publicEndpoint(r *http.Request) (string, string) {
	secure := r.TLS != nil
	host := r.Host
	if requestFromTrustedProxy(r) {
		if proto := firstHeaderValue(r.Header.Get("X-Forwarded-Proto")); proto != "" {
			secure = strings.EqualFold(proto, "https") || strings.EqualFold(proto, "wss")
		}
		if forwarded := firstHeaderValue(r.Header.Get("X-Forwarded-Host")); validHostRx.MatchString(forwarded) {
			host = forwarded
		}
	}
	if !validHostRx.MatchString(host) {
		host = "localhost:" + config.AppConfig.APIPort
	}
	if secure {
		return "wss", host
	}
	return "ws", host
}

func firstHeaderValue(value string) string {
	first, _, _ := strings.Cut(value, ",")
	return strings.TrimSpace(first)
}

// requestFromTrustedProxy reports a request whose peer is listed in TRUSTED_PROXIES. Without
// an explicit list (empty, or "nil"), forwarded headers are never honoured.
func requestFromTrustedProxy(r *http.Request) bool {
	configured := strings.TrimSpace(config.AppConfig.TrustedProxies)
	if configured == "" || configured == "nil" {
		return false
	}
	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remote = r.RemoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(remote))
	if ip == nil {
		return false
	}
	for _, entry := range strings.Split(configured, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			if network.Contains(ip) {
				return true
			}
			continue
		}
		if trusted := net.ParseIP(entry); trusted != nil && trusted.Equal(ip) {
			return true
		}
	}
	return false
}

var packetflixUpgrader = websocket.Upgrader{
	ReadBufferSize:  4 << 10,
	WriteBufferSize: 64 << 10,
	// The ticket in the path is the credential, not a cookie, so the origin does not matter;
	// cshargextcap sends none.
	CheckOrigin: func(*http.Request) bool { return true },
}

// PacketflixCaptureHandler redeems a capture ticket and streams the capture over a
// Packetflix-compatible websocket.
// @Summary Packetflix capture websocket
// @Description Redeems a single-use capture ticket (no bearer token; the ticket is the credential) and streams the capture as the ticket's user: the pcapng stream in binary websocket messages, starting with the section header, compatible with Edgeshark's Packetflix as cshargextcap consumes it. The capture ends after the ticket's duration, with a normal close frame, or when the client closes or disconnects, which stops the capture in the lab. The query parameters cshargextcap sends (container, nif, ...) are ignored. cshargextcap dials {ticket}/capture, which serves the same websocket. Requires a websocket upgrade; unknown, used and expired tickets get 404 before the upgrade.
// @Tags Capture
// @Param ticket path string true "Capture ticket"
// @Success 101 {string} string "Switching protocols; binary pcapng messages follow"
// @Failure 400 {object} models.ErrorResponse "Not a websocket upgrade"
// @Failure 404 {object} models.ErrorResponse "Ticket unknown, used or expired, or the lab is gone"
// @Router /api/v1/capture/packetflix/{ticket} [get]
func PacketflixCaptureHandler(c *gin.Context) {
	if !websocket.IsWebSocketUpgrade(c.Request) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Packetflix capture needs a websocket upgrade"})
		return
	}
	grant, err := captureTicketStore().Redeem(c.Param("ticket"))
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
		return
	}
	// The lab must still be the ticket user's.
	if _, err := verifyLabOwnership(c, grant.Username, grant.LabName); err != nil {
		return
	}
	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "containerlab service not initialized"})
		return
	}

	conn, err := packetflixUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Warnf("Packetflix capture of lab '%s' for user '%s': websocket upgrade failed: %v", grant.LabName, grant.Username, err)
		return
	}
	log.Infof("Packetflix capture of lab '%s' by user '%s' started: %s", grant.LabName, grant.Username,
		strings.Join(captureInterfaceNames(grant.Targets), ", "))
	started := time.Now()
	err = servePacketflix(c.Request.Context(), conn, func(ctx context.Context, w io.Writer) error {
		return svc.CaptureLab(ctx, clab.LabCaptureOptions{
			Username: grant.Username,
			LabName:  grant.LabName,
			Targets:  libraryCaptureTargets(grant.Targets),
			Duration: grant.Duration,
		}, w)
	})
	if err != nil {
		log.Warnf("Packetflix capture of lab '%s' by user '%s' failed after %s: %v", grant.LabName, grant.Username,
			time.Since(started).Round(time.Millisecond), err)
		return
	}
	log.Infof("Packetflix capture of lab '%s' by user '%s' ended after %s", grant.LabName, grant.Username,
		time.Since(started).Round(time.Millisecond))
}

// PacketflixCshargextcapHandler serves the path cshargextcap dials for a packetflix: URL: it
// strips a trailing /capture from the URL path and csharg appends /capture again.
// @Summary Packetflix capture websocket (cshargextcap path)
// @Description The same websocket as /api/v1/capture/packetflix/{ticket}, at the path cshargextcap dials for a packetflix: URL (the URL path with /capture appended).
// @Tags Capture
// @Param ticket path string true "Capture ticket"
// @Success 101 {string} string "Switching protocols; binary pcapng messages follow"
// @Failure 400 {object} models.ErrorResponse "Not a websocket upgrade"
// @Failure 404 {object} models.ErrorResponse "Ticket unknown, used or expired, or the lab is gone"
// @Router /api/v1/capture/packetflix/{ticket}/capture [get]
func PacketflixCshargextcapHandler(c *gin.Context) {
	PacketflixCaptureHandler(c)
}

// PacketflixDiscoverHandler answers the target discovery cshargextcap runs before every
// packetflix: capture (GET <url path>/discover/mobyshark) with an empty target list: the
// ticket already names the targets. It does not touch the ticket.
// @Summary Packetflix target discovery
// @Description Answers cshargextcap's target discovery with an empty list (Ghostwire's shape); the ticket names the targets. Does not consume the ticket.
// @Tags Capture
// @Produce json
// @Param ticket path string true "Capture ticket"
// @Success 200 {object} map[string][]string "{\"containers\":[]}"
// @Router /api/v1/capture/packetflix/{ticket}/discover/mobyshark [get]
func PacketflixDiscoverHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"containers": []string{}})
}

// packetflixWriter sends each write as one binary websocket message, as Packetflix does with
// its capture process' output.
type packetflixWriter struct {
	conn *websocket.Conn
}

func (w *packetflixWriter) Write(p []byte) (int, error) {
	if err := w.conn.SetWriteDeadline(time.Now().Add(packetflixWriteTimeout)); err != nil {
		return 0, err
	}
	if err := w.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// servePacketflix runs capture with the websocket as its output, like Packetflix:
//   - every write is one binary message; the first ones carry the pcapng section header and
//     the interface descriptions;
//   - a close or disconnect of the client cancels the capture (gorilla answers the close);
//   - when the capture ends, the server sends a close frame, 1000 after a normal end and 1011
//     with the error otherwise, and waits briefly for the client's answer.
//
// It returns the capture's error.
func servePacketflix(ctx context.Context, conn *websocket.Conn, run func(context.Context, io.Writer) error) error {
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	clientGone := make(chan struct{})
	go func() {
		defer close(clientGone)
		defer cancel()
		for {
			// Data from the client is not part of the protocol; read only to see control frames.
			if _, _, err := conn.NextReader(); err != nil {
				return
			}
		}
	}()

	err := run(ctx, &packetflixWriter{conn: conn})

	select {
	case <-clientGone:
		// The client closed or went away; the capture ended because of it.
		return nil
	default:
	}
	code, reason := websocket.CloseNormalClosure, "capture ended"
	if err != nil {
		code, reason = websocket.CloseInternalServerErr, closeReason(err.Error())
	}
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason),
		time.Now().Add(packetflixCloseWait))
	select {
	case <-clientGone:
	case <-time.After(packetflixCloseWait):
	}
	return err
}

// closeReason fits a reason into a close frame (123 bytes).
func closeReason(reason string) string {
	const maxReason = 123
	if len(reason) <= maxReason {
		return reason
	}
	cut := maxReason
	for cut > 0 && (reason[cut]&0xC0) == 0x80 { // keep UTF-8 runes whole
		cut--
	}
	return reason[:cut]
}

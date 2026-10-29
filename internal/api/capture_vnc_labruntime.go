// internal/api/capture_vnc_labruntime.go
package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/capture"
	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// Wireshark VNC under a lab runtime (c9s): the server still runs the Wireshark VNC container
// on its own host, which needs Docker there, but instead of Edgeshark the server captures
// through the lab runtime, as the requesting user, and writes the pcapng stream into a named
// pipe the container's Wireshark reads (wireshark-vnc-docker's CLABWIRE_CAPTURE_PIPE mode).
// The container does not reach the server.

// wiresharkVncProbe reports whether Wireshark VNC sessions can run; tests replace it.
var wiresharkVncProbe = func() bool {
	if !clab.IsLabRuntime() {
		return true
	}
	manager := GetCaptureManager()
	if manager == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return manager.ContainerRuntimeAvailable(ctx)
}

// requireWiresharkVnc guards the Wireshark VNC routes. With Docker and Podman they work as
// before (through Edgeshark); with a lab runtime they need Docker on the server host.
func requireWiresharkVnc() gin.HandlerFunc {
	return func(c *gin.Context) {
		if clab.IsLabRuntime() && !wiresharkVncProbe() {
			c.AbortWithStatusJSON(http.StatusNotImplemented, models.ErrorResponse{
				Error: fmt.Sprintf("Wireshark VNC is not supported by lab runtime %s on this server: it needs Docker on the server host", clab.RuntimeKind()),
			})
			return
		}
		c.Next()
	}
}

// vncCaptureGroup is one Wireshark VNC session: the targets of one node.
type vncCaptureGroup struct {
	containerName string
	targets       []capture.Target
}

// createLabRuntimeWiresharkSessions starts Wireshark VNC sessions on a lab runtime: one per
// node, each fed with one capture of that node's targets as the requesting user.
func createLabRuntimeWiresharkSessions(
	c *gin.Context,
	manager *capture.Manager,
	username, labName string,
	req models.CaptureWiresharkVncRequest,
) {
	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "containerlab service not initialized"})
		return
	}
	if len(req.Targets) > maxCaptureTargets {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("at most %d targets per capture", maxCaptureTargets)})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), captureResolveTimeout)
	defer cancel()
	containers, err := svc.ListContainers(ctx, clab.ListOptions{Username: username, LabName: labName})
	if err != nil {
		c.JSON(serviceErrorStatus(err, http.StatusInternalServerError), models.ErrorResponse{
			Error: fmt.Sprintf("failed to inspect lab '%s' for capture targets: %v", labName, err),
		})
		return
	}
	infos := make([]models.ClabContainerInfo, 0, len(containers))
	for _, container := range containers {
		infos = append(infos, clab.ContainerToClabContainerInfo(container))
	}
	if len(infos) == 0 {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("lab '%s' not found", labName)})
		return
	}

	// Each target names a node by its inspect name (<lab>-<node>); group them per node.
	var groups []*vncCaptureGroup
	groupOfNode := map[string]*vncCaptureGroup{}
	requested := make([]capture.Target, 0, len(req.Targets))
	for _, target := range req.Targets {
		containerName := strings.TrimSpace(target.ContainerName)
		if !isResolvableContainerReference(containerName) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("Invalid container name format: %q", containerName)})
			return
		}
		info, ok := resolveCaptureContainer(c, username, labName, containerName, infos)
		if !ok {
			return
		}
		node := strings.TrimSpace(info.NodeName)
		if node == "" {
			node = strings.TrimPrefix(info.Name, labName+"-")
		}
		checked, err := checkCaptureTarget(node, target.InterfaceName)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
			return
		}
		requested = append(requested, checked)
		if groupOfNode[node] == nil {
			groupOfNode[node] = &vncCaptureGroup{containerName: info.Name}
			groups = append(groups, groupOfNode[node])
		}
	}

	resolved, err := resolveCaptureTargets(ctx, svc, username, labName, requested)
	if err != nil {
		c.JSON(captureErrorStatus(err), models.ErrorResponse{Error: err.Error()})
		return
	}
	for idx, target := range resolved {
		group := groupOfNode[requested[idx].Node]
		group.targets = append(group.targets, target)
	}

	specs := make([]capture.WiresharkPipeSpec, 0, len(groups))
	for _, group := range groups {
		targets := group.targets
		interfaceNames := make([]string, 0, len(targets))
		for _, target := range targets {
			interfaceNames = append(interfaceNames, target.Interface)
		}
		specs = append(specs, capture.WiresharkPipeSpec{
			ContainerName:  group.containerName,
			InterfaceNames: interfaceNames,
			// Runs whenever the session's Wireshark opens its pipe, until the session ends.
			Capture: func(ctx context.Context, w io.Writer) error {
				return captureForWireshark(ctx, svc, username, labName, targets, w)
			},
		})
	}

	startCtx, cancelStart := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancelStart()
	sessions, err := manager.CreatePipeWiresharkSessions(startCtx, capture.CreatePipeWiresharkSessionsOptions{
		Username: username,
		LabName:  labName,
		Theme:    req.Theme,
		Specs:    specs,
	})
	if err != nil {
		mapCaptureOperationError(c, err)
		return
	}
	respondWiresharkSessions(c, sessions)
}

// captureForWireshark writes one capture of a session's targets into its Wireshark's pipe.
func captureForWireshark(
	ctx context.Context,
	svc *clab.Service,
	username, labName string,
	targets []capture.Target,
	w io.Writer,
) error {
	log.Infof("Wireshark VNC capture of lab '%s' by user '%s' started: %s", labName, username,
		strings.Join(captureInterfaceNames(targets), ", "))
	started := time.Now()
	err := svc.CaptureLab(ctx, clab.LabCaptureOptions{
		Username: username,
		LabName:  labName,
		Targets:  libraryCaptureTargets(targets),
	}, w)
	log.Infof("Wireshark VNC capture of lab '%s' by user '%s' ended after %s", labName, username,
		time.Since(started).Round(time.Millisecond))
	if err != nil {
		return classifyLabCaptureError(err)
	}
	return nil
}

// respondWiresharkSessions answers a Wireshark VNC session request.
func respondWiresharkSessions(c *gin.Context, sessions []capture.WiresharkSessionInfo) {
	response := models.CaptureWiresharkVncCreateResponse{
		Sessions: make([]models.CaptureWiresharkVncSession, 0, len(sessions)),
	}
	for _, session := range sessions {
		response.Sessions = append(response.Sessions, models.CaptureWiresharkVncSession{
			SessionID:      session.SessionID,
			LabName:        session.LabName,
			ContainerName:  session.ContainerName,
			InterfaceNames: session.InterfaceNames,
			VncPath:        session.VncPath,
			ShowVolumeTip:  session.ShowVolumeTip,
			CreatedAt:      session.CreatedAt,
			ExpiresAt:      session.ExpiresAt,
		})
	}
	c.JSON(http.StatusOK, response)
}

// internal/api/capture_vnc_labruntime.go
package api

import (
	"context"
	"errors"
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

// Wireshark VNC without Edgeshark: the server runs the Wireshark VNC container on its own host
// (on a lab runtime that needs Docker there), captures with the containerlab library and writes
// the pcapng stream into a named pipe the container's Wireshark reads (wireshark-vnc-docker's
// CLABWIRE_CAPTURE_PIPE mode). The container does not reach the server. With Docker and Podman,
// Edgeshark remains for what capture streams do not cover: the management interface, and labs
// whose topology file is gone.

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

// requireWiresharkVnc guards the Wireshark VNC routes: with a lab runtime they need Docker on
// the server host.
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
	labDirectory  string
	targets       []capture.Target
}

// createPipeWiresharkSessions starts Wireshark VNC sessions fed by a capture stream: one per
// node, each with one capture of that node's targets. It reports whether it handled the
// request. With Docker and Podman it leaves targets a stream cannot capture to the caller, which
// tries Edgeshark; on a lab runtime it refuses them.
func createPipeWiresharkSessions(
	c *gin.Context,
	manager *capture.Manager,
	username, labName string,
	req models.CaptureWiresharkVncRequest,
) bool {
	specs, ok, err := wiresharkPipeSpecs(c, username, labName, req)
	if !ok {
		return true
	}
	if err != nil {
		if !clab.IsLabRuntime() && captureNeedsEdgeshark(err) {
			log.Infof("Wireshark VNC capture of lab '%s' falls back to Edgeshark: %v", labName, err)
			return false
		}
		c.JSON(captureErrorStatus(err), models.ErrorResponse{Error: err.Error()})
		return true
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
		return true
	}
	respondWiresharkSessions(c, sessions)
	return true
}

// captureNeedsEdgeshark reports errors of targets that only Edgeshark can capture.
func captureNeedsEdgeshark(err error) bool {
	return errors.Is(err, errInvalidCaptureTarget) || errors.Is(err, errCaptureTopologyMissing)
}

// wiresharkPipeSpecs resolves a Wireshark VNC request to one session per node. It answers the
// request itself and returns ok false for what no capture method can serve; err is why capture
// streams cannot capture the targets.
func wiresharkPipeSpecs(
	c *gin.Context,
	username, labName string,
	req models.CaptureWiresharkVncRequest,
) (specs []capture.WiresharkPipeSpec, ok bool, err error) {
	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "containerlab service not initialized"})
		return nil, false, nil
	}
	if len(req.Targets) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "At least one capture target is required"})
		return nil, false, nil
	}
	if len(req.Targets) > maxCaptureTargets {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("at most %d targets per capture", maxCaptureTargets)})
		return nil, false, nil
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), captureResolveTimeout)
	defer cancel()
	containers, err := svc.ListContainers(ctx, clab.ListOptions{Username: username, LabName: labName})
	if err != nil {
		c.JSON(serviceErrorStatus(err, http.StatusInternalServerError), models.ErrorResponse{
			Error: fmt.Sprintf("failed to inspect lab '%s' for capture targets: %v", labName, err),
		})
		return nil, false, nil
	}
	infos := make([]models.ClabContainerInfo, 0, len(containers))
	for _, container := range containers {
		infos = append(infos, clab.ContainerToClabContainerInfo(container))
	}
	if len(infos) == 0 {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("lab '%s' not found", labName)})
		return nil, false, nil
	}

	// Each target names a node by its inspect name (<lab>-<node>); group them per node.
	var groups []*vncCaptureGroup
	groupOfNode := map[string]*vncCaptureGroup{}
	requested := make([]capture.Target, 0, len(req.Targets))
	for _, target := range req.Targets {
		containerName := strings.TrimSpace(target.ContainerName)
		if !isResolvableContainerReference(containerName) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("Invalid container name format: %q", containerName)})
			return nil, false, nil
		}
		info, found := resolveCaptureContainer(c, username, labName, containerName, infos)
		if !found {
			return nil, false, nil
		}
		node := strings.TrimSpace(info.NodeName)
		if node == "" {
			node = strings.TrimPrefix(info.Name, labName+"-")
		}
		checked, err := checkCaptureTarget(node, target.InterfaceName)
		if err != nil {
			return nil, true, err
		}
		requested = append(requested, checked)
		if groupOfNode[node] == nil {
			groupOfNode[node] = &vncCaptureGroup{containerName: info.Name}
			// The lab directory holds what a Docker or Podman lab's Wireshark saves.
			if !clab.IsLabRuntime() {
				groupOfNode[node].labDirectory = resolveLabDirectory(info)
			}
			groups = append(groups, groupOfNode[node])
		}
	}

	resolved, err := resolveCaptureTargets(ctx, svc, username, labName, requested)
	if err != nil {
		return nil, true, err
	}
	for idx, target := range resolved {
		group := groupOfNode[requested[idx].Node]
		group.targets = append(group.targets, target)
	}

	specs = make([]capture.WiresharkPipeSpec, 0, len(groups))
	for _, group := range groups {
		targets := group.targets
		interfaceNames := make([]string, 0, len(targets))
		for _, target := range targets {
			interfaceNames = append(interfaceNames, target.Interface)
		}
		specs = append(specs, capture.WiresharkPipeSpec{
			ContainerName:  group.containerName,
			InterfaceNames: interfaceNames,
			LabDirectory:   group.labDirectory,
			// Runs whenever the session's Wireshark opens its pipe, until the session ends.
			Capture: func(ctx context.Context, w io.Writer) error {
				return captureForWireshark(ctx, svc, username, labName, targets, w)
			},
		})
	}
	return specs, true, nil
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

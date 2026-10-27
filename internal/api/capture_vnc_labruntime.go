// internal/api/capture_vnc_labruntime.go
package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/capture"
	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// Wireshark VNC under a lab runtime (c9s): the server still runs the Wireshark VNC container
// on its own host, which needs Docker there, but the container's Wireshark captures from a
// ticket URL of this server (PACKETFLIX_LINK) instead of Edgeshark. The container reaches the
// server through the Docker host gateway.

// vncServerCertPath is where the server's TLS certificate is mounted in the Wireshark
// container, which trusts it through SSL_CERT_FILE (cshargextcap is a Go program).
const vncServerCertPath = "/etc/clab-api-server/server.crt"

var (
	serverCertMu   sync.RWMutex
	serverCertFile string
)

// SetServerCertificateFile records the TLS certificate the server serves, so the Wireshark
// VNC container can trust it.
func SetServerCertificateFile(path string) {
	serverCertMu.Lock()
	defer serverCertMu.Unlock()
	serverCertFile = path
}

func serverCertificateFile() string {
	serverCertMu.RLock()
	defer serverCertMu.RUnlock()
	return serverCertFile
}

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

// vncServerEndpoint is how the Wireshark VNC container reaches this server.
type vncServerEndpoint struct {
	scheme  string // ws or wss
	host    string // host:port
	runArgs []string
}

// wiresharkServerEndpoint returns how the Wireshark container reaches this server: through
// the Docker host gateway, as host.docker.internal without TLS. With TLS, cshargextcap
// verifies the server's certificate, so the container uses a name the certificate holds (the
// first DNS name other than localhost, mapped to the host gateway, or else its first
// non-loopback IP address) and trusts the certificate itself.
func wiresharkServerEndpoint() (vncServerEndpoint, error) {
	port := strings.TrimSpace(config.AppConfig.APIPort)
	if !config.AppConfig.TLSEnable {
		// The manager maps host.docker.internal to the host gateway.
		return vncServerEndpoint{scheme: "ws", host: net.JoinHostPort("host.docker.internal", port)}, nil
	}
	certFile := serverCertificateFile()
	if certFile == "" {
		certFile = config.AppConfig.TLSCertFile
	}
	if certFile == "" {
		return vncServerEndpoint{}, errors.New("the server's TLS certificate file is unknown")
	}
	name, isIP, err := certificateHostForContainers(certFile)
	if err != nil {
		return vncServerEndpoint{}, err
	}
	runArgs := []string{
		"-v", certFile + ":" + vncServerCertPath + ":ro",
		"-e", "SSL_CERT_FILE=" + vncServerCertPath,
	}
	if !isIP {
		runArgs = append(runArgs, "--add-host", name+":host-gateway")
	}
	return vncServerEndpoint{scheme: "wss", host: net.JoinHostPort(name, port), runArgs: runArgs}, nil
}

// certificateHostForContainers picks the name a container uses to reach the server so that
// the certificate verifies: the first DNS name other than localhost and wildcards, or the first
// IP address that is not a loopback address.
func certificateHostForContainers(certFile string) (string, bool, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return "", false, fmt.Errorf("reading the server's TLS certificate: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", false, fmt.Errorf("the server's TLS certificate %s holds no PEM certificate", certFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", false, fmt.Errorf("parsing the server's TLS certificate: %w", err)
	}
	for _, name := range cert.DNSNames {
		if name != "" && !strings.EqualFold(name, "localhost") && !strings.HasPrefix(name, "*") {
			return name, false, nil
		}
	}
	for _, ip := range cert.IPAddresses {
		if !ip.IsLoopback() && !ip.IsUnspecified() {
			return ip.String(), true, nil
		}
	}
	return "", false, fmt.Errorf("the server's TLS certificate %s names no host a Wireshark container can reach (only localhost or loopback addresses)", certFile)
}

// vncCaptureGroup is one Wireshark VNC session: the targets of one node.
type vncCaptureGroup struct {
	containerName string
	targets       []capture.Target
}

// createLabRuntimeWiresharkSessions starts Wireshark VNC sessions on a lab runtime: one per
// node, each capturing that node's targets through a capture ticket of the requesting user.
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

	endpoint, err := wiresharkServerEndpoint()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Wireshark VNC cannot reach this server: " + err.Error()})
		return
	}

	specs := make([]capture.WiresharkLinkSpec, 0, len(groups))
	for _, group := range groups {
		targets := group.targets
		interfaceNames := make([]string, 0, len(targets))
		for _, target := range targets {
			interfaceNames = append(interfaceNames, target.Interface)
		}
		specs = append(specs, capture.WiresharkLinkSpec{
			ContainerName:  group.containerName,
			InterfaceNames: interfaceNames,
			RunArgs:        endpoint.runArgs,
			PacketflixLink: func() (string, error) {
				ticket, err := captureTicketStore().Mint(capture.TicketGrant{
					Username: username, LabName: labName, Targets: targets,
				})
				if err != nil {
					return "", err
				}
				return packetflixTicketURI(endpoint.scheme, endpoint.host, ticket.ID, labName, targets), nil
			},
		})
	}

	startCtx, cancelStart := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancelStart()
	sessions, err := manager.CreateLinkedWiresharkSessions(startCtx, capture.CreateLinkedWiresharkSessionsOptions{
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

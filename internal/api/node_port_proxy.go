// internal/api/node_port_proxy.go
package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// nodePortProxyPath is the route below a node that proxies HTTP to one of its ports.
const nodePortProxyPath = "/ports/%d/proxy/"

// labRuntimeBrowserPorts lists the TCP ports a lab runtime node exposes, each with the
// server path that proxies to it.
func labRuntimeBrowserPorts(labName, nodeName string, info *models.ClabContainerInfo) []models.NodeBrowserPort {
	ports := make([]models.NodeBrowserPort, 0, len(info.ExposedPorts))
	seen := map[int]bool{}
	for _, port := range info.ExposedPorts {
		if port.Port <= 0 || seen[port.Port] {
			continue
		}
		if port.Protocol != "" && !strings.EqualFold(port.Protocol, "tcp") {
			continue
		}
		seen[port.Port] = true
		ports = append(ports, models.NodeBrowserPort{
			HostIP:        info.LoadBalancerAddress,
			ContainerPort: port.Port,
			Protocol:      "tcp",
			Description:   describePort(port.Port),
			ProxyPath: fmt.Sprintf("/api/v1/labs/%s/nodes/%s"+nodePortProxyPath,
				url.PathEscape(labName), url.PathEscape(nodeName), port.Port),
		})
	}
	return ports
}

// @Summary Proxy HTTP to a node port
// @Description Proxies an HTTP request (including WebSocket upgrades) to a TCP port of a lab node, through a Kubernetes port-forward opened as the caller.
// @Description
// @Description **Notes**
// @Description - Only available with a lab runtime (`runtime` `c9s` on `/health`); other runtimes answer 501 and publish host ports instead.
// @Description - `browser-ports` lists the ports with their `proxyPath`.
// @Description - The request is sent to the node without the `Authorization` header.
// @Tags Labs - Nodes
// @Security BearerAuth
// @Param labName path string true "Lab name"
// @Param nodeName path string true "Node name"
// @Param port path int true "Node TCP port"
// @Param proxyPath path string true "Path on the node"
// @Success 200 {string} string "Response of the node"
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 501 {object} models.ErrorResponse "Not supported by the runtime"
// @Failure 502 {object} models.ErrorResponse "Node port not reachable"
// @Router /api/v1/labs/{labName}/nodes/{nodeName}/ports/{port}/proxy/{proxyPath} [get]
func ProxyNodePortHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := strings.TrimSpace(c.Param("labName"))
	nodeName := strings.TrimSpace(c.Param("nodeName"))

	if !clab.IsLabRuntime() {
		c.JSON(http.StatusNotImplemented, models.ErrorResponse{
			Error: fmt.Sprintf("proxying node ports is not supported by runtime %s; use the published host ports", clab.RuntimeKind()),
		})
		return
	}
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name format."})
		return
	}
	if !isValidNodeName(nodeName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid node name format."})
		return
	}
	port, err := strconv.Atoi(c.Param("port"))
	if err != nil || port <= 0 || port > 65535 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid port."})
		return
	}

	if _, err := verifyLabOwnership(c, username, labName); err != nil {
		return
	}
	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	lookupCtx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
	container, err := resolveLabNodeContainer(lookupCtx, svc, username, labName, nodeName)
	cancel()
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
		return
	}
	node := resolveTopologyNodeName(labName, container)

	proxy := newNodePortProxy(func(ctx context.Context) (net.Conn, error) {
		return svc.DialNodePort(ctx, username, labName, node, port)
	}, node, port, c.Param("proxyPath"))
	proxy.ServeHTTP(c.Writer, c.Request)
}

// newNodePortProxy returns a reverse proxy that sends every request to path on a node port
// over connections from dial.
func newNodePortProxy(dial func(ctx context.Context) (net.Conn, error), node string, port int, path string) *httputil.ReverseProxy {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	host := net.JoinHostPort(node, strconv.Itoa(port))
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dial(ctx)
		},
		// Each request opens its own port-forward; keeping them idle holds cluster streams.
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 2 * time.Minute,
	}
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = "http"
			r.Out.URL.Host = host
			r.Out.URL.Path = path
			r.Out.URL.RawPath = ""
			r.Out.Host = host
			// The API token is the caller's credential for this server, not for the node.
			r.Out.Header.Del("Authorization")
			r.Out.Header.Del("Cookie")
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Warnf("node port proxy to %s failed: %v", host, err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprintf(w, `{"error":%q}`, fmt.Sprintf("node port %d of %s is not reachable: %v", port, node, err))
		},
	}
}

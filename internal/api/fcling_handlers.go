package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/fcling"
	"github.com/srl-labs/clab-api-server/internal/models"
)

const (
	fclingReportTimeout = 10 * time.Minute
	// An engine's first start can pull its image.
	fclingStartTimeout  = 10 * time.Minute
	fclingStatusTimeout = time.Minute
)

// topologyPathForFcling says whether a lab's topology can be mounted into an fcling container.
func topologyPathForFcling(c *gin.Context, topoPath string) bool {
	if topoPath == "" || strings.HasPrefix(strings.ToLower(topoPath), "http") {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Lab topology path is unavailable for fcling."})
		return false
	}
	return true
}

// @Summary Run fcling report
// @Description Runs an fcling report once against the selected lab topology and returns its output.
// @Tags Labs - Tools
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param labName path string true "Lab Name"
// @Param fcling_request body models.FclingCommandRequest true "fcling command request"
// @Success 200 {object} models.FclingCommandResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Failure 501 {object} models.ErrorResponse "Not supported by the configured lab runtime"
// @Router /api/v1/labs/{labName}/fcling [post]
func RunLabFclingHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := strings.TrimSpace(c.Param("labName"))

	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name format."})
		return
	}

	topoPath, err := verifyLabOwnership(c, username, labName)
	if err != nil {
		return
	}
	if !topologyPathForFcling(c, topoPath) {
		return
	}

	var req models.FclingCommandRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	command := strings.TrimSpace(req.Command)
	commandArgs := strings.Fields(command)
	if len(commandArgs) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "fcling command is required."})
		return
	}

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), fclingReportTimeout)
	defer cancel()

	output, runErr := svc.RunFclingCommand(ctx, clab.FclingRunOptions{
		Runtime:      config.AppConfig.ClabRuntime,
		LabName:      labName,
		TopologyPath: topoPath,
		CommandArgs:  commandArgs,
	})
	if runErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: runErr.Error()})
		return
	}

	c.JSON(http.StatusOK, models.FclingCommandResponse{
		Command: command,
		Output:  output,
	})
}

// RunLabFcliHandler keeps released clients working: fcling replaced fcli, with the same reports.
//
// @Summary Run fcling report (old path)
// @Description Deprecated: use POST /api/v1/labs/{labName}/fcling. Runs the same fcling report.
// @Tags Labs - Tools
// @Security BearerAuth
// @Accept json
// @Produce json
// @Deprecated
// @Param labName path string true "Lab Name"
// @Param fcli_request body models.FclingCommandRequest true "fcling command request"
// @Success 200 {object} models.FclingCommandResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Failure 501 {object} models.ErrorResponse "Not supported by the configured lab runtime"
// @Router /api/v1/labs/{labName}/fcli [post]
func RunLabFcliHandler(c *gin.Context) {
	RunLabFclingHandler(c)
}

// fclingEngineRequest validates what every engine route needs. It answers the request itself
// when it returns false.
func fclingEngineRequest(c *gin.Context) (manager *fcling.Manager, labName, topoPath string, ok bool) {
	username := c.GetString("username")
	labName = strings.TrimSpace(c.Param("labName"))
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name format."})
		return nil, "", "", false
	}
	manager = GetFclingManager()
	if manager == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "fcling manager not initialized"})
		return nil, "", "", false
	}
	topoPath, err := verifyLabOwnership(c, username, labName)
	if err != nil {
		return nil, "", "", false
	}
	return manager, labName, topoPath, true
}

func fclingEngineStatusResponse(status fcling.Status) models.FclingEngineStatus {
	return models.FclingEngineStatus{
		State:         status.State,
		Image:         status.Image,
		ContainerName: status.ContainerName,
		StartedAt:     status.StartedAt,
		GnmiPort:      status.GnmiPort,
		Error:         status.Error,
	}
}

// @Summary Get fcling engine status
// @Description Tells how the lab's fcling engine is doing: `stopped` without one, `starting` until it answers, `ready` then, `failed` once its container has exited, with the end of its log.
// @Tags Labs - Tools
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab Name"
// @Success 200 {object} models.FclingEngineStatus
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Failure 501 {object} models.ErrorResponse "Not supported by the configured lab runtime"
// @Router /api/v1/labs/{labName}/fcling/engine [get]
func GetFclingEngineHandler(c *gin.Context) {
	manager, labName, _, ok := fclingEngineRequest(c)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), fclingStatusTimeout)
	defer cancel()
	status, err := manager.Status(ctx, labName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, fclingEngineStatusResponse(status))
}

// @Summary Start fcling engine
// @Description Starts the lab's fcling engine, which streams its SR Linux nodes and keeps a history of what changes. An engine that runs is left alone, unless the request gives it another gNMI port: then it is replaced, and keeps its history. A port given is also used for the lab's reports and kept for the next start. The first start can take a while, since it pulls the image; poll the status until it says `ready`.
// @Tags Labs - Tools
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param labName path string true "Lab Name"
// @Param fcling_engine_request body models.FclingEngineStartRequest false "How to start the engine"
// @Success 200 {object} models.FclingEngineStatus
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Failure 501 {object} models.ErrorResponse "Not supported by the configured lab runtime"
// @Router /api/v1/labs/{labName}/fcling/engine [post]
func StartFclingEngineHandler(c *gin.Context) {
	manager, labName, topoPath, ok := fclingEngineRequest(c)
	if !ok || !topologyPathForFcling(c, topoPath) {
		return
	}
	var req models.FclingEngineStartRequest
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}
	if req.GnmiPort != 0 && !fcling.ValidGnmiPort(req.GnmiPort) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "The gNMI port must be between 1 and 65535."})
		return
	}
	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	// A client that leaves during the image pull finds the engine when it returns.
	ctx, cancel := context.WithTimeout(context.Background(), fclingStartTimeout)
	defer cancel()
	status, err := manager.Start(ctx, fcling.StartOptions{
		LabName:      labName,
		TopologyPath: topoPath,
		GnmiPort:     req.GnmiPort,
		NetworkArgs: func(ctx context.Context) ([]string, error) {
			return svc.FclingNetworkArgs(ctx, topoPath)
		},
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, fclingEngineStatusResponse(status))
}

// @Summary Stop fcling engine
// @Description Stops the lab's fcling engine. Its history is kept for the next start, and goes when the lab is destroyed.
// @Tags Labs - Tools
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab Name"
// @Success 200 {object} models.FclingEngineStatus
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Failure 501 {object} models.ErrorResponse "Not supported by the configured lab runtime"
// @Router /api/v1/labs/{labName}/fcling/engine [delete]
func StopFclingEngineHandler(c *gin.Context) {
	manager, labName, _, ok := fclingEngineRequest(c)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), fclingStatusTimeout)
	defer cancel()
	if err := manager.Stop(ctx, labName); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.FclingEngineStatus{State: fcling.StateStopped})
}

// ProxyFclingAPIHandler proxies fcling's fabric API, events included, to the lab's engine.
//
// @Summary Proxy fcling engine API
// @Description Passes a request to the HTTP API of the lab's running fcling engine, with the engine's own token, and streams its answer. Only these reach it. GET: status, reports, reports/{name}, checks, incidents, acks, history, drift, configs, configs/diff, baselines, lenses, lenses/{name}, topology, events. POST: acks, baselines. DELETE: acks, baselines/{name}. Anything else is refused with 403. A lab without a running engine answers 409.
// @Tags Labs - Tools
// @Security BearerAuth
// @Accept json
// @Produce json
// @Produce text/event-stream
// @Param labName path string true "Lab Name"
// @Param proxyPath path string true "Path below the engine's /api, e.g. reports/bgp-peers"
// @Success 200 {object} object "The engine's answer"
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 403 {object} models.ErrorResponse "Not part of the fabric API"
// @Failure 404 {object} models.ErrorResponse
// @Failure 409 {object} models.ErrorResponse "The engine is not running"
// @Failure 501 {object} models.ErrorResponse "Not supported by the configured lab runtime"
// @Failure 502 {object} models.ErrorResponse "The engine is not reachable"
// @Router /api/v1/labs/{labName}/fcling/api/{proxyPath} [get]
// @Router /api/v1/labs/{labName}/fcling/api/{proxyPath} [post]
// @Router /api/v1/labs/{labName}/fcling/api/{proxyPath} [delete]
func ProxyFclingAPIHandler(c *gin.Context) {
	proxyPath := c.Param("proxyPath")
	if !fcling.AllowedAPI(c.Request.Method, proxyPath) {
		c.JSON(http.StatusForbidden, models.ErrorResponse{Error: "This fcling API path is not available through the server."})
		return
	}
	manager, labName, _, ok := fclingEngineRequest(c)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), fclingStatusTimeout)
	defer cancel()
	target, err := manager.Target(ctx, labName)
	if errors.Is(err, fcling.ErrEngineNotRunning) {
		c.JSON(http.StatusConflict, models.ErrorResponse{Error: "The fcling engine of lab '" + labName + "' is not running. Start it first."})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	fcling.NewProxy(target, proxyPath).ServeHTTP(c.Writer, c.Request)
}

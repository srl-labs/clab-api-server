package api

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	"gopkg.in/yaml.v3"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

const (
	defaultGottyPort = 8080
	defaultMgmtNet   = "clab"
)

var httpLinkRegexp = regexp.MustCompile(`https?://[^\s"'<>]+`)

type topologyMgmtConfig struct {
	Mgmt struct {
		Network string `yaml:"network"`
	} `yaml:"mgmt"`
}

// @Summary Start node
// @Description Starts a stopped node in a lab.
// @Tags Labs - Nodes
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab Name"
// @Param nodeName path string true "Node Name"
// @Success 200 {object} models.GenericSuccessResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/labs/{labName}/nodes/{nodeName}/start [post]
func StartNodeHandler(c *gin.Context) {
	handleNodeLifecycle(c, clab.NodeLifecycleActionStart)
}

// @Summary Stop node
// @Description Stops a running node in a lab.
// @Tags Labs - Nodes
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab Name"
// @Param nodeName path string true "Node Name"
// @Success 200 {object} models.GenericSuccessResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/labs/{labName}/nodes/{nodeName}/stop [post]
func StopNodeHandler(c *gin.Context) {
	handleNodeLifecycle(c, clab.NodeLifecycleActionStop)
}

// @Summary Restart node
// @Description Restarts a node in a lab while preserving containerlab dataplane links.
// @Tags Labs - Nodes
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab Name"
// @Param nodeName path string true "Node Name"
// @Success 200 {object} models.GenericSuccessResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/labs/{labName}/nodes/{nodeName}/restart [post]
func RestartNodeHandler(c *gin.Context) {
	handleNodeLifecycle(c, clab.NodeLifecycleActionRestart)
}

// @Summary Pause node
// @Description Pauses a running node in a lab.
// @Tags Labs - Nodes
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab Name"
// @Param nodeName path string true "Node Name"
// @Success 200 {object} models.GenericSuccessResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/labs/{labName}/nodes/{nodeName}/pause [post]
func PauseNodeHandler(c *gin.Context) {
	handleNodeLifecycle(c, clab.NodeLifecycleActionPause)
}

// @Summary Unpause node
// @Description Unpauses a paused node in a lab.
// @Tags Labs - Nodes
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab Name"
// @Param nodeName path string true "Node Name"
// @Success 200 {object} models.GenericSuccessResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/labs/{labName}/nodes/{nodeName}/unpause [post]
func UnpauseNodeHandler(c *gin.Context) {
	handleNodeLifecycle(c, clab.NodeLifecycleActionUnpause)
}

func handleNodeLifecycle(c *gin.Context, action clab.NodeLifecycleAction) {
	username := c.GetString("username")
	labName := strings.TrimSpace(c.Param("labName"))
	nodeName := strings.TrimSpace(c.Param("nodeName"))

	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name format."})
		return
	}
	if nodeName == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Node name is required."})
		return
	}

	releaseLabOperation, ok := beginLabOperationOrConflict(c, labName, string(action))
	if !ok {
		return
	}
	defer releaseLabOperation()

	originalTopoPath, err := verifyLabOwnership(c, username, labName)
	if err != nil {
		return
	}

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	containerInfo, err := resolveLabNodeContainer(ctx, svc, labName, nodeName)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
		return
	}

	containerName := clab.GetContainerName(containerInfo)
	if containerName == "" {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "failed to resolve container name"})
		return
	}

	if err := svc.RunNodeLifecycleAction(ctx, clab.NodeLifecycleOptions{
		ContainerName: containerName,
		LabName:       labName,
		TopoPath:      originalTopoPath,
		Username:      username,
		NodeNames:     []string{resolveTopologyNodeName(labName, containerInfo)},
		Action:        action,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.GenericSuccessResponse{
		Message: fmt.Sprintf("Node '%s' %s successfully.", nodeName, lifecyclePastTense(action)),
	})
}

// @Summary Start lab nodes
// @Description Starts all nodes in a deployed lab while preserving containerlab dataplane links.
// @Description
// @Description **Notes**
// @Description - `stream=true` returns `application/x-ndjson` lifecycle events.
// @Description - `includeLogs=true` includes captured lifecycle logs in the JSON response.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab Name"
// @Param stream query boolean false "Stream lifecycle output as NDJSON events"
// @Param includeLogs query boolean false "Include captured lifecycle logs in the JSON response"
// @Success 200 {object} models.GenericSuccessResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/labs/{labName}/start [post]
func StartLabNodesHandler(c *gin.Context) {
	handleLabNodeLifecycle(c, clab.NodeLifecycleActionStart)
}

// @Summary Stop lab nodes
// @Description Stops all nodes in a deployed lab while preserving containerlab dataplane links.
// @Description
// @Description **Notes**
// @Description - `stream=true` returns `application/x-ndjson` lifecycle events.
// @Description - `includeLogs=true` includes captured lifecycle logs in the JSON response.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab Name"
// @Param stream query boolean false "Stream lifecycle output as NDJSON events"
// @Param includeLogs query boolean false "Include captured lifecycle logs in the JSON response"
// @Success 200 {object} models.GenericSuccessResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/labs/{labName}/stop [post]
func StopLabNodesHandler(c *gin.Context) {
	handleLabNodeLifecycle(c, clab.NodeLifecycleActionStop)
}

// @Summary Restart lab nodes
// @Description Restarts all nodes in a deployed lab while preserving containerlab dataplane links.
// @Description
// @Description **Notes**
// @Description - `stream=true` returns `application/x-ndjson` lifecycle events.
// @Description - `includeLogs=true` includes captured lifecycle logs in the JSON response.
// @Tags Labs
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab Name"
// @Param stream query boolean false "Stream lifecycle output as NDJSON events"
// @Param includeLogs query boolean false "Include captured lifecycle logs in the JSON response"
// @Success 200 {object} models.GenericSuccessResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/labs/{labName}/restart [post]
func RestartLabNodesHandler(c *gin.Context) {
	handleLabNodeLifecycle(c, clab.NodeLifecycleActionRestart)
}

func handleLabNodeLifecycle(c *gin.Context, action clab.NodeLifecycleAction) {
	username := c.GetString("username")
	labName := strings.TrimSpace(c.Param("labName"))
	streamLogs := c.Query("stream") == "true"
	includeLogs := c.Query("includeLogs") == "true"

	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name format."})
		return
	}

	releaseLabOperation, ok := beginLabOperationOrConflict(c, labName, string(action))
	if !ok {
		return
	}
	defer releaseLabOperation()

	originalTopoPath, err := verifyLabOwnership(c, username, labName)
	if err != nil {
		return
	}

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Minute)
	defer cancel()

	opts := clab.NodeLifecycleOptions{
		LabName:  labName,
		TopoPath: originalTopoPath,
		Username: username,
		Action:   action,
	}

	runLifecycle := func() error {
		if err := svc.RunLabLifecycleAction(ctx, opts); err != nil {
			return fmt.Errorf("failed to %s lab '%s': %w", action, labName, err)
		}
		return nil
	}

	successMessage := fmt.Sprintf("Lab '%s' nodes %s successfully.", labName, lifecyclePastTense(action))
	if streamLogs {
		streamLifecycleCommand(c, runLifecycle, successMessage)
		return
	}

	if includeLogs {
		logs, lifecycleErr := captureLifecycleLogs(runLifecycle)
		if lifecycleErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": lifecycleErr.Error(),
				"logs":  logs,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"message": successMessage,
			"logs":    logs,
		})
		return
	}

	if err := runLifecycle(); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.GenericSuccessResponse{Message: successMessage})
}

// @Summary Get node browser ports
// @Description Returns exposed host ports for a node suitable for opening in a browser.
// @Tags Labs - Nodes
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab Name"
// @Param nodeName path string true "Node Name"
// @Success 200 {object} models.NodeBrowserPortsResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/labs/{labName}/nodes/{nodeName}/browser-ports [get]
func GetNodeBrowserPortsHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := strings.TrimSpace(c.Param("labName"))
	nodeName := strings.TrimSpace(c.Param("nodeName"))

	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name format."})
		return
	}
	if nodeName == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Node name is required."})
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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	containerInfo, err := resolveLabNodeContainer(ctx, svc, labName, nodeName)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
		return
	}

	ports := make([]models.NodeBrowserPort, 0)
	seen := map[string]struct{}{}
	for _, port := range containerInfo.Ports {
		if port.HostPort <= 0 {
			continue
		}
		identity := fmt.Sprintf("%s:%d/%s->%d", port.HostIP, port.HostPort, port.Protocol, port.ContainerPort)
		if _, ok := seen[identity]; ok {
			continue
		}
		seen[identity] = struct{}{}
		ports = append(ports, models.NodeBrowserPort{
			HostIP:        port.HostIP,
			HostPort:      port.HostPort,
			ContainerPort: port.ContainerPort,
			Protocol:      port.Protocol,
			Description:   describePort(port.ContainerPort),
		})
	}

	sort.Slice(ports, func(i, j int) bool {
		if ports[i].HostPort != ports[j].HostPort {
			return ports[i].HostPort < ports[j].HostPort
		}
		if ports[i].ContainerPort != ports[j].ContainerPort {
			return ports[i].ContainerPort < ports[j].ContainerPort
		}
		return ports[i].Protocol < ports[j].Protocol
	})

	c.JSON(http.StatusOK, models.NodeBrowserPortsResponse{
		NodeName:      nodeName,
		ContainerName: clab.GetContainerName(containerInfo),
		Ports:         ports,
	})
}

// @Summary SSHX share action
// @Description Executes SSHX share action (attach, detach, reattach) for a lab.
// @Tags Labs - Sharing
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab Name"
// @Param action path string true "Action (attach|detach|reattach)"
// @Success 200 {object} models.ShareToolResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/labs/{labName}/sshx/{action} [post]
func LabSSHXShareHandler(c *gin.Context) {
	handleLabShareAction(c, "sshx")
}

// @Summary GoTTY share action
// @Description Executes GoTTY share action (attach, detach, reattach) for a lab.
// @Tags Labs - Sharing
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab Name"
// @Param action path string true "Action (attach|detach|reattach)"
// @Param port query int false "GoTTY port (attach/reattach only)"
// @Success 200 {object} models.ShareToolResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/labs/{labName}/gotty/{action} [post]
func LabGoTTYShareHandler(c *gin.Context) {
	handleLabShareAction(c, "gotty")
}

func handleLabShareAction(c *gin.Context, kind string) {
	username := c.GetString("username")
	labName := strings.TrimSpace(c.Param("labName"))
	action := strings.ToLower(strings.TrimSpace(c.Param("action")))

	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name format."})
		return
	}
	if action != "attach" && action != "detach" && action != "reattach" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid action. Use attach, detach, or reattach."})
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

	args := []string{"tools", kind, action, "-l", labName}
	if kind == "gotty" && (action == "attach" || action == "reattach") {
		port := defaultGottyPort
		if rawPort := strings.TrimSpace(c.Query("port")); rawPort != "" {
			parsed, err := strconv.Atoi(rawPort)
			if err != nil || parsed <= 0 || parsed > 65535 {
				c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid gotty port value."})
				return
			}
			port = parsed
		}
		args = append(args, "--port", strconv.Itoa(port))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	output, err := svc.RunContainerlabTool(ctx, clab.ContainerlabToolRunOptions{Args: args})
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	link := extractFirstHTTPLink(output)
	if link != "" && strings.Contains(link, "HOST_IP") {
		if host := strings.TrimSpace(config.AppConfig.APIServerHost); host != "" {
			link = strings.ReplaceAll(link, "HOST_IP", host)
		}
	}

	message := fmt.Sprintf("%s %s completed for lab '%s'.", strings.ToUpper(kind), action, labName)
	c.JSON(http.StatusOK, models.ShareToolResponse{
		Message: message,
		Link:    link,
		Output:  output,
	})
}

// @Summary Run fcli command
// @Description Runs an fcli command against the selected lab topology.
// @Tags Labs - Tools
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param labName path string true "Lab Name"
// @Param fcli_request body models.FcliCommandRequest true "fcli command request"
// @Success 200 {object} models.FcliCommandResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/labs/{labName}/fcli [post]
func RunLabFcliHandler(c *gin.Context) {
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
	pathOwner := c.GetString(verifiedLabOwnerContextKey)
	if strings.TrimSpace(pathOwner) == "" {
		pathOwner = username
	}
	if topoPath == "" || strings.HasPrefix(strings.ToLower(topoPath), "http") {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Lab topology path is unavailable for fcli execution."})
		return
	}

	var req models.FcliCommandRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	command := strings.TrimSpace(req.Command)
	commandArgs := strings.Fields(command)
	if len(commandArgs) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "fcli command is required."})
		return
	}

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	output, runErr := svc.RunFcliCommand(ctx, clab.FcliRunOptions{
		Runtime:      config.AppConfig.ClabRuntime,
		Network:      readMgmtNetworkFromTopologyFile(pathOwner, topoPath),
		TopologyPath: topoPath,
		CommandArgs:  commandArgs,
	})
	if runErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: runErr.Error()})
		return
	}

	c.JSON(http.StatusOK, models.FcliCommandResponse{
		Command: command,
		Output:  output,
	})
}

// @Summary Generate draw.io graph
// @Description Generates a draw.io diagram from a lab topology and returns the generated XML content.
// @Tags Labs - Graph
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param labName path string true "Lab Name"
// @Param drawio_request body models.DrawioGenerateRequest false "Draw.io generation options"
// @Success 200 {object} models.DrawioGenerateResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 404 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/labs/{labName}/graph/drawio [post]
func GenerateLabDrawioHandler(c *gin.Context) {
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
	pathOwner := c.GetString(verifiedLabOwnerContextKey)
	if strings.TrimSpace(pathOwner) == "" {
		pathOwner = username
	}
	if topoPath == "" || strings.HasPrefix(strings.ToLower(topoPath), "http") {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Lab topology path is unavailable for graph generation."})
		return
	}

	var req models.DrawioGenerateRequest
	_ = c.ShouldBindJSON(&req)

	layout := strings.ToLower(strings.TrimSpace(req.Layout))
	if layout == "" {
		layout = "horizontal"
	}
	if layout != "horizontal" && layout != "vertical" && layout != "interactive" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error: "Invalid layout value. Use horizontal, vertical, or interactive.",
		})
		return
	}

	effectiveLayout := layout
	message := ""
	if layout == "interactive" {
		// The standalone web cannot provide an interactive TTY drawio session.
		effectiveLayout = "horizontal"
		message = "Interactive draw.io mode is not available in standalone web; generated horizontal layout."
	}

	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Containerlab service not initialized"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	drawioResult, generateErr := svc.GenerateDrawioFile(ctx, clab.DrawioGenerateOptions{
		TopoPath:    topoPath,
		Runtime:     config.AppConfig.ClabRuntime,
		Layout:      effectiveLayout,
		Theme:       req.Theme,
		Interactive: false,
	})
	if generateErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: generateErr.Error()})
		return
	}

	rootedDrawio, resolveErr := resolveUserRootedFilePath(pathOwner, drawioResult.Path)
	if resolveErr != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: resolveErr.Error()})
		return
	}
	content, readErr := readRootedFile(rootedDrawio)
	if readErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error: fmt.Sprintf("failed to read generated drawio file: %v", readErr),
		})
		return
	}

	c.JSON(http.StatusOK, models.DrawioGenerateResponse{
		FileName: filepath.Base(drawioResult.Path),
		Content:  string(content),
		Layout:   effectiveLayout,
		Message:  message,
		Output:   drawioResult.Output,
	})
}

func lifecyclePastTense(action clab.NodeLifecycleAction) string {
	switch action {
	case clab.NodeLifecycleActionStart:
		return "started"
	case clab.NodeLifecycleActionStop:
		return "stopped"
	case clab.NodeLifecycleActionRestart:
		return "restarted"
	case clab.NodeLifecycleActionPause:
		return "paused"
	case clab.NodeLifecycleActionUnpause:
		return "unpaused"
	default:
		return string(action)
	}
}

func resolveTopologyNodeName(labName string, containerInfo *clabruntime.GenericContainer) string {
	if nodeName := strings.TrimSpace(clab.GetContainerNodeName(containerInfo)); nodeName != "" {
		return nodeName
	}
	return stripContainerPrefix(labName, clab.GetContainerName(containerInfo))
}

func resolveLabNodeContainer(
	ctx context.Context,
	svc *clab.Service,
	labName, nodeName string,
) (*clabruntime.GenericContainer, error) {
	target := strings.TrimSpace(nodeName)
	if target == "" {
		return nil, fmt.Errorf("node name is required")
	}

	// Try explicit node name resolution first.
	if containers, err := svc.ListContainers(ctx, clab.ListOptions{
		LabName:  labName,
		NodeName: target,
	}); err == nil && len(containers) > 0 {
		return &containers[0], nil
	}

	// Then try direct container-name match.
	if containers, err := svc.ListContainers(ctx, clab.ListOptions{
		LabName:       labName,
		ContainerName: target,
	}); err == nil && len(containers) > 0 {
		return &containers[0], nil
	}

	containers, err := svc.ListContainers(ctx, clab.ListOptions{LabName: labName})
	if err != nil {
		return nil, fmt.Errorf("failed to list lab containers: %w", err)
	}
	if len(containers) == 0 {
		return nil, fmt.Errorf("node '%s' not found in lab '%s'", target, labName)
	}

	var best *clabruntime.GenericContainer
	bestScore := 0
	for _, container := range containers {
		candidate := container
		score := scoreNodeMatch(labName, clab.GetContainerName(&candidate), target)
		if score > bestScore {
			best = &candidate
			bestScore = score
		}
	}

	if best == nil || bestScore == 0 {
		return nil, fmt.Errorf("node '%s' not found in lab '%s'", target, labName)
	}

	return best, nil
}

func scoreNodeMatch(labName, containerName, requestedNodeName string) int {
	normalizedContainer := strings.ToLower(strings.TrimSpace(containerName))
	requestedCandidates := nodeNameCandidates(labName, requestedNodeName)
	containerCandidates := nodeNameCandidates(labName, containerName)
	if normalizedContainer == "" || len(requestedCandidates) == 0 {
		return 0
	}

	if containsString(requestedCandidates, normalizedContainer) {
		return 100
	}

	for _, requested := range requestedCandidates {
		if containsString(containerCandidates, requested) {
			return 90
		}
		for _, candidate := range containerCandidates {
			if strings.HasPrefix(candidate, requested+"-") {
				return 80
			}
		}
		if strings.HasSuffix(normalizedContainer, "-"+requested) {
			return 70
		}
	}

	return 0
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func nodeNameCandidates(labName, value string) []string {
	candidates := make([]string, 0, 2)
	seen := map[string]struct{}{}
	add := func(candidate string) {
		normalized := strings.ToLower(strings.TrimSpace(candidate))
		if normalized == "" {
			return
		}
		if _, exists := seen[normalized]; exists {
			return
		}
		candidates = append(candidates, normalized)
		seen[normalized] = struct{}{}
	}

	add(value)
	add(stripContainerPrefix(labName, value))

	return candidates
}

func stripContainerPrefix(labName, containerName string) string {
	trimmed := strings.TrimSpace(containerName)
	normalizedLab := strings.ToLower(strings.TrimSpace(labName))
	if trimmed == "" || normalizedLab == "" {
		return trimmed
	}

	normalizedName := strings.ToLower(trimmed)
	defaultPrefix := fmt.Sprintf("clab-%s-", normalizedLab)
	if strings.HasPrefix(normalizedName, defaultPrefix) {
		return trimmed[len(defaultPrefix):]
	}

	labPrefix := normalizedLab + "-"
	if strings.HasPrefix(normalizedName, labPrefix) {
		return trimmed[len(labPrefix):]
	}

	labSegment := "-" + normalizedLab + "-"
	if segmentIndex := strings.LastIndex(normalizedName, labSegment); segmentIndex >= 0 {
		return trimmed[segmentIndex+len(labSegment):]
	}

	return trimmed
}

func hasDifferentDefaultContainerlabPrefix(labName, containerName string) bool {
	normalizedName := strings.ToLower(strings.TrimSpace(containerName))
	normalizedLab := strings.ToLower(strings.TrimSpace(labName))
	if normalizedName == "" || normalizedLab == "" {
		return false
	}

	expectedPrefix := fmt.Sprintf("clab-%s-", normalizedLab)
	return strings.HasPrefix(normalizedName, "clab-") && !strings.HasPrefix(normalizedName, expectedPrefix)
}

func readMgmtNetworkFromTopologyFile(username, topoPath string) string {
	rootedTopology, resolveErr := resolveUserRootedFilePath(username, topoPath)
	if resolveErr != nil {
		log.Warnf("fcli: rejected topology file path '%s': %v", topoPath, resolveErr)
		return defaultMgmtNet
	}
	content, err := readRootedFile(rootedTopology)
	if err != nil {
		log.Warnf("fcli: failed to read topology file '%s': %v", topoPath, err)
		return defaultMgmtNet
	}

	var parsed topologyMgmtConfig
	if err := yaml.Unmarshal(content, &parsed); err != nil {
		log.Warnf("fcli: failed to parse topology file '%s': %v", topoPath, err)
		return defaultMgmtNet
	}

	network := strings.TrimSpace(parsed.Mgmt.Network)
	if network == "" {
		return defaultMgmtNet
	}

	return network
}

func extractFirstHTTPLink(output string) string {
	match := httpLinkRegexp.FindString(strings.TrimSpace(output))
	return strings.TrimSpace(match)
}

func describePort(port int) string {
	switch port {
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 443:
		return "HTTPS"
	case 1880:
		return "Node-RED"
	case 3000:
		return "Grafana"
	case 5432:
		return "PostgreSQL"
	case 5601:
		return "Kibana"
	case 8080:
		return "Web Server"
	case 8443:
		return "HTTPS (Alt)"
	case 9000:
		return "Web Server"
	case 9090:
		return "Prometheus"
	case 9200:
		return "Elasticsearch"
	default:
		return ""
	}
}

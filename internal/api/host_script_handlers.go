// internal/api/host_script_handlers.go
package api

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/auth"
	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

const (
	// Linux limits one command line argument to 128 KiB, and bash -c takes the script as one.
	maxInlineScriptBytes = 100 * 1024
	// A script file is read to show and check it, so it has to fit in memory.
	maxScriptFileBytes     = 10 * 1024 * 1024
	maxScriptPreviewBytes  = 64 * 1024
	maxHostScriptBodyBytes = 256 * 1024
	maxHostScriptTimeout   = 24 * time.Hour
	// maxHostScriptsPerUser keeps an accident from filling a shared host.
	maxHostScriptsPerUser = 4
)

// hostScriptLabTopology finds a lab's topology file and owner; tests replace it, because
// the real one asks the container runtime.
var hostScriptLabTopology = resolveLabTopologyFile

var (
	hostScriptsRunning   = map[string]int{}
	hostScriptsRunningMu sync.Mutex
)

// requireHostScripts guards the script button routes: off unless the administrator turned
// them on, and never with a lab runtime, whose labs have no host to run on.
func requireHostScripts() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := clab.RequireContainerRuntime("host scripts"); err != nil {
			c.AbortWithStatusJSON(http.StatusNotImplemented, models.ErrorResponse{Error: err.Error()})
			return
		}
		if !config.AppConfig.APIHostScripts {
			c.AbortWithStatusJSON(http.StatusNotImplemented, models.ErrorResponse{Error: "Script buttons are turned off on this server (API_HOST_SCRIPTS)."})
			return
		}
		c.Next()
	}
}

// hostScriptAccount is the signed-in user, who a script runs as. Never the lab's owner:
// a superuser or shared-folder peer clicking a button must not act as someone else.
type hostScriptAccount struct {
	username string
	home     string
	uid      int
	gid      int
	groups   []int
}

func lookupHostScriptAccount(username string) (hostScriptAccount, error) {
	usr, err := user.Lookup(username)
	if err != nil {
		return hostScriptAccount{}, fmt.Errorf("could not determine user details: %w", err)
	}
	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return hostScriptAccount{}, fmt.Errorf("could not process user UID: %w", err)
	}
	gid, err := strconv.Atoi(usr.Gid)
	if err != nil {
		return hostScriptAccount{}, fmt.Errorf("could not process user GID: %w", err)
	}
	return hostScriptAccount{username: username, home: usr.HomeDir, uid: uid, gid: gid, groups: userGroupIDs(username, gid)}, nil
}

// credential is what the script process runs with. A server not running as root cannot
// switch accounts, and must not run a script as itself for somebody else.
func (a hostScriptAccount) credential() (*syscall.Credential, error) {
	euid := os.Geteuid()
	if euid != 0 {
		if euid == a.uid {
			return nil, nil
		}
		return nil, fmt.Errorf("the server does not run as root, so it cannot run scripts as %s", a.username)
	}
	groups := make([]uint32, 0, len(a.groups))
	for _, group := range a.groups {
		groups = append(groups, uint32(group))
	}
	return &syscall.Credential{Uid: uint32(a.uid), Gid: uint32(a.gid), Groups: groups}, nil
}

func (a hostScriptAccount) environment(labName, topologyPath string) []string {
	return []string{
		"HOME=" + a.home,
		"USER=" + a.username,
		"LOGNAME=" + a.username,
		"SHELL=/bin/bash",
		"LANG=C.UTF-8",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"CLAB_LAB_NAME=" + labName,
		"CLAB_TOPOLOGY=" + topologyPath,
	}
}

// preparedHostScript is a checked script, ready to describe or run.
type preparedHostScript struct {
	account     hostScriptAccount
	labName     string
	topology    string
	folder      string
	args        []string
	description models.HostScriptDescription
}

type hostScriptProblem struct {
	status  int
	message string
}

func (p *hostScriptProblem) send(c *gin.Context) {
	c.JSON(p.status, models.ErrorResponse{Error: p.message})
}

func validateHostScriptSource(source models.HostScriptSourceRequest) *hostScriptProblem {
	if strings.TrimSpace(source.ScriptPath) == "" && strings.TrimSpace(source.Script) == "" {
		return &hostScriptProblem{http.StatusBadRequest, "The script button has no script or script path."}
	}
	if strings.TrimSpace(source.ScriptPath) == "" && len(source.Script) > maxInlineScriptBytes {
		return &hostScriptProblem{http.StatusBadRequest, fmt.Sprintf("An inline script can have at most %d KiB. Use a script file.", maxInlineScriptBytes/1024)}
	}
	return nil
}

// prepareHostScript finds a script of a lab and reads it as the signed-in user. It writes
// the response itself when it returns false.
func prepareHostScript(ctx context.Context, c *gin.Context, source models.HostScriptSourceRequest) (*preparedHostScript, bool) {
	username := c.GetString("username")
	labName := c.Param("labName")
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return nil, false
	}
	if problem := validateHostScriptSource(source); problem != nil {
		problem.send(c)
		return nil, false
	}
	if !auth.HasLoginShell(username) {
		c.JSON(http.StatusForbidden, models.ErrorResponse{Error: "Your account has no login shell, so it cannot run scripts."})
		return nil, false
	}
	account, err := lookupHostScriptAccount(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return nil, false
	}

	// Handles ownership, undeployed labs through ?path=, and answers on failure.
	topologyPath, owner, ok := hostScriptLabTopology(ctx, c, username, labName)
	if !ok {
		return nil, false
	}
	foreign := owner != username || isSharedLabPath(topologyPath)
	prepared := &preparedHostScript{
		account:  account,
		labName:  labName,
		topology: topologyPath,
		folder:   filepath.Dir(topologyPath),
	}

	scriptPath := strings.TrimSpace(source.ScriptPath)
	if scriptPath == "" {
		sum := sha256.Sum256([]byte(source.Script))
		prepared.args = []string{"-c", source.Script}
		prepared.description = models.HostScriptDescription{
			Kind:      "inline",
			Sha256:    hex.EncodeToString(sum[:]),
			Size:      int64(len(source.Script)),
			Foreign:   foreign,
			Content:   previewOf([]byte(source.Script)),
			Truncated: len(source.Script) > maxScriptPreviewBytes,
		}
		return prepared, true
	}

	scope, err := labPathScopeFor(owner, topologyPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return nil, false
	}
	resolved, err := scope.resolve(scriptPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("Invalid script path: %s", err.Error())})
		return nil, false
	}
	description, problem := describeHostScriptFile(resolved.Path, account)
	if problem != nil {
		problem.send(c)
		return nil, false
	}
	description.Foreign = description.Foreign || foreign
	prepared.args = []string{resolved.Path}
	prepared.description = description
	return prepared, true
}

// describeHostScriptFile reads a script file as the account would: this server runs as
// root, and must not show anyone a file they cannot read themselves.
func describeHostScriptFile(path string, account hostScriptAccount) (models.HostScriptDescription, *hostScriptProblem) {
	file, err := clab.OpenScriptFile(path, clab.FileReader{UID: account.uid, GIDs: account.groups})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return models.HostScriptDescription{}, &hostScriptProblem{http.StatusNotFound, fmt.Sprintf("Script not found: %s", path)}
		}
		return models.HostScriptDescription{}, &hostScriptProblem{http.StatusForbidden, fmt.Sprintf("Cannot read %s: %s", path, err.Error())}
	}
	defer func() { _ = file.Close() }()

	content, err := io.ReadAll(io.LimitReader(file, maxScriptFileBytes+1))
	if err != nil {
		return models.HostScriptDescription{}, &hostScriptProblem{http.StatusInternalServerError, fmt.Sprintf("Cannot read %s: %s", path, err.Error())}
	}
	if len(content) > maxScriptFileBytes {
		return models.HostScriptDescription{}, &hostScriptProblem{http.StatusRequestEntityTooLarge, fmt.Sprintf("%s is larger than %d MiB.", path, maxScriptFileBytes/(1024*1024))}
	}

	description := models.HostScriptDescription{Kind: "file", ResolvedPath: path}
	sum := sha256.Sum256(content)
	description.Sha256 = hex.EncodeToString(sum[:])
	description.Size = int64(len(content))
	description.Content = previewOf(content)
	description.Truncated = len(content) > maxScriptPreviewBytes
	if info, statErr := file.Stat(); statErr == nil {
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			description.Foreign = int(st.Uid) != account.uid
			description.Owner = ownerName(st.Uid)
		}
	}
	return description, nil
}

func previewOf(content []byte) string {
	if len(content) > maxScriptPreviewBytes {
		content = content[:maxScriptPreviewBytes]
	}
	return strings.ToValidUTF8(string(content), "�")
}

func ownerName(uid uint32) string {
	if owner, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		return owner.Username
	}
	return fmt.Sprintf("uid %d", uid)
}

func bindHostScriptBody(c *gin.Context, target any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxHostScriptBodyBytes)
	if err := c.ShouldBindJSON(target); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return false
	}
	return true
}

// @Summary Describe a script button's script
// @Description Says what a script is right now, as the signed-in user can read it, for the confirmation before it runs. Needs API_HOST_SCRIPTS=true; not available with lab runtime c9s.
// @Tags Labs
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param labName path string true "Lab name"
// @Param path query string false "Topology file of a lab that is not deployed, from the topology listing"
// @Param request body models.HostScriptSourceRequest true "The script"
// @Success 200 {object} models.HostScriptDescription
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 403 {object} models.ErrorResponse "The account cannot run scripts or read this one"
// @Failure 404 {object} models.ErrorResponse "Lab or script not found"
// @Failure 501 {object} models.ErrorResponse "Turned off, or a lab runtime"
// @Router /api/v1/labs/{labName}/host-script/describe [post]
func DescribeHostScriptHandler(c *gin.Context) {
	var source models.HostScriptSourceRequest
	if !bindHostScriptBody(c, &source) {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
	defer cancel()
	prepared, ok := prepareHostScript(ctx, c, source)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, prepared.description)
}

func hostScriptTimeout(request models.HostScriptRunRequest) (time.Duration, *hostScriptProblem) {
	if request.TimeoutSeconds == nil {
		return maxHostScriptTimeout, nil
	}
	seconds := *request.TimeoutSeconds
	if math.IsNaN(seconds) || seconds <= 0 || seconds > maxHostScriptTimeout.Seconds() {
		return 0, &hostScriptProblem{http.StatusBadRequest, fmt.Sprintf("The timeout must be between 1 and %d seconds.", int(maxHostScriptTimeout.Seconds()))}
	}
	return time.Duration(seconds * float64(time.Second)), nil
}

func claimHostScriptSlot(username string) bool {
	hostScriptsRunningMu.Lock()
	defer hostScriptsRunningMu.Unlock()
	if hostScriptsRunning[username] >= maxHostScriptsPerUser {
		return false
	}
	hostScriptsRunning[username]++
	return true
}

func releaseHostScriptSlot(username string) {
	hostScriptsRunningMu.Lock()
	defer hostScriptsRunningMu.Unlock()
	hostScriptsRunning[username]--
	if hostScriptsRunning[username] <= 0 {
		delete(hostScriptsRunning, username)
	}
}

// hostScriptStartMessage names the likely cause: the kernel reports a folder the account
// cannot enter as a failure to execute bash.
func hostScriptStartMessage(err error, folder string) string {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Sprintf("Your account cannot enter the lab's folder %s, so the script cannot run from it.", folder)
	}
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Sprintf("The lab's folder %s does not exist.", folder)
	}
	return fmt.Sprintf("Could not start the script: %s", err.Error())
}

func hostScriptStartStatus(err error) int {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return http.StatusForbidden
	case errors.Is(err, fs.ErrNotExist):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

// @Summary Run a script button's script
// @Description Runs a script with bash on this host, from the lab's topology folder, as the signed-in user, and answers with NDJSON events: output as it comes, then the exit. Blank lines keep the connection open. Closing the connection stops the script and what it started. Needs API_HOST_SCRIPTS=true; not available with lab runtime c9s.
// @Tags Labs
// @Security BearerAuth
// @Accept json
// @Produce application/x-ndjson
// @Param labName path string true "Lab name"
// @Param path query string false "Topology file of a lab that is not deployed, from the topology listing"
// @Param request body models.HostScriptRunRequest true "The script"
// @Success 200 {object} models.HostScriptEvent
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 403 {object} models.ErrorResponse "The account cannot run scripts or read this one"
// @Failure 404 {object} models.ErrorResponse "Lab or script not found"
// @Failure 409 {object} models.ErrorResponse "The script is not the one that was confirmed"
// @Failure 429 {object} models.ErrorResponse "Too many running scripts"
// @Failure 501 {object} models.ErrorResponse "Turned off, or a lab runtime"
// @Router /api/v1/labs/{labName}/host-script/stream [post]
func StreamHostScriptHandler(c *gin.Context) {
	username := c.GetString("username")
	var request models.HostScriptRunRequest
	if !bindHostScriptBody(c, &request) {
		return
	}
	timeout, problem := hostScriptTimeout(request)
	if problem != nil {
		problem.send(c)
		return
	}

	lookup, cancelLookup := context.WithTimeout(c.Request.Context(), 2*time.Minute)
	defer cancelLookup()
	prepared, ok := prepareHostScript(lookup, c, request.HostScriptSourceRequest)
	if !ok {
		return
	}
	if request.ExpectedSha256 != "" && request.ExpectedSha256 != prepared.description.Sha256 {
		c.JSON(http.StatusConflict, models.ErrorResponse{Error: "The script changed since it was confirmed. Run it again to review it."})
		return
	}
	credential, err := prepared.account.credential()
	if err != nil {
		c.JSON(http.StatusForbidden, models.ErrorResponse{Error: err.Error()})
		return
	}
	if !claimHostScriptSlot(username) {
		c.JSON(http.StatusTooManyRequests, models.ErrorResponse{Error: fmt.Sprintf("You already run %d scripts on this host. Wait for one to end or stop it.", maxHostScriptsPerUser)})
		return
	}
	defer releaseHostScriptSlot(username)

	// A closed connection ends this context, which stops the script.
	ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
	defer cancel()
	run, err := clab.StartHostScript(ctx, clab.HostScriptOptions{
		Args:       prepared.args,
		Dir:        prepared.folder,
		Env:        prepared.account.environment(prepared.labName, prepared.topology),
		Credential: credential,
	})
	if err != nil {
		log.Warnf("HostScript user '%s': could not start a script of lab '%s': %v", username, prepared.labName, err)
		c.JSON(hostScriptStartStatus(err), models.ErrorResponse{Error: hostScriptStartMessage(err, prepared.folder)})
		return
	}
	log.Infof("HostScript user '%s': started on lab '%s' (%s, sha256 %s, foreign %t)", username, prepared.labName, hostScriptName(prepared), prepared.description.Sha256, prepared.description.Foreign)

	c.Header("Content-Type", "application/x-ndjson; charset=utf-8")
	c.Header("Cache-Control", "no-cache")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)
	c.Writer.WriteHeaderNow()

	result := streamHostScriptEvents(cancel, c, run)
	log.Infof("HostScript user '%s': ended on lab '%s' (%s, exit %s, timed out %t, cancelled %t, %d ms)", username, prepared.labName, hostScriptName(prepared), hostScriptExitText(result.ExitCode), result.TimedOut, result.Cancelled, result.Duration.Milliseconds())
}

// streamHostScriptEvents forwards a run to the client. Once the client is gone it cancels
// the run and only reads on so that the script's end can be reported to the log.
func streamHostScriptEvents(cancel context.CancelFunc, c *gin.Context, run *clab.HostScriptRun) clab.HostScriptExit {
	writer := bufio.NewWriter(c.Writer)
	flusher, canFlush := c.Writer.(http.Flusher)
	if !canFlush {
		cancel()
	} else {
		flusher.Flush()
	}

	heartbeat := time.NewTicker(ndjsonStreamHeartbeatInterval)
	defer heartbeat.Stop()

	connected := canFlush
	writeEvent := func(event models.HostScriptEvent) {
		if !connected {
			return
		}
		payload, err := json.Marshal(event)
		if err == nil && writeNDJSONLine(writer, flusher, string(payload)) {
			return
		}
		connected = false
		cancel()
	}

	output := run.Output
	for output != nil {
		select {
		case <-heartbeat.C:
			if connected && !writeNDJSONHeartbeat(writer, flusher) {
				connected = false
				cancel()
			}
		case piece, open := <-output:
			if !open {
				output = nil
				continue
			}
			writeEvent(models.HostScriptEvent{Type: "output", Stream: piece.Stream, Text: piece.Text})
		}
	}

	result := <-run.Done
	writeEvent(models.HostScriptEvent{
		Type: "exit",
		Result: &models.HostScriptResult{
			ExitCode:   result.ExitCode,
			TimedOut:   result.TimedOut,
			Cancelled:  result.Cancelled,
			DurationMs: result.Duration.Milliseconds(),
		},
	})
	return result
}

func hostScriptName(prepared *preparedHostScript) string {
	if prepared.description.ResolvedPath != "" {
		return prepared.description.ResolvedPath
	}
	return "inline script"
}

func hostScriptExitText(code *int) string {
	if code == nil {
		return "by signal"
	}
	return strconv.Itoa(*code)
}

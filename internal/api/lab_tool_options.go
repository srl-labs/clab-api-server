package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/models"
)

const (
	defaultGottyUsername = "admin"
	defaultGottyShell    = "bash"
	maxOptionalJSONBody  = 1 << 20
	redactedSecret       = "***"
)

// errInvalidGottyPort reports a GoTTY port outside 1-65535.
var errInvalidGottyPort = errors.New("invalid gotty port value")

// mermaidDirections are the flowchart directions containerlab accepts.
var mermaidDirections = []string{"TD", "TB", "BT", "RL", "LR"}

// GoTTY options are interpolated into a shell command inside the GoTTY
// container, so only plain tokens without shell metacharacters are allowed.
var (
	gottyUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
	gottyPasswordPattern = regexp.MustCompile(`^[A-Za-z0-9._@%+=,!-]{1,64}$`)
	gottyShellPattern    = regexp.MustCompile(`^/?[A-Za-z0-9_][A-Za-z0-9_./-]{0,63}$`)
)

// gottyShareOptions are validated GoTTY attach/reattach options. Empty strings
// mean containerlab's defaults apply.
type gottyShareOptions struct {
	Port     int
	Username string
	Password string
	Shell    string
}

// bindOptionalJSON decodes a JSON request body into target. An empty body
// leaves target unchanged.
func bindOptionalJSON(c *gin.Context, target any) error {
	if c.Request == nil || c.Request.Body == nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxOptionalJSONBody))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	return json.Unmarshal(body, target)
}

// normalizeMermaidDirection validates a mermaid direction case-insensitively and
// returns it in upper case. An empty direction defaults to TD.
func normalizeMermaidDirection(raw string) (string, error) {
	direction := strings.ToUpper(strings.TrimSpace(raw))
	if direction == "" {
		return "TD", nil
	}
	for _, allowed := range mermaidDirections {
		if direction == allowed {
			return direction, nil
		}
	}
	return "", fmt.Errorf("invalid direction value, use one of %s", strings.Join(mermaidDirections, ", "))
}

// sshxReadOnlyLink derives the SSHX read-only link from a full access link the
// way containerlab prints it: the fragment holds "<read key>,<write key>".
func sshxReadOnlyLink(link string) string {
	parts := strings.Split(link, "#")
	if len(parts) < 2 {
		return ""
	}
	accessParts := strings.Split(parts[1], ",")
	if len(accessParts) < 2 {
		return ""
	}
	return parts[0] + "#" + accessParts[0]
}

// resolveGoTTYShareOptions validates GoTTY options from the request body and the
// legacy port query. A body port wins over the query port.
func resolveGoTTYShareOptions(req models.GoTTYShareRequest, rawQueryPort string) (gottyShareOptions, error) {
	opts := gottyShareOptions{Port: defaultGottyPort}

	if rawPort := strings.TrimSpace(rawQueryPort); rawPort != "" {
		parsed, err := strconv.Atoi(rawPort)
		if err != nil || parsed <= 0 || parsed > 65535 {
			return gottyShareOptions{}, errInvalidGottyPort
		}
		opts.Port = parsed
	}
	if req.Port != 0 {
		if req.Port < 0 || req.Port > 65535 {
			return gottyShareOptions{}, errInvalidGottyPort
		}
		opts.Port = req.Port
	}

	if (req.Username == "") != (req.Password == "") {
		return gottyShareOptions{}, errors.New("gotty username and password must be provided together")
	}
	if req.Username != "" && !gottyUsernamePattern.MatchString(req.Username) {
		return gottyShareOptions{}, errors.New("invalid gotty username: use 1-32 letters, digits, '.', '_' or '-', starting with a letter or digit")
	}
	if req.Password != "" && (!gottyPasswordPattern.MatchString(req.Password) || strings.HasPrefix(req.Password, "-")) {
		return gottyShareOptions{}, errors.New("invalid gotty password: use 1-64 letters, digits or . _ @ % + = , ! - and do not start with '-'")
	}
	if req.Shell != "" && (!gottyShellPattern.MatchString(req.Shell) || strings.Contains(req.Shell, "..")) {
		return gottyShareOptions{}, errors.New("invalid gotty shell: use a shell name or path such as bash or /bin/sh")
	}

	opts.Username = req.Username
	opts.Password = req.Password
	opts.Shell = req.Shell
	return opts, nil
}

// args returns the containerlab flags for the options.
func (o gottyShareOptions) args() []string {
	args := []string{"--port", strconv.Itoa(o.Port)}
	if o.Username != "" {
		args = append(args, "--username", o.Username, "--password", o.Password)
	}
	if o.Shell != "" {
		args = append(args, "--shell", o.Shell)
	}
	return args
}

// effectiveUsername returns the GoTTY login name containerlab uses.
func (o gottyShareOptions) effectiveUsername() string {
	if o.Username == "" {
		return defaultGottyUsername
	}
	return o.Username
}

// effectiveShell returns the GoTTY shell containerlab uses.
func (o gottyShareOptions) effectiveShell() string {
	if o.Shell == "" {
		return defaultGottyShell
	}
	return o.Shell
}

// redactSecret replaces every occurrence of secret in text.
func redactSecret(text, secret string) string {
	if secret == "" {
		return text
	}
	return strings.ReplaceAll(text, secret, redactedSecret)
}

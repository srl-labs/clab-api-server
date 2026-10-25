package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

func newJSONBodyContext(target, body string, params gin.Params) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = params
	c.Set("username", "alice")
	return c, recorder
}

func TestNormalizeMermaidDirection(t *testing.T) {
	tests := []struct {
		raw     string
		want    string
		wantErr bool
	}{
		{raw: "", want: "TD"},
		{raw: "  ", want: "TD"},
		{raw: "TD", want: "TD"},
		{raw: "tb", want: "TB"},
		{raw: "Bt", want: "BT"},
		{raw: "rl", want: "RL"},
		{raw: " lr ", want: "LR"},
		{raw: "DT", wantErr: true},
		{raw: "left", wantErr: true},
		{raw: "TD;", wantErr: true},
	}
	for _, tt := range tests {
		got, err := normalizeMermaidDirection(tt.raw)
		if tt.wantErr {
			if err == nil {
				t.Errorf("normalizeMermaidDirection(%q) = %q, want error", tt.raw, got)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("normalizeMermaidDirection(%q) = %q, %v; want %q", tt.raw, got, err, tt.want)
		}
	}
}

func TestSSHXReadOnlyLink(t *testing.T) {
	tests := []struct {
		link string
		want string
	}{
		{link: "https://sshx.io/s/abc123#readKey,writeKey", want: "https://sshx.io/s/abc123#readKey"},
		{link: "https://sshx.io/s/abc123#readKey", want: ""},
		{link: "https://sshx.io/s/abc123", want: ""},
		{link: "", want: ""},
		{link: "https://sshx.io/s/abc123#,writeKey", want: "https://sshx.io/s/abc123#"},
	}
	for _, tt := range tests {
		if got := sshxReadOnlyLink(tt.link); got != tt.want {
			t.Errorf("sshxReadOnlyLink(%q) = %q, want %q", tt.link, got, tt.want)
		}
	}
}

func TestResolveGoTTYShareOptions(t *testing.T) {
	tests := []struct {
		name      string
		req       models.GoTTYShareRequest
		queryPort string
		want      gottyShareOptions
		wantErr   bool
	}{
		{name: "defaults", want: gottyShareOptions{Port: defaultGottyPort}},
		{name: "query port", queryPort: "9000", want: gottyShareOptions{Port: 9000}},
		{name: "body port wins", req: models.GoTTYShareRequest{Port: 9100}, queryPort: "9000", want: gottyShareOptions{Port: 9100}},
		{
			name: "credentials and shell",
			req:  models.GoTTYShareRequest{Username: "lab.user_1", Password: "S3cr3t@lab%+=,!-x", Shell: "/bin/zsh"},
			want: gottyShareOptions{Port: defaultGottyPort, Username: "lab.user_1", Password: "S3cr3t@lab%+=,!-x", Shell: "/bin/zsh"},
		},
		{name: "plain shell", req: models.GoTTYShareRequest{Shell: "sh"}, want: gottyShareOptions{Port: defaultGottyPort, Shell: "sh"}},
		{name: "invalid query port", queryPort: "abc", wantErr: true},
		{name: "query port zero", queryPort: "0", wantErr: true},
		{name: "query port too large", queryPort: "65536", wantErr: true},
		{name: "negative body port", req: models.GoTTYShareRequest{Port: -1}, wantErr: true},
		{name: "body port too large", req: models.GoTTYShareRequest{Port: 70000}, wantErr: true},
		{name: "username without password", req: models.GoTTYShareRequest{Username: "alice"}, wantErr: true},
		{name: "password without username", req: models.GoTTYShareRequest{Password: "secret"}, wantErr: true},
		{name: "username too long", req: models.GoTTYShareRequest{Username: strings.Repeat("a", 33), Password: "x"}, wantErr: true},
		{name: "username leading dash", req: models.GoTTYShareRequest{Username: "-alice", Password: "x"}, wantErr: true},
		{name: "username quote injection", req: models.GoTTYShareRequest{Username: "a'; rm -rf /", Password: "x"}, wantErr: true},
		{name: "username command substitution", req: models.GoTTYShareRequest{Username: "$(id)", Password: "x"}, wantErr: true},
		{name: "username space", req: models.GoTTYShareRequest{Username: "al ice", Password: "x"}, wantErr: true},
		{name: "username newline", req: models.GoTTYShareRequest{Username: "alice\n", Password: "x"}, wantErr: true},
		{name: "password quote injection", req: models.GoTTYShareRequest{Username: "alice", Password: "a'; rm -rf /"}, wantErr: true},
		{name: "password command substitution", req: models.GoTTYShareRequest{Username: "alice", Password: "$(id)"}, wantErr: true},
		{name: "password backticks", req: models.GoTTYShareRequest{Username: "alice", Password: "`id`"}, wantErr: true},
		{name: "password space", req: models.GoTTYShareRequest{Username: "alice", Password: "pass word"}, wantErr: true},
		{name: "password comment", req: models.GoTTYShareRequest{Username: "alice", Password: "#x"}, wantErr: true},
		{name: "password tilde", req: models.GoTTYShareRequest{Username: "alice", Password: "~"}, wantErr: true},
		{name: "password newline", req: models.GoTTYShareRequest{Username: "alice", Password: "pass\nid"}, wantErr: true},
		{name: "password semicolon", req: models.GoTTYShareRequest{Username: "alice", Password: "a;id"}, wantErr: true},
		{name: "password leading dash", req: models.GoTTYShareRequest{Username: "alice", Password: "-x"}, wantErr: true},
		{name: "password too long", req: models.GoTTYShareRequest{Username: "alice", Password: strings.Repeat("p", 65)}, wantErr: true},
		{name: "shell injection", req: models.GoTTYShareRequest{Shell: "bash; id"}, wantErr: true},
		{name: "shell command substitution", req: models.GoTTYShareRequest{Shell: "$(id)"}, wantErr: true},
		{name: "shell quote", req: models.GoTTYShareRequest{Shell: "a'; rm -rf /"}, wantErr: true},
		{name: "shell parent dir", req: models.GoTTYShareRequest{Shell: "/bin/../tmp/x"}, wantErr: true},
		{name: "shell space", req: models.GoTTYShareRequest{Shell: "bash -c id"}, wantErr: true},
		{name: "shell comment", req: models.GoTTYShareRequest{Shell: "#x"}, wantErr: true},
		{name: "shell tilde", req: models.GoTTYShareRequest{Shell: "~/sh"}, wantErr: true},
		{name: "shell newline", req: models.GoTTYShareRequest{Shell: "bash\nid"}, wantErr: true},
		{name: "shell leading dash", req: models.GoTTYShareRequest{Shell: "-bash"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveGoTTYShareOptions(tt.req, tt.queryPort)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveGoTTYShareOptions(%+v, %q) = %+v, want error", tt.req, tt.queryPort, got)
				}
				if tt.req.Password != "" && strings.Contains(err.Error(), tt.req.Password) {
					t.Fatalf("error %q echoes the password", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveGoTTYShareOptions: %v", err)
			}
			if got != tt.want {
				t.Fatalf("resolveGoTTYShareOptions = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestGoTTYShareOptionsArgsAndDefaults(t *testing.T) {
	defaults := gottyShareOptions{Port: 8080}
	if got := defaults.args(); !slices.Equal(got, []string{"--port", "8080"}) {
		t.Fatalf("default args = %v", got)
	}
	if defaults.effectiveUsername() != "admin" || defaults.effectiveShell() != "bash" {
		t.Fatalf("defaults = %q/%q, want admin/bash", defaults.effectiveUsername(), defaults.effectiveShell())
	}

	custom := gottyShareOptions{Port: 9000, Username: "alice", Password: "secret", Shell: "/bin/sh"}
	want := []string{"--port", "9000", "--username", "alice", "--password", "secret", "--shell", "/bin/sh"}
	if got := custom.args(); !slices.Equal(got, want) {
		t.Fatalf("custom args = %v, want %v", got, want)
	}
	if custom.effectiveUsername() != "alice" || custom.effectiveShell() != "/bin/sh" {
		t.Fatalf("custom = %q/%q, want alice//bin/sh", custom.effectiveUsername(), custom.effectiveShell())
	}
}

func TestRedactSecret(t *testing.T) {
	text := "command containerlab tools gotty attach --password s3cret failed: password=s3cret"
	got := redactSecret(text, "s3cret")
	if strings.Contains(got, "s3cret") || strings.Count(got, redactedSecret) != 2 {
		t.Fatalf("redactSecret = %q", got)
	}
	if redactSecret(text, "") != text {
		t.Fatal("empty secret changed the text")
	}
}

func TestBindOptionalJSON(t *testing.T) {
	for _, body := range []string{"", "   \n"} {
		c, _ := newJSONBodyContext("/", body, nil)
		req := models.SSHXShareRequest{EnableReaders: true}
		if err := bindOptionalJSON(c, &req); err != nil || !req.EnableReaders {
			t.Fatalf("empty body %q: err=%v req=%+v", body, err, req)
		}
	}

	c, _ := newJSONBodyContext("/", `{"enableReaders": true}`, nil)
	var req models.SSHXShareRequest
	if err := bindOptionalJSON(c, &req); err != nil || !req.EnableReaders {
		t.Fatalf("valid body: err=%v req=%+v", err, req)
	}

	c, _ = newJSONBodyContext("/", `{"enableReaders": `, nil)
	if err := bindOptionalJSON(c, &req); err == nil {
		t.Fatal("malformed body accepted")
	}
}

func TestLabShareHandlersRejectInvalidOptions(t *testing.T) {
	tests := []struct {
		name    string
		handler gin.HandlerFunc
		action  string
		target  string
		body    string
	}{
		{name: "gotty injected username", handler: LabGoTTYShareHandler, action: "attach", body: `{"username":"a'; rm -rf /","password":"x"}`},
		{name: "gotty injected password", handler: LabGoTTYShareHandler, action: "reattach", body: `{"username":"alice","password":"$(id)"}`},
		{name: "gotty injected shell", handler: LabGoTTYShareHandler, action: "attach", body: `{"shell":"bash; id"}`},
		{name: "gotty username only", handler: LabGoTTYShareHandler, action: "attach", body: `{"username":"alice"}`},
		{name: "gotty invalid body port", handler: LabGoTTYShareHandler, action: "attach", body: `{"port":70000}`},
		{name: "gotty invalid query port", handler: LabGoTTYShareHandler, action: "attach", target: "/?port=abc"},
		{name: "gotty malformed body", handler: LabGoTTYShareHandler, action: "attach", body: `{"port":`},
		{name: "sshx malformed body", handler: LabSSHXShareHandler, action: "attach", body: `{"enableReaders":"yes"}`},
		{name: "invalid action", handler: LabSSHXShareHandler, action: "share"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := tt.target
			if target == "" {
				target = "/"
			}
			c, recorder := newJSONBodyContext(target, tt.body, gin.Params{
				{Key: "labName", Value: "lab1"},
				{Key: "action", Value: tt.action},
			})
			tt.handler(c)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%s)", recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "$(id)") {
				t.Fatalf("response echoes the password: %s", recorder.Body.String())
			}
		})
	}
}

func TestLabGoTTYShareHandlerKeepsPortErrorMessage(t *testing.T) {
	for _, tt := range []struct{ target, body string }{
		{target: "/?port=not-a-port"},
		{target: "/", body: `{"port":-5}`},
	} {
		c, recorder := newJSONBodyContext(tt.target, tt.body, gin.Params{
			{Key: "labName", Value: "lab1"},
			{Key: "action", Value: "attach"},
		})
		LabGoTTYShareHandler(c)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "Invalid gotty port value.") {
			t.Fatalf("%s %s: status = %d, body = %s", tt.target, tt.body, recorder.Code, recorder.Body.String())
		}
	}
}

func TestLabMermaidHandlerRejectsInvalidDirection(t *testing.T) {
	for _, body := range []string{`{"direction":"sideways"}`, `{"direction":`} {
		c, recorder := newJSONBodyContext("/", body, gin.Params{{Key: "labName", Value: "lab1"}})
		GenerateLabMermaidHandler(c)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("body %s: status = %d, want 400 (%s)", body, recorder.Code, recorder.Body.String())
		}
	}

	c, recorder := newJSONBodyContext("/", "", gin.Params{{Key: "labName", Value: "bad name!"}})
	GenerateLabDotHandler(c)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid lab name: status = %d, want 400", recorder.Code)
	}
}

func TestHealthCheckAdvertisesFeatures(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/health", nil)

	HealthCheckHandler(c)

	var resp models.HealthResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	want := []string{"validate", "graph-mermaid", "graph-dot", "sshx-readers", "gotty-options"}
	for _, feature := range want {
		if !slices.Contains(resp.Features, feature) {
			t.Errorf("features %v missing %q", resp.Features, feature)
		}
	}
	if !slices.Equal(serverFeatures[:len(want)], want) {
		t.Errorf("serverFeatures = %v, want prefix %v", serverFeatures, want)
	}
}

func TestGenerateTopologyHandlerRejectsUngenerateableKind(t *testing.T) {
	previous := GetClabService()
	SetClabService(clab.NewService())
	t.Cleanup(func() { SetClabService(previous) })

	body := `{"name":"gen1","tiers":[{"count":1,"kind":"srl"},{"count":1,"kind":"not_a_kind"}],"images":{"srl":"ghcr.io/nokia/srlinux"}}`
	c, recorder := newJSONBodyContext("/api/v1/generate", body, nil)
	GenerateTopologyHandler(c)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%s)", recorder.Code, recorder.Body.String())
	}
	var resp models.ErrorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.Error != "kind 'not_a_kind' cannot be used to generate a topology" {
		t.Fatalf("error = %q", resp.Error)
	}
}

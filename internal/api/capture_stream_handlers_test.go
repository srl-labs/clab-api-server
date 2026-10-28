package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	clablabruntime "github.com/srl-labs/containerlab/labruntime"
	"github.com/stretchr/testify/require"

	"github.com/srl-labs/clab-api-server/internal/capture"
	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// captureLab adds a two-node lab with a link to the fake and its capturable interfaces.
func (a *c9sAPI) captureLab() {
	a.addLab("lab1", "n1", "srl1")
	a.fake.CaptureIfaces = map[string][]clablabruntime.CaptureInterface{
		"n1":   {{Node: "n1", Interface: "eth1", PeerNode: "srl1", PeerInterface: "e1-1"}},
		"srl1": {{Node: "srl1", Interface: "e1-1", Alias: "ethernet-1/1", PeerNode: "n1", PeerInterface: "eth1"}},
	}
}

// server serves the router over HTTP for streaming and websocket tests.
func (a *c9sAPI) server() *httptest.Server {
	server := httptest.NewServer(a.router)
	a.t.Cleanup(server.Close)
	return server
}

func (a *c9sAPI) get(ctx context.Context, rawURL string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+a.token)
	return http.DefaultClient.Do(request)
}

func TestParseCaptureTarget(t *testing.T) {
	for raw, want := range map[string]capture.Target{
		"n1:eth1":              {Node: "n1", Interface: "eth1"},
		" srl1:ethernet-1/1 ":  {Node: "srl1", Interface: "ethernet-1/1"},
		"sros:1/1/3":           {Node: "sros", Interface: "1/1/3"},
		"r1:eth1:sub":          {Node: "r1", Interface: "eth1:sub"},
		"node.with_dots:e1-12": {Node: "node.with_dots", Interface: "e1-12"},
	} {
		got, err := parseCaptureTarget(raw)
		require.NoError(t, err, raw)
		require.Equal(t, want, got, raw)
	}
	for _, raw := range []string{"", "n1", "n1:", ":eth1", "n 1:eth1", "n1:eth 1", "n1:eth1;rm", "n1/x:eth1", strings.Repeat("a", 129) + ":eth1"} {
		_, err := parseCaptureTarget(raw)
		require.ErrorIs(t, err, errInvalidCaptureTarget, raw)
	}
}

func TestParseCaptureQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	parse := func(query string) ([]capture.Target, captureLimits, error) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/x?"+query, nil)
		return parseCaptureQuery(c)
	}
	targets, limits, err := parse("target=n1:eth1&target=srl1:ethernet-1/1&duration=1m30s&packetLimit=100&snapLength=128")
	require.NoError(t, err)
	require.Equal(t, []capture.Target{{Node: "n1", Interface: "eth1"}, {Node: "srl1", Interface: "ethernet-1/1"}}, targets)
	require.Equal(t, captureLimits{duration: 90 * time.Second, packetLimit: 100, snapLength: 128}, limits)

	_, limits, err = parse("target=n1:eth1")
	require.NoError(t, err)
	require.Equal(t, captureLimits{}, limits, "no limits: until the client disconnects")

	for _, query := range []string{
		"", "duration=5s", "target=n1", "target=n1:eth1&duration=5", "target=n1:eth1&duration=-1s", "target=n1:eth1&duration=0s",
		"target=n1:eth1&packetLimit=0", "target=n1:eth1&packetLimit=x", "target=n1:eth1&snapLength=63", "target=n1:eth1&snapLength=1048577",
		strings.Repeat("target=n1:eth1&", maxCaptureTargets+1),
	} {
		_, _, err := parse(query)
		require.Error(t, err, query)
	}
}

func TestMatchCaptureTargets(t *testing.T) {
	available := []clablabruntime.CaptureInterface{
		{Node: "R1", Interface: "e1-1", Alias: "ethernet-1/1"},
		{Node: "R1", Interface: "e1-2"},
		{Node: "n2", Interface: "eth1"},
	}
	resolved, err := matchCaptureTargets(available, []capture.Target{
		{Node: "r1", Interface: "ethernet-1/1"}, {Node: "R1", Interface: "e1-2"}, {Node: "n2", Interface: "eth1"},
	})
	require.NoError(t, err)
	require.Equal(t, []capture.Target{{Node: "R1", Interface: "e1-1"}, {Node: "R1", Interface: "e1-2"}, {Node: "n2", Interface: "eth1"}}, resolved,
		"sanitized node names and aliases resolve to the names the capture carries")

	_, err = matchCaptureTargets(available, []capture.Target{{Node: "R1", Interface: "eth0"}})
	require.ErrorIs(t, err, errInvalidCaptureTarget)
	require.ErrorContains(t, err, "capturable: e1-1 (ethernet-1/1), e1-2")
	_, err = matchCaptureTargets(available, []capture.Target{{Node: "R1", Interface: "e1-1"}, {Node: "R1", Interface: "ethernet-1/1"}})
	require.ErrorContains(t, err, "more than once")
	_, err = matchCaptureTargets(available, []capture.Target{{Node: "n3", Interface: "eth1"}})
	require.ErrorContains(t, err, "no capturable lab link interface")
}

func TestCaptureErrorStatus(t *testing.T) {
	for err, want := range map[error]int{
		fmt.Errorf("%w: x", errInvalidCaptureTarget):                                                              http.StatusBadRequest,
		classifyLabCaptureError(errors.New(`node "n9" was not found in c9s lab ns/lab1`)):                         http.StatusBadRequest,
		classifyLabCaptureError(errors.New("c9s node ns/lab1/n1 has no pod; is it running?")):                     http.StatusConflict,
		errors.New(`pods "x" is forbidden: User "clab:bob" cannot create resource "pods/exec" in namespace "ns"`): http.StatusForbidden,
		fmt.Errorf("x: %w", clablabruntime.ErrUnsupportedRuntimeVersion):                                          http.StatusNotImplemented,
		errors.New("boom"): http.StatusInternalServerError,
	} {
		require.Equal(t, want, captureErrorStatus(err), err.Error())
	}
}

func TestCaptureInterfacesOnC9s(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()

	recorder := api.do(http.MethodGet, "/api/v1/labs/lab1/capture/interfaces", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.JSONEq(t, `[
		{"node":"n1","interface":"eth1","peerNode":"srl1","peerInterface":"e1-1"},
		{"node":"srl1","interface":"e1-1","alias":"ethernet-1/1","peerNode":"n1","peerInterface":"eth1"}
	]`, recorder.Body.String())
	calls := api.fake.CallsOf("capture-interfaces")
	require.Len(t, calls, 1)
	require.Equal(t, "c9s-lab1", calls[0].Namespace)
	require.Empty(t, calls[0].Nodes, "every running node")

	require.Equal(t, http.StatusNotFound, api.do(http.MethodGet, "/api/v1/labs/other/capture/interfaces", nil).Code)
}

func TestCaptureRoutesNeedALabRuntime(t *testing.T) {
	api := newC9sAPI(t)
	config.AppConfig.ClabRuntime = "docker"
	for _, route := range []struct{ method, target string }{
		{http.MethodGet, "/api/v1/labs/lab1/capture/interfaces"},
		{http.MethodGet, "/api/v1/labs/lab1/capture/stream?target=n1:eth1"},
	} {
		recorder := api.do(route.method, route.target, nil)
		require.Equal(t, http.StatusNotImplemented, recorder.Code, route.target)
		require.Contains(t, decodeError(t, recorder), "need the lab runtime c9s", route.target)
	}
}

func TestCaptureStreamFlushesAsItCaptures(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()
	release := make(chan struct{})
	var got clablabruntime.CaptureRequest
	api.fake.CaptureFunc = func(ctx context.Context, req clablabruntime.CaptureRequest, w io.Writer) error {
		got = req
		if _, err := w.Write([]byte("header|")); err != nil {
			return err
		}
		select {
		case <-release:
		case <-ctx.Done():
			return nil
		}
		_, err := w.Write([]byte("packet"))
		return err
	}
	server := api.server()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := api.get(ctx, server.URL+"/api/v1/labs/lab1/capture/stream?target=n1:eth1&target=srl1:ethernet-1/1&duration=5s&packetLimit=10&snapLength=96&download=1")
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "application/x-pcapng", response.Header.Get("Content-Type"))
	require.Equal(t, []string{"chunked"}, response.TransferEncoding)
	require.Regexp(t, `^attachment; filename="lab1-\d{8}T\d{6}Z\.pcapng"$`, response.Header.Get("Content-Disposition"))

	first := make([]byte, len("header|"))
	_, err = io.ReadFull(response.Body, first)
	require.NoError(t, err, "the first block arrives before the capture writes more")
	require.Equal(t, "header|", string(first))
	close(release)
	rest, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, "packet", string(rest))

	require.Equal(t, []clablabruntime.CaptureTarget{{Node: "n1", Interface: "eth1"}, {Node: "srl1", Interface: "e1-1"}}, got.Targets,
		"aliases resolve to interface names")
	require.Equal(t, 5*time.Second, got.Duration)
	require.Equal(t, 10, got.PacketLimit)
	require.Equal(t, 96, got.SnapLength)
	require.Equal(t, "lab1", got.Name)
	require.Equal(t, "c9s-lab1", api.fake.CallsOf("capture")[0].Namespace)

	// Without download there is no attachment header.
	release = make(chan struct{})
	close(release)
	response, err = api.get(ctx, server.URL+"/api/v1/labs/lab1/capture/stream?target=n1:eth1")
	require.NoError(t, err)
	_, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Empty(t, response.Header.Get("Content-Disposition"))
}

func TestCaptureStreamClientDisconnectCancelsTheCapture(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()
	ended := make(chan error, 1)
	api.fake.CaptureFunc = func(ctx context.Context, _ clablabruntime.CaptureRequest, w io.Writer) error {
		if _, err := w.Write([]byte("header")); err != nil {
			return err
		}
		<-ctx.Done()
		ended <- ctx.Err()
		return nil
	}
	server := api.server()

	ctx, cancel := context.WithCancel(context.Background())
	response, err := api.get(ctx, server.URL+"/api/v1/labs/lab1/capture/stream?target=n1:eth1")
	require.NoError(t, err)
	buffer := make([]byte, 6)
	_, err = io.ReadFull(response.Body, buffer)
	require.NoError(t, err)
	cancel()
	_ = response.Body.Close()

	select {
	case err := <-ended:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("the capture's context did not end when the client went away")
	}
}

func TestCaptureStreamErrorsBeforeTheFirstByte(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()
	api.fake.AddLab("c9s-foreign", "foreign", "someone-else", "", "x1")

	for _, tc := range []struct {
		query  string
		status int
		want   string
	}{
		{"", http.StatusBadRequest, "at least one target"},
		{"target=n1", http.StatusBadRequest, "<node>:<interface>"},
		{"target=n1:eth9", http.StatusBadRequest, "capturable: eth1"},
		{"target=n9:eth1", http.StatusBadRequest, "was not found"},
		{"target=n1:eth1&target=n1:eth1", http.StatusBadRequest, "more than once"},
		{"target=n1:eth1&duration=soon", http.StatusBadRequest, "invalid duration"},
	} {
		recorder := api.do(http.MethodGet, "/api/v1/labs/lab1/capture/stream?"+tc.query, nil)
		require.Equal(t, tc.status, recorder.Code, "%s: %s", tc.query, recorder.Body.String())
		require.Contains(t, decodeError(t, recorder), tc.want, tc.query)
	}
	require.Equal(t, http.StatusNotFound, api.do(http.MethodGet, "/api/v1/labs/foreign/capture/stream?target=x1:eth1", nil).Code,
		"another user's lab")
	require.Equal(t, http.StatusNotFound, api.do(http.MethodGet, "/api/v1/labs/nolab/capture/stream?target=x1:eth1", nil).Code)
	require.Empty(t, api.fake.CallsOf("capture"), "nothing was captured")

	for message, status := range map[string]int{
		`pods "lab1-n1-pod" is forbidden: User "clab:x" cannot create resource "pods/exec"`: http.StatusForbidden,
		"c9s node c9s-lab1/lab1/n1 has no pod; is it running?":                              http.StatusConflict,
		"clabwire exploded": http.StatusInternalServerError,
	} {
		api.fake.CaptureFunc = func(context.Context, clablabruntime.CaptureRequest, io.Writer) error {
			return errors.New(message)
		}
		recorder := api.do(http.MethodGet, "/api/v1/labs/lab1/capture/stream?target=n1:eth1", nil)
		require.Equal(t, status, recorder.Code, message)
		require.Contains(t, decodeError(t, recorder), message)
	}

	// An error after the first byte ends the stream; the status is already sent.
	api.fake.CaptureFunc = func(_ context.Context, _ clablabruntime.CaptureRequest, w io.Writer) error {
		_, _ = w.Write([]byte("partial"))
		return errors.New("clabwire failed late")
	}
	recorder := api.do(http.MethodGet, "/api/v1/labs/lab1/capture/stream?target=n1:eth1", nil)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, "partial", recorder.Body.String())
}

func TestCaptureRunsAsTheSignedInUser(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()
	identity := clablabruntime.Identity{User: "clab:" + api.username, Groups: []string{"clab:users"}}
	api.svc.SetLabScoper(staticScoper{scope: func(user, lab string) (string, clablabruntime.Identity) {
		return "c9s-lab1", identity
	}})
	recorder := api.do(http.MethodGet, "/api/v1/labs/lab1/capture/stream?target=n1:eth1", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	for _, op := range []string{"capture-interfaces", "capture"} {
		calls := api.fake.CallsOf(op)
		require.NotEmpty(t, calls, op)
		require.Equal(t, identity, calls[len(calls)-1].Identity, op)
	}
}

// staticScoper puts every lab in one namespace and acts with one identity.
type staticScoper struct {
	scope func(user, lab string) (string, clablabruntime.Identity)
}

func (s staticScoper) scopeOf(user, lab string) clab.LabScope {
	namespace, identity := s.scope(user, lab)
	return clab.LabScope{LabName: lab, Namespace: namespace, Owner: user, Identity: identity}
}

func (s staticScoper) ScopeForLab(_ context.Context, user, lab string) (clab.LabScope, error) {
	return s.scopeOf(user, lab), nil
}

func (s staticScoper) PrepareDeploy(_ context.Context, user, lab, _ string) (clab.LabScope, error) {
	return s.scopeOf(user, lab), nil
}

func (s staticScoper) ListScopes(_ context.Context, user string) ([]clab.LabScope, error) {
	return []clab.LabScope{s.scopeOf(user, "")}, nil
}

func (staticScoper) AfterDestroy(context.Context, clab.LabScope, bool) error { return nil }

func TestInspectInterfacesOnC9s(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()
	api.fake.AddLab("c9s-foreign", "foreign", "someone-else", "", "x1")

	recorder := api.do(http.MethodGet, "/api/v1/labs/lab1/interfaces", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var nodes models.ClabInspectInterfacesOutput
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &nodes))
	require.Len(t, nodes, 2)
	names := map[string][]string{}
	for _, node := range nodes {
		for _, iface := range node.Interfaces {
			names[node.NodeName] = append(names[node.NodeName], iface.Name+"/"+iface.Alias+"/"+iface.State)
		}
	}
	require.Equal(t, map[string][]string{
		"lab1-n1":   {"eth0//up", "eth1//up", "lo//unknown"},
		"lab1-srl1": {"eth0//up", "e1-1/ethernet-1/1/up", "lo//unknown"},
	}, names)
	require.Equal(t, 9500, nodes[0].Interfaces[1].Mtu)
	calls := api.fake.CallsOf("inspect-interfaces")
	require.Len(t, calls, 1)
	require.Equal(t, "c9s-lab1", calls[0].Namespace, "in the lab's namespace")
	require.Empty(t, calls[0].Nodes)

	// The node query filters like with Docker (part of the node name).
	recorder = api.do(http.MethodGet, "/api/v1/labs/lab1/interfaces?node=srl1", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	nodes = nil
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &nodes))
	require.Len(t, nodes, 1)
	require.Equal(t, "lab1-srl1", nodes[0].NodeName)

	require.Equal(t, http.StatusNotFound, api.do(http.MethodGet, "/api/v1/labs/foreign/interfaces", nil).Code, "another user's lab")
	require.Equal(t, http.StatusNotFound, api.do(http.MethodGet, "/api/v1/labs/gone/interfaces", nil).Code)
	require.Len(t, api.fake.CallsOf("inspect-interfaces"), 2)
}

func TestInspectInterfacesRunsAsTheSignedInUser(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()
	api.svc.SetLabScoper(staticScoper{scope: func(user, _ string) (string, clablabruntime.Identity) {
		return "c9s-lab1", clablabruntime.Identity{User: "clab:" + user, Groups: []string{"clab:users"}}
	}})
	recorder := api.do(http.MethodGet, "/api/v1/labs/lab1/interfaces", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	calls := api.fake.CallsOf("inspect-interfaces")
	require.Equal(t, "clab:"+api.username, calls[len(calls)-1].Identity.User)
	require.Equal(t, []string{"clab:users"}, calls[len(calls)-1].Identity.Groups)
}

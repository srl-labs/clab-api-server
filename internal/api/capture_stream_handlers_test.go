package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
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
		{http.MethodPost, "/api/v1/labs/lab1/capture/tickets"},
		{http.MethodGet, "/api/v1/capture/packetflix/abc"},
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

func mintTicket(t *testing.T, api *c9sAPI, body string) models.CaptureTicketResponse {
	t.Helper()
	recorder := api.do(http.MethodPost, "/api/v1/labs/lab1/capture/tickets", []byte(body))
	require.Equal(t, http.StatusCreated, recorder.Code, recorder.Body.String())
	var response models.CaptureTicketResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	return response
}

func TestCaptureTicketIsBoundToTheUserLabAndTargets(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()

	response := mintTicket(t, api, `{"targets":[{"node":"n1","interface":"eth1"},{"node":"srl1","interface":"ethernet-1/1"}],"duration":"30s"}`)
	require.Len(t, response.Ticket, 43, "256 bits, base64url")
	require.WithinDuration(t, time.Now().Add(60*time.Second), response.ExpiresAt, 2*time.Second)
	require.True(t, strings.HasPrefix(response.PacketflixURI, "packetflix:ws://example.com/api/v1/capture/packetflix/"+response.Ticket+"?container="),
		response.PacketflixURI)

	grant, err := captureTicketStore().Redeem(response.Ticket)
	require.NoError(t, err)
	require.Equal(t, capture.TicketGrant{
		Username: api.username, LabName: "lab1", Duration: 30 * time.Second,
		Targets: []capture.Target{{Node: "n1", Interface: "eth1"}, {Node: "srl1", Interface: "e1-1"}},
	}, grant)

	for body, want := range map[string]string{
		`{}`: "Invalid request body",
		`{"targets":[{"node":"n1","interface":"eth9"}]}`:                    "capturable: eth1",
		`{"targets":[{"node":"n1","interface":"eth1"}],"duration":"-5s"}`:   "invalid duration",
		`{"targets":[{"node":"n1 x","interface":"eth1"}]}`:                  "invalid node name",
		`{"targets":[{"node":"n1","interface":"eth1"}],"duration":"later"}`: "invalid duration",
	} {
		recorder := api.do(http.MethodPost, "/api/v1/labs/lab1/capture/tickets", []byte(body))
		require.Equal(t, http.StatusBadRequest, recorder.Code, body)
		require.Contains(t, decodeError(t, recorder), want, body)
	}
	api.fake.AddLab("c9s-foreign", "foreign", "someone-else", "", "x1")
	recorder := api.do(http.MethodPost, "/api/v1/labs/foreign/capture/tickets", []byte(`{"targets":[{"node":"x1","interface":"eth1"}]}`))
	require.Equal(t, http.StatusNotFound, recorder.Code, "no tickets for another user's lab")
	require.Zero(t, captureTicketStore().Pending())
}

// TestPacketflixTicketURIWorksForCshargextcap parses the URI the way cshargextcap's packetflix
// nif does (nif/packetflix.go and cli/target): it strips "packetflix:" and a trailing
// "/capture", requires a JSON container target, and csharg dials <path>/capture.
func TestPacketflixTicketURIWorksForCshargextcap(t *testing.T) {
	uri := packetflixTicketURI("wss", "clab.example.com:8443", "TICKET", "lab1",
		[]capture.Target{{Node: "srl1", Interface: "e1-1"}, {Node: "n1", Interface: "eth1"}})
	require.True(t, strings.HasPrefix(uri, "packetflix:wss://clab.example.com:8443/api/v1/capture/packetflix/TICKET?container="), uri)

	parsed, err := url.Parse(strings.TrimPrefix(uri, "packetflix:"))
	require.NoError(t, err)
	require.Equal(t, "wss", parsed.Scheme)
	container := parsed.Query().Get("container")
	var target struct {
		Name              string   `json:"name"`
		Type              string   `json:"type"`
		NetworkInterfaces []string `json:"network-interfaces"`
	}
	require.NoError(t, json.Unmarshal([]byte(container), &target))
	require.Equal(t, "lab1", target.Name)
	require.Equal(t, []string{"srl1:e1-1", "n1:eth1"}, target.NetworkInterfaces,
		"csharg skips its target discovery only with network interfaces")
	require.Empty(t, parsed.Query().Get("nif"), "without nif, cshargextcap uses the network interfaces")
	dialed := path.Join(strings.TrimSuffix(parsed.Path, "/capture"), "capture")
	require.Equal(t, "/api/v1/capture/packetflix/TICKET/capture", dialed)
}

func TestPublicEndpoint(t *testing.T) {
	previous := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previous })
	config.AppConfig.APIPort = "8080"

	request := func(remote string, tlsOn bool, headers map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "http://clab.example.com:8080/x", nil)
		r.RemoteAddr = remote
		if tlsOn {
			r.TLS = &tls.ConnectionState{}
		}
		for key, value := range headers {
			r.Header.Set(key, value)
		}
		return r
	}
	forwarded := map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "clab.public.example:443"}

	scheme, host := publicEndpoint(request("10.0.0.5:1234", false, nil))
	require.Equal(t, []string{"ws", "clab.example.com:8080"}, []string{scheme, host})
	scheme, host = publicEndpoint(request("10.0.0.5:1234", true, nil))
	require.Equal(t, []string{"wss", "clab.example.com:8080"}, []string{scheme, host})

	for _, trusted := range []string{"", "nil", "10.9.9.9", "192.168.0.0/16"} {
		config.AppConfig.TrustedProxies = trusted
		scheme, host = publicEndpoint(request("10.0.0.5:1234", false, forwarded))
		require.Equal(t, []string{"ws", "clab.example.com:8080"}, []string{scheme, host}, "untrusted %q: forwarded headers are ignored", trusted)
	}
	for _, trusted := range []string{"10.0.0.5", "10.0.0.0/8", "127.0.0.1, 10.0.0.0/24"} {
		config.AppConfig.TrustedProxies = trusted
		scheme, host = publicEndpoint(request("10.0.0.5:1234", false, forwarded))
		require.Equal(t, []string{"wss", "clab.public.example:443"}, []string{scheme, host}, trusted)
	}
	config.AppConfig.TrustedProxies = "10.0.0.5"
	scheme, host = publicEndpoint(request("10.0.0.5:1234", true, map[string]string{
		"X-Forwarded-Proto": "http", "X-Forwarded-Host": "evil/path?x",
	}))
	require.Equal(t, []string{"ws", "clab.example.com:8080"}, []string{scheme, host}, "an invalid forwarded host is ignored")
	scheme, host = publicEndpoint(request("10.0.0.5:1234", false, map[string]string{"X-Forwarded-Host": "[2001:db8::1]:8443, other"}))
	require.Equal(t, []string{"ws", "[2001:db8::1]:8443"}, []string{scheme, host})
}

// dialPacketflix connects like csharg's host client: a gorilla websocket dial of
// <ticket path>/capture with the container and nif query parameters and the Clustershark
// headers, no subprotocol and no bearer token.
func dialPacketflix(serverURL, packetflixURI string) (*websocket.Conn, *http.Response, error) {
	parsed, err := url.Parse(strings.TrimPrefix(packetflixURI, "packetflix:"))
	if err != nil {
		return nil, nil, err
	}
	base, _ := url.Parse(serverURL)
	parsed.Scheme = "ws"
	parsed.Host = base.Host
	parsed.Path = path.Join(strings.TrimSuffix(parsed.Path, "/capture"), "capture")
	query := parsed.Query()
	query.Set("nif", "srl1:e1-1")
	parsed.RawQuery = query.Encode()
	header := http.Header{
		"Clustershark-Container": {query.Get("container")},
		"Clustershark-Nif":       {"srl1:e1-1"},
	}
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	return dialer.Dial(parsed.String(), header)
}

func TestPacketflixWebsocketStreamsBinaryMessagesAndCloses(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()
	var got clablabruntime.CaptureRequest
	api.fake.CaptureFunc = func(_ context.Context, req clablabruntime.CaptureRequest, w io.Writer) error {
		got = req
		for _, block := range []string{"SHB", "IDB0", "IDB1", "EPB"} {
			if _, err := w.Write([]byte(block)); err != nil {
				return err
			}
		}
		return nil
	}
	server := api.server()
	ticket := mintTicket(t, api, `{"targets":[{"node":"srl1","interface":"ethernet-1/1"}],"duration":"2s"}`)

	// cshargextcap's target discovery answers empty and does not use up the ticket.
	response, err := http.Get(server.URL + captureTicketPath + ticket.Ticket + "/discover/mobyshark")
	require.NoError(t, err)
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.JSONEq(t, `{"containers":[]}`, string(body))
	// A plain GET without an upgrade neither.
	response, err = http.Get(server.URL + captureTicketPath + ticket.Ticket)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusBadRequest, response.StatusCode)

	conn, _, err := dialPacketflix(server.URL, ticket.PacketflixURI)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	var messages []string
	for {
		messageType, data, err := conn.ReadMessage()
		if err != nil {
			var closeErr *websocket.CloseError
			require.ErrorAs(t, err, &closeErr)
			require.Equal(t, websocket.CloseNormalClosure, closeErr.Code)
			break
		}
		require.Equal(t, websocket.BinaryMessage, messageType)
		messages = append(messages, string(data))
	}
	require.Equal(t, []string{"SHB", "IDB0", "IDB1", "EPB"}, messages, "one binary message per write, in order")
	require.Equal(t, []clablabruntime.CaptureTarget{{Node: "srl1", Interface: "e1-1"}}, got.Targets, "the ticket's targets, not the query's")
	require.Equal(t, 2*time.Second, got.Duration)

	// A used ticket is refused before the upgrade.
	_, response, err = dialPacketflix(server.URL, ticket.PacketflixURI)
	require.ErrorIs(t, err, websocket.ErrBadHandshake)
	require.Equal(t, http.StatusNotFound, response.StatusCode)
	require.Len(t, api.fake.CallsOf("capture"), 1)
}

func TestPacketflixClientCloseStopsTheCapture(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()
	ended := make(chan error, 1)
	api.fake.CaptureFunc = func(ctx context.Context, _ clablabruntime.CaptureRequest, w io.Writer) error {
		if _, err := w.Write([]byte("SHB")); err != nil {
			return err
		}
		<-ctx.Done()
		ended <- ctx.Err()
		return nil
	}
	server := api.server()
	ticket := mintTicket(t, api, `{"targets":[{"node":"n1","interface":"eth1"}]}`)

	conn, _, err := dialPacketflix(server.URL, ticket.PacketflixURI)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, data, err := conn.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, "SHB", string(data))

	// cshargextcap stops with a normal close ("ciao") and waits for the answer.
	require.NoError(t, conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "ciao")))
	_, _, err = conn.ReadMessage()
	var closeErr *websocket.CloseError
	require.ErrorAs(t, err, &closeErr, "the server answers the close")
	require.Equal(t, websocket.CloseNormalClosure, closeErr.Code)
	select {
	case err := <-ended:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("the capture did not stop when the client closed")
	}

	// A client that just disconnects stops the capture as well.
	ticket = mintTicket(t, api, `{"targets":[{"node":"n1","interface":"eth1"}]}`)
	conn, _, err = dialPacketflix(server.URL, ticket.PacketflixURI)
	require.NoError(t, err)
	_, _, err = conn.ReadMessage()
	require.NoError(t, err)
	_ = conn.UnderlyingConn().Close()
	select {
	case err := <-ended:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("the capture did not stop when the client disconnected")
	}
}

func TestPacketflixCaptureFailureClosesWithTheError(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()
	api.fake.CaptureFunc = func(context.Context, clablabruntime.CaptureRequest, io.Writer) error {
		return errors.New(`pods "lab1-n1-pod" is forbidden: ` + strings.Repeat("x", 200))
	}
	server := api.server()
	ticket := mintTicket(t, api, `{"targets":[{"node":"n1","interface":"eth1"}]}`)
	conn, _, err := dialPacketflix(server.URL, ticket.PacketflixURI)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, _, err = conn.ReadMessage()
	var closeErr *websocket.CloseError
	require.ErrorAs(t, err, &closeErr)
	require.Equal(t, websocket.CloseInternalServerErr, closeErr.Code)
	require.True(t, strings.HasPrefix(closeErr.Text, `pods "lab1-n1-pod" is forbidden`), closeErr.Text)
	require.LessOrEqual(t, len(closeErr.Text), 123)
}

func TestPacketflixTicketChecksItsUserAndLab(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()
	var captured atomic.Int32
	api.fake.CaptureFunc = func(context.Context, clablabruntime.CaptureRequest, io.Writer) error {
		captured.Add(1)
		return nil
	}
	server := api.server()
	store := captureTicketStore()

	// A ticket of a user who cannot reach the lab, and one for a lab that is gone, are refused
	// (and used up) before the upgrade.
	for _, grant := range []capture.TicketGrant{
		{Username: "c9stest-nobody", LabName: "lab1", Targets: []capture.Target{{Node: "n1", Interface: "eth1"}}},
		{Username: api.username, LabName: "gone", Targets: []capture.Target{{Node: "n1", Interface: "eth1"}}},
	} {
		ticket, err := store.Mint(grant)
		require.NoError(t, err)
		uri := packetflixTicketURI("ws", "unused", ticket.ID, grant.LabName, grant.Targets)
		_, response, err := dialPacketflix(server.URL, uri)
		require.ErrorIs(t, err, websocket.ErrBadHandshake, grant.Username)
		require.Equal(t, http.StatusNotFound, response.StatusCode, grant.Username)
		_, err = store.Redeem(ticket.ID)
		require.ErrorIs(t, err, capture.ErrTicketInvalid)
	}
	require.Zero(t, captured.Load())
}

func TestPacketflixTicketRedeemsOnceUnderConcurrentConnects(t *testing.T) {
	api := newC9sAPI(t)
	api.captureLab()
	api.fake.CaptureFunc = func(_ context.Context, _ clablabruntime.CaptureRequest, w io.Writer) error {
		_, err := w.Write([]byte("SHB"))
		return err
	}
	server := api.server()
	ticket := mintTicket(t, api, `{"targets":[{"node":"n1","interface":"eth1"}]}`)

	results := make(chan int, 8)
	for range 8 {
		go func() {
			conn, response, err := dialPacketflix(server.URL, ticket.PacketflixURI)
			if err != nil {
				results <- response.StatusCode
				return
			}
			_, _, _ = conn.ReadMessage()
			_ = conn.Close()
			results <- http.StatusSwitchingProtocols
		}()
	}
	statuses := map[int]int{}
	for range 8 {
		statuses[<-results]++
	}
	require.Equal(t, map[int]int{http.StatusSwitchingProtocols: 1, http.StatusNotFound: 7}, statuses)
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

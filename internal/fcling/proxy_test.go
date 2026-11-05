package fcling

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAllowedAPI(t *testing.T) {
	allowed := []struct{ method, path string }{
		{http.MethodGet, "status"},
		{http.MethodGet, "/status"},
		{http.MethodGet, "reports"},
		{http.MethodGet, "reports/bgp-peers"},
		{http.MethodGet, "checks"},
		{http.MethodGet, "incidents"},
		{http.MethodGet, "acks"},
		{http.MethodGet, "history"},
		{http.MethodGet, "drift"},
		{http.MethodGet, "configs"},
		{http.MethodGet, "configs/diff"},
		{http.MethodGet, "baselines"},
		{http.MethodGet, "lenses"},
		{http.MethodGet, "lenses/path"},
		{http.MethodGet, "topology"},
		{http.MethodGet, "events"},
		{http.MethodPost, "acks"},
		{http.MethodPost, "baselines"},
		{http.MethodDelete, "acks"},
		{http.MethodDelete, "baselines/pre-change"},
		{http.MethodDelete, "baselines/2026-10-18T14:02:11"},
		{http.MethodDelete, "baselines/before the change"},
	}
	for _, request := range allowed {
		require.True(t, AllowedAPI(request.method, request.path), "%s %s", request.method, request.path)
	}

	refused := []struct{ method, path string }{
		// Chat, MCP and what describes them.
		{http.MethodPost, "chat"},
		{http.MethodGet, "chat"},
		{http.MethodGet, "mcp"},
		{http.MethodPost, "mcp"},
		{http.MethodGet, "../mcp"},
		{http.MethodPost, "../mcp"},
		{http.MethodGet, "openapi.json"},
		{http.MethodGet, ""},
		{http.MethodGet, "/"},
		// Out of a report's name.
		{http.MethodGet, "reports/../chat"},
		{http.MethodPost, "reports/../chat"},
		{http.MethodGet, "reports/.."},
		{http.MethodGet, "reports/."},
		{http.MethodGet, "reports/"},
		{http.MethodGet, "reports/a/b"},
		{http.MethodGet, "lenses/../../mcp"},
		{http.MethodDelete, "baselines/../acks"},
		// Right path, wrong method.
		{http.MethodPost, "status"},
		{http.MethodPost, "reports/bgp-peers"},
		{http.MethodDelete, "history"},
		{http.MethodDelete, "baselines"},
		{http.MethodPost, "baselines/x"},
		{http.MethodPut, "acks"},
		{http.MethodPatch, "acks"},
		{http.MethodHead, "status"},
		{http.MethodOptions, "status"},
		// Near misses.
		{http.MethodGet, "status/"},
		{http.MethodGet, "configs/other"},
		{http.MethodGet, "topology/x"},
	}
	for _, request := range refused {
		require.False(t, AllowedAPI(request.method, request.path), "%s %s", request.method, request.path)
	}
}

// proxied serves the proxy to an engine at engine, for a path below its /api.
func proxied(t *testing.T, engine http.Handler, token, path string) *httptest.Server {
	t.Helper()
	upstream := httptest.NewServer(engine)
	t.Cleanup(upstream.Close)
	target := Target{Host: strings.TrimPrefix(upstream.URL, "http://"), Token: token}
	front := httptest.NewServer(NewProxy(target, path))
	t.Cleanup(front.Close)
	return front
}

func TestProxyUsesTheEnginesTokenOnly(t *testing.T) {
	var seen *http.Request
	var body string
	front := proxied(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Clone(context.Background())
		data, _ := io.ReadAll(r.Body)
		body = string(data)
		w.Header().Set("Set-Cookie", "fcli_token=engine-token; Path=/; HttpOnly")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}), "engine-token", "/reports/bgp-peers")

	request, err := http.NewRequest(http.MethodPost, front.URL+"/anything?table=1&node=leaf1&node=leaf2&token=server-jwt", strings.NewReader(`{"note":"x"}`))
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer server-jwt")
	request.Header.Set("Cookie", "session=server-cookie")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Last-Event-ID", "42")

	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	answer, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, response.StatusCode)
	require.JSONEq(t, `{"ok":true}`, string(answer))
	require.Empty(t, response.Header.Get("Set-Cookie"), "the engine's cookie stays here")

	require.Equal(t, "Bearer engine-token", seen.Header.Get("Authorization"))
	require.Empty(t, seen.Header.Get("Cookie"))
	require.Equal(t, "/api/reports/bgp-peers", seen.URL.Path)
	require.Empty(t, seen.URL.Query().Get("token"))
	require.Equal(t, "1", seen.URL.Query().Get("table"))
	require.Equal(t, []string{"leaf1", "leaf2"}, seen.URL.Query()["node"])
	require.Equal(t, "42", seen.Header.Get("Last-Event-ID"))
	require.Equal(t, `{"note":"x"}`, body)
}

func TestProxyStreamsEventsAsTheyHappen(t *testing.T) {
	release := make(chan struct{})
	front := proxied(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: status\ndata: {\"type\":\"status\"}\n\n"))
		w.(http.Flusher).Flush()
		<-release
		_, _ = w.Write([]byte("event: change\ndata: {\"type\":\"change\"}\n\n"))
	}), "engine-token", "events")
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, front.URL, nil)
	require.NoError(t, err)
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, "text/event-stream", response.Header.Get("Content-Type"))

	// The first event arrives while the engine still holds the stream open.
	line, err := bufio.NewReader(response.Body).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "event: status\n", line)
}

func TestProxyAnswersJSONWhenTheEngineIsGone(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	host := strings.TrimPrefix(gone.URL, "http://")
	gone.Close()
	front := httptest.NewServer(NewProxy(Target{Host: host, Token: "x"}, "status"))
	defer front.Close()

	response, err := http.Get(front.URL)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadGateway, response.StatusCode)
	require.Contains(t, string(body), `"error":"the fcling engine is not reachable`)
}

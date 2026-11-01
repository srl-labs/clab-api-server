package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/srl-labs/clab-api-server/internal/config"
)

func TestParseLifecycleTimeoutQuery(t *testing.T) {
	for query, want := range map[string]time.Duration{
		"":            0,
		"timeout=":    0,
		"timeout=30s": 30 * time.Second,
		"timeout=15m": 15 * time.Minute,
		"timeout=2h":  2 * time.Hour,
	} {
		c, recorder := newQueryContext(query)
		got, ok := parseLifecycleTimeoutQuery(c)
		require.True(t, ok, "%s rejected: %s", query, recorder.Body.String())
		require.Equal(t, want, got, query)
	}

	for _, query := range []string{"timeout=10", "timeout=-5m", "timeout=0s", "timeout=soon", "timeout=2h1s"} {
		c, recorder := newQueryContext(query)
		_, ok := parseLifecycleTimeoutQuery(c)
		require.False(t, ok, "%s accepted", query)
		require.Equal(t, http.StatusBadRequest, recorder.Code, query)
	}
}

func TestLifecycleRequestTimeoutFollowsContainerlabsTimeout(t *testing.T) {
	previous := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previous })

	config.AppConfig.ClabRuntime = "docker"
	require.Equal(t, 10*time.Minute, lifecycleRequestTimeout(0, 1), "Docker keeps its 10 minute request limit")
	require.Equal(t, 35*time.Minute, lifecycleRequestTimeout(30*time.Minute, 1))

	config.AppConfig.ClabRuntime = config.RuntimeC9s
	require.Equal(t, 15*time.Minute, lifecycleRequestTimeout(0, 1), "c9s waits containerlab's 10 minutes")
	require.Equal(t, 25*time.Minute, lifecycleRequestTimeout(0, 2), "a redeploy destroys, then deploys")
	require.Equal(t, 125*time.Minute, lifecycleRequestTimeout(time.Hour, 2))
}

func TestFormatDuration(t *testing.T) {
	require.Equal(t, "10m", formatDuration(10*time.Minute))
	require.Equal(t, "2h", formatDuration(2*time.Hour))
	require.Equal(t, "1h30m", formatDuration(90*time.Minute))
	require.Equal(t, "45s", formatDuration(45*time.Second))
	require.Equal(t, "1m30s", formatDuration(90*time.Second))
}

func TestLifecycleTimeoutReachesTheLabRuntime(t *testing.T) {
	api := newC9sAPI(t)
	body := []byte(`{"topologyContent":{"name":"slow-lab","topology":{"nodes":{"n1":{"kind":"linux","image":"alpine"}}}}}`)

	recorder := api.do(http.MethodPost, "/api/v1/labs?timeout=3h", body)
	require.Equal(t, http.StatusBadRequest, recorder.Code, recorder.Body.String())
	require.Empty(t, api.fake.CallsOf("deploy"))

	recorder = api.do(http.MethodPost, "/api/v1/labs", body)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Equal(t, 10*time.Minute, api.fake.CallsOf("deploy")[0].Timeout, "containerlab's c9s default")

	// A redeploy destroys the lab, then deploys it again (reconfiguring, which destroys
	// first as well): every call gets the timeout.
	recorder = api.do(http.MethodPut, "/api/v1/labs/slow-lab?timeout=45m", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	for _, call := range api.fake.CallsOf("destroy") {
		require.Equal(t, 45*time.Minute, call.Timeout)
	}
	require.Equal(t, 45*time.Minute, api.fake.CallsOf("deploy")[1].Timeout)

	recorder = api.do(http.MethodDelete, "/api/v1/labs/slow-lab?timeout=30s", nil)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	destroys := api.fake.CallsOf("destroy")
	require.Equal(t, 30*time.Second, destroys[len(destroys)-1].Timeout)
}

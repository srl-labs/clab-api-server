package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

func TestParseNodeNameList(t *testing.T) {
	nodes, err := parseNodeNameList("leaf1, spine.1,leaf1,,node_2")
	require.NoError(t, err)
	require.Equal(t, []string{"leaf1", "spine.1", "node_2"}, nodes)

	for _, raw := range []string{"", ",", " , ", "a;b", "a/b", "a b", "$(id)", "a|b"} {
		_, err := parseNodeNameList(raw)
		require.Error(t, err, raw)
	}
}

func TestParseLabelFilter(t *testing.T) {
	for raw, want := range map[string]clab.LabelFilter{
		"role=spine":                   {Key: "role", Value: "spine"},
		"clab-node-kind=nokia_srlinux": {Key: "clab-node-kind", Value: "nokia_srlinux"},
		"com.example/tier=edge":        {Key: "com.example/tier", Value: "edge"},
		" group = core ":               {Key: "group", Value: "core"},
		"image=ghcr.io/nokia/srl:25.3": {Key: "image", Value: "ghcr.io/nokia/srl:25.3"},
	} {
		got, err := parseLabelFilter(raw)
		require.NoError(t, err, raw)
		require.Equal(t, want, got, raw)
	}

	for _, raw := range []string{"", "role", "=spine", "role=", "role=a=b", "role=a,b", "ro le=x", "role=a b", "-role=x", "role=$(id)", "role=a;b"} {
		_, err := parseLabelFilter(raw)
		require.Error(t, err, raw)
	}
}

func TestParseExecFilterQuery(t *testing.T) {
	c, recorder := newQueryContext("nodes=leaf1,leaf2&label=role%3Dleaf&label=tier%3D1")
	filters, ok := parseExecFilterQuery(c)
	require.True(t, ok, recorder.Body.String())
	require.Equal(t, []string{"leaf1", "leaf2"}, filters.nodes)
	require.Equal(t, []clab.LabelFilter{{Key: "role", Value: "leaf"}, {Key: "tier", Value: "1"}}, filters.labels)
	require.True(t, filters.active())

	c, _ = newQueryContext("")
	filters, ok = parseExecFilterQuery(c)
	require.True(t, ok)
	require.False(t, filters.active())

	tooMany := ""
	for i := 0; i <= maxExecLabelFilters; i++ {
		tooMany += fmt.Sprintf("label=k%d%%3Dv&", i)
	}
	for _, query := range []string{"nodes=", "nodes=a%3Bb", "label=bad", "label=a%3Db%2Cc", tooMany} {
		c, recorder := newQueryContext(query)
		_, ok := parseExecFilterQuery(c)
		require.False(t, ok, query)
		require.Equal(t, http.StatusBadRequest, recorder.Code, query)
	}
}

func TestLifecycleHelpers(t *testing.T) {
	require.Equal(t, "Lab 'demo' nodes started successfully.", lifecycleSuccessMessage("demo", clab.NodeLifecycleActionStart, nil))
	require.Equal(t, "Lab 'demo' nodes r1, r2 stopped successfully.", lifecycleSuccessMessage("demo", clab.NodeLifecycleActionStop, []string{"r1", "r2"}))

	wrapped := fmt.Errorf("failed to start lab 'demo': %w", fmt.Errorf("failed to start node(s): %w", clab.ErrIncorrectInput))
	require.Equal(t, http.StatusBadRequest, lifecycleErrorStatus(wrapped))
	require.Equal(t, http.StatusInternalServerError, lifecycleErrorStatus(errors.New("boom")))

	c, _ := newQueryContext("nodeFilter=r1,r2")
	nodes, ok := parseLifecycleNodeFilter(c)
	require.True(t, ok)
	require.Equal(t, []string{"r1", "r2"}, nodes)

	c, _ = newQueryContext("")
	nodes, ok = parseLifecycleNodeFilter(c)
	require.True(t, ok)
	require.Nil(t, nodes)
}

func TestValidateSnapshotRequest(t *testing.T) {
	nodes, timeout, outputDir, err := validateSnapshotRequest(models.SnapshotSaveRequest{})
	require.NoError(t, err)
	require.Nil(t, nodes)
	require.Equal(t, clab.DefaultSnapshotTimeout, timeout)
	require.Equal(t, "snapshots", outputDir)

	dir, tmo := "backups/vm", "10m"
	nodes, timeout, outputDir, err = validateSnapshotRequest(models.SnapshotSaveRequest{
		Nodes: []string{"r1", "r2", "r1"}, OutputDir: &dir, Timeout: &tmo,
	})
	require.NoError(t, err)
	require.Equal(t, []string{"r1", "r2"}, nodes)
	require.Equal(t, 10*time.Minute, timeout)
	require.Equal(t, "backups/vm", outputDir)

	blank, huge, tiny, junk := "  ", "31m", "500ms", "soon"
	for _, req := range []models.SnapshotSaveRequest{
		{OutputDir: &blank},
		{Timeout: &huge},
		{Timeout: &tiny},
		{Timeout: &junk},
		{Timeout: &blank},
		{Nodes: []string{"r1;rm"}},
		{Nodes: []string{""}},
	} {
		_, _, _, err := validateSnapshotRequest(req)
		require.Error(t, err)
	}
}

func TestBuildSnapshotSaveResponse(t *testing.T) {
	scope, _, _ := newTestLabPathScope(t)
	outputDir, err := scope.resolve("snapshots")
	require.NoError(t, err)

	response := buildSnapshotSaveResponse(outputDir, []clab.SnapshotNodeResult{
		{Node: "r1", Status: clab.SnapshotStatusSuccess, Path: filepath.Join(outputDir.Path, "r1.tar"), SizeBytes: 123, Duration: 1500 * time.Millisecond},
		{Node: "r2", Status: clab.SnapshotStatusFailed, Path: filepath.Join(outputDir.Path, "r2.tar"), Error: "timeout", Duration: time.Second},
		{Node: "srl", Status: clab.SnapshotStatusSkipped, Reason: "not a vrnetlab node"},
	})
	require.Equal(t, "lab1/snapshots", response.OutputDir)
	require.Equal(t, "1 succeeded, 1 failed, 1 skipped", response.Summary)
	require.Equal(t, []models.SnapshotNodeResult{
		{Node: "r1", Status: "success", Path: "lab1/snapshots/r1.tar", SizeBytes: 123, DurationMs: 1500},
		{Node: "r2", Status: "failed", Error: "timeout", DurationMs: 1000},
		{Node: "srl", Status: "skipped", Reason: "not a vrnetlab node"},
	}, response.Results)

	raw, err := json.Marshal(response)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Contains(t, decoded, "outputDir")
	require.Contains(t, decoded, "results")
	require.Contains(t, decoded, "summary")

	empty := buildSnapshotSaveResponse(outputDir, nil)
	raw, err = json.Marshal(empty)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"results":[]`)
}

func TestHealthAdvertisesFeatures(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/health", nil)
	HealthCheckHandler(c)

	require.Equal(t, http.StatusOK, recorder.Code)
	var response models.HealthResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	require.Subset(t, response.Features, []string{
		"exec-filters",
		"lab-lifecycle-node-filter",
		"save-copy",
		"inspect-details",
		"snapshot-save",
		"deploy-restore",
	}, response.Features)
}

func TestLabOpsHandlersRejectInvalidInput(t *testing.T) {
	router, _ := workspaceTestRouter(t)
	router.POST("/labs/:labName/exec", ExecCommandHandler)
	router.POST("/labs/:labName/start", StartLabNodesHandler)
	router.POST("/labs/:labName/stop", StopLabNodesHandler)
	router.POST("/labs/:labName/restart", RestartLabNodesHandler)
	router.POST("/labs/:labName/save", SaveLabConfigHandler)
	router.GET("/labs/:labName", InspectLabHandler)
	router.POST("/labs/:labName/snapshots", SaveLabSnapshotsHandler)

	execBody := []byte(`{"command":"ip a"}`)
	for _, tc := range []struct {
		name, method, target string
		body                 []byte
		wantError            string
	}{
		{"exec bad label", http.MethodPost, "/labs/demo/exec?label=role", execBody, "label"},
		{"exec label comma", http.MethodPost, "/labs/demo/exec?label=" + url.QueryEscape("role=a,b"), execBody, "label"},
		{"exec bad nodes", http.MethodPost, "/labs/demo/exec?nodes=" + url.QueryEscape("a;b"), execBody, "nodes"},
		{"exec empty nodes", http.MethodPost, "/labs/demo/exec?nodes=", execBody, "nodes"},
		{"exec nodeFilter with nodes", http.MethodPost, "/labs/demo/exec?nodeFilter=clab-demo-a&nodes=a", execBody, "cannot be combined"},
		{"exec nodeFilter with label", http.MethodPost, "/labs/demo/exec?nodeFilter=clab-demo-a&label=" + url.QueryEscape("role=x"), execBody, "cannot be combined"},
		{"start bad nodeFilter", http.MethodPost, "/labs/demo/start?nodeFilter=" + url.QueryEscape("a b"), nil, "nodeFilter"},
		{"stop empty nodeFilter", http.MethodPost, "/labs/demo/stop?nodeFilter=", nil, "nodeFilter"},
		{"restart bad nodeFilter", http.MethodPost, "/labs/demo/restart?nodeFilter=" + url.QueryEscape("a/b"), nil, "nodeFilter"},
		{"save empty copy", http.MethodPost, "/labs/demo/save?copy=", nil, "copy"},
		{"save blank copy", http.MethodPost, "/labs/demo/save?copy=%20%20", nil, "copy"},
		{"inspect bad details", http.MethodGet, "/labs/demo?details=maybe", nil, "details"},
		{"snapshot bad json", http.MethodPost, "/labs/demo/snapshots", []byte(`{"nodes":`), "Invalid request body"},
		{"snapshot bad timeout", http.MethodPost, "/labs/demo/snapshots", []byte(`{"timeout":"2h"}`), "timeout"},
		{"snapshot blank outputDir", http.MethodPost, "/labs/demo/snapshots", []byte(`{"outputDir":" "}`), "outputDir"},
		{"snapshot bad node", http.MethodPost, "/labs/demo/snapshots", []byte(`{"nodes":["r1;id"]}`), "node"},
		{"snapshot bad lab", http.MethodPost, "/labs/bad%20lab/snapshots", nil, "lab name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := performWorkspaceRequest(router, tc.method, tc.target, tc.body)
			require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
			require.Contains(t, response.Body.String(), tc.wantError)
		})
	}
}

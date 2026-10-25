package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

func renderTestRouter(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	router, root := workspaceTestRouter(t)
	previous := GetClabService()
	SetClabService(clab.NewService())
	t.Cleanup(func() { SetClabService(previous) })
	router.GET("/labs/:labName/topology/rendered", RenderTopologyHandler)
	return router, root
}

func renderQuery(path, varsPath string) string {
	query := url.Values{"path": {path}}
	if varsPath != "" {
		query.Set("varsPath", varsPath)
	}
	return "/labs/fabric/topology/rendered?" + query.Encode()
}

// requireJSONError checks for a JSON ErrorResponse; clients tell a missing
// route (plain-text 404) apart from a missing file by this shape.
func requireJSONError(t *testing.T, recorder *httptest.ResponseRecorder, status int) string {
	t.Helper()
	require.Equal(t, status, recorder.Code, recorder.Body.String())
	require.Contains(t, recorder.Header().Get("Content-Type"), "application/json")
	var errResponse models.ErrorResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &errResponse))
	require.NotEmpty(t, errResponse.Error)
	return errResponse.Error
}

func currentTestUsername(t *testing.T) string {
	t.Helper()
	currentUser, err := user.Current()
	require.NoError(t, err)
	return currentUser.Username
}

func TestListTopologyEntriesIncludesTemplates(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"flat.clab.gotmpl":                           "name: {{ .name }}\n",
		"single/topology.clab.gotmpl":                "name: {{ .name }}\n",
		"repo/labs/literal.clab.gotmpl":              "name: literal-lab # fixed\ntopology:\n{{- range .nodes }}\n  {{ . }}: {}\n{{- end }}\n",
		"repo/labs/quoted.CLAB.GOTMPL":               "{{ $x := 1 }}\nname: \"quoted-lab\"\n",
		"repo/labs/templated-name.clab.gotmpl":       "name: {{ .name }}\ntopology: {}\n",
		"repo/labs/env-name.clab.gotmpl":             "name: ${LAB_NAME:=env}\n",
		"repo/labs/.hidden.clab.gotmpl":              "name: hidden\n",
		"repo/labs/plain.clab.yml":                   "name: plain-lab\n",
		"repo/labs/fabric.clab_vars.yml":             "name: fabric\n",
		"repo/labs/clab_templates/x.gotmpl":          "{{ define \"x\" }}{{ end }}\n",
		"repo/labs/lab.clab.gotmpl.annotations.json": "{}",
		"repo/labs/lab.clab.gotmpl":                  "name: annotated\n",
	}
	for path, content := range files {
		writeTopologyFixture(t, root, path, content)
	}

	entries, err := listTopologyEntries(root)
	require.NoError(t, err)
	got := map[string]models.TopologyEntry{}
	for _, entry := range entries {
		got[entry.YamlFileName] = entry
	}
	expected := map[string]string{
		"flat.clab.gotmpl":                     "flat",
		"single/topology.clab.gotmpl":          "single",
		"repo/labs/literal.clab.gotmpl":        "literal-lab",
		"repo/labs/quoted.CLAB.GOTMPL":         "quoted-lab",
		"repo/labs/templated-name.clab.gotmpl": "templated-name",
		"repo/labs/env-name.clab.gotmpl":       "env-name",
		"repo/labs/plain.clab.yml":             "plain-lab",
		"repo/labs/lab.clab.gotmpl":            "annotated",
	}
	require.Len(t, got, len(expected))
	for path, labName := range expected {
		require.Equal(t, labName, got[path].LabName, path)
	}
	require.True(t, got["repo/labs/lab.clab.gotmpl"].HasAnnotations)
	require.Equal(t, "repo/labs/lab.clab.gotmpl.annotations.json", got["repo/labs/lab.clab.gotmpl"].AnnotationsFileName)
}

func TestListTopologyEntriesExpandsGitNameTokens(t *testing.T) {
	root := t.TempDir()
	repoDir := filepath.Join(root, "repo", "labs")
	writeTopologyFixture(t, root, "repo/labs/a.clab.gotmpl", "name: lab-__gitBranch__-__gitHash__\n")
	writeTopologyFixture(t, root, "repo/labs/b.clab.yml", "name: b-__gitBranch__\n")
	writeTopologyFixture(t, root, "plain/labs/a.clab.yml", "name: c-__gitHash__\n")
	writeTopologyFixture(t, root, "plain/labs/b.clab.yml", "name: d\n")

	repo, err := gogit.PlainInit(repoDir, false)
	require.NoError(t, err)
	worktree, err := repo.Worktree()
	require.NoError(t, err)
	_, err = worktree.Add("a.clab.gotmpl")
	require.NoError(t, err)
	hash, err := worktree.Commit("initial", &gogit.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	})
	require.NoError(t, err)

	entries, err := listTopologyEntries(root)
	require.NoError(t, err)
	got := map[string]string{}
	for _, entry := range entries {
		got[entry.YamlFileName] = entry.LabName
	}
	require.Equal(t, "lab-master-"+hash.String()[:7], got["repo/labs/a.clab.gotmpl"])
	require.Equal(t, "b-master", got["repo/labs/b.clab.yml"])
	require.Equal(t, "c-none", got["plain/labs/a.clab.yml"])
}

func TestRenderTopologyHandler(t *testing.T) {
	router, root := renderTestRouter(t)
	writeTopologyFixture(t, root, "repo/labs/fabric.clab.gotmpl", `name: {{ .name }}
topology:
  defaults:
    image: ${CLAB_API_SERVER_RENDER_HANDLER_IMAGE:=alpine:3}
  nodes:
{{- range .nodes }}
{{ template "node.gotmpl" . }}
{{- end }}
`)
	writeTopologyFixture(t, root, "repo/labs/clab_templates/node.gotmpl", "    {{ . }}:\n      kind: linux\n")
	writeTopologyFixture(t, root, "repo/labs/fabric.clab_vars.yml", "name: fabric\nnodes: [n1, n2]\n")
	writeTopologyFixture(t, root, "repo/common/prod.yml", "name: prod-fabric\nnodes: [p1]\n")

	rendered := performWorkspaceRequest(router, http.MethodGet, renderQuery("repo/labs/fabric.clab.gotmpl", ""), nil)
	require.Equal(t, http.StatusOK, rendered.Code, rendered.Body.String())
	var response models.RenderedTopologyResponse
	require.NoError(t, json.Unmarshal(rendered.Body.Bytes(), &response))
	require.Equal(t, "repo/labs/fabric.clab.gotmpl", response.Path)
	require.Equal(t, "fabric", response.LabName)
	require.Equal(t, []string{"fabric.clab_vars.yml"}, response.VarsFiles)
	require.Empty(t, response.Error)
	require.Contains(t, response.Content, "image: alpine:3")
	require.Contains(t, response.Content, "    n2:\n      kind: linux")

	explicit := performWorkspaceRequest(router, http.MethodGet, renderQuery("repo/labs/fabric.clab.gotmpl", "../common/prod.yml"), nil)
	require.Equal(t, http.StatusOK, explicit.Code, explicit.Body.String())
	response = models.RenderedTopologyResponse{}
	require.NoError(t, json.Unmarshal(explicit.Body.Bytes(), &response))
	require.Equal(t, "prod-fabric", response.LabName)
	require.Equal(t, []string{"../common/prod.yml"}, response.VarsFiles)
	require.Contains(t, response.Content, "    p1:\n")
	require.NotContains(t, response.Content, "n1:")

	// Content containerlab rejects is still returned.
	writeTopologyFixture(t, root, "repo/labs/strict.clab.yml", "name: strict\nunknown: true\n")
	strict := performWorkspaceRequest(router, http.MethodGet, renderQuery("repo/labs/strict.clab.yml", ""), nil)
	require.Equal(t, http.StatusOK, strict.Code, strict.Body.String())
	response = models.RenderedTopologyResponse{}
	require.NoError(t, json.Unmarshal(strict.Body.Bytes(), &response))
	require.Equal(t, "name: strict\nunknown: true\n", response.Content)
	require.Equal(t, "strict", response.LabName)
	require.Equal(t, []string{}, response.VarsFiles)
	require.NotEmpty(t, response.Error)
}

func TestRenderTopologyHandlerErrors(t *testing.T) {
	router, root := renderTestRouter(t)
	writeTopologyFixture(t, root, "repo/labs/broken.clab.gotmpl", "name: {{ .name \n")
	writeTopologyFixture(t, root, "repo/labs/ok.clab.gotmpl", "name: ok\n")
	writeTopologyFixture(t, root, "repo/labs/badvars.clab.gotmpl", "name: {{ .name }}\n")
	writeTopologyFixture(t, root, "repo/labs/badvars.clab_vars.yml", "name: [\n")

	broken := performWorkspaceRequest(router, http.MethodGet, renderQuery("repo/labs/broken.clab.gotmpl", ""), nil)
	message := requireJSONError(t, broken, http.StatusUnprocessableEntity)
	require.Contains(t, message, "broken.clab.gotmpl")

	badVars := performWorkspaceRequest(router, http.MethodGet, renderQuery("repo/labs/badvars.clab.gotmpl", ""), nil)
	requireJSONError(t, badVars, http.StatusUnprocessableEntity)

	for _, tc := range []struct {
		path, varsPath string
		status         int
	}{
		{path: "repo/labs/missing.clab.gotmpl", status: http.StatusNotFound},
		{path: "repo/labs/ok.clab.gotmpl", varsPath: "missing.yml", status: http.StatusNotFound},
		{path: "", status: http.StatusBadRequest},
		{path: "../escape.clab.yml", status: http.StatusBadRequest},
		{path: "/etc/passwd", status: http.StatusBadRequest},
		{path: "repo/labs", status: http.StatusBadRequest},
		{path: "repo/labs/ok.clab.gotmpl", varsPath: "/etc/passwd", status: http.StatusBadRequest},
		{path: "repo/labs/ok.clab.gotmpl", varsPath: "../../../outside.yml", status: http.StatusBadRequest},
	} {
		recorder := performWorkspaceRequest(router, http.MethodGet, renderQuery(tc.path, tc.varsPath), nil)
		requireJSONError(t, recorder, tc.status)
	}

	invalidLab := performWorkspaceRequest(router, http.MethodGet, strings.Replace(renderQuery("repo/labs/ok.clab.gotmpl", ""), "/fabric/", "/bad.name/", 1), nil)
	requireJSONError(t, invalidLab, http.StatusBadRequest)

	// Links must not expose files outside the workspace.
	outside := filepath.Join(t.TempDir(), "secret.yml")
	require.NoError(t, os.WriteFile(outside, []byte("name: secret\n"), 0600))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "repo", "labs", "linked.yml")))
	linkedVars := performWorkspaceRequest(router, http.MethodGet, renderQuery("repo/labs/ok.clab.gotmpl", "linked.yml"), nil)
	requireJSONError(t, linkedVars, http.StatusBadRequest)

	require.NoError(t, os.Symlink(outside, filepath.Join(root, "repo", "labs", "ok.clab_vars.yml")))
	discoveredLink := performWorkspaceRequest(router, http.MethodGet, renderQuery("repo/labs/ok.clab.gotmpl", ""), nil)
	requireJSONError(t, discoveredLink, http.StatusBadRequest)

	require.NoError(t, os.MkdirAll(filepath.Join(root, "repo", "labs", "clab_templates"), 0750))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "repo", "labs", "clab_templates", "secret.gotmpl")))
	subtemplateLink := performWorkspaceRequest(router, http.MethodGet, renderQuery("repo/labs/broken.clab.gotmpl", ""), nil)
	requireJSONError(t, subtemplateLink, http.StatusBadRequest)
}

func TestVarsFilesFromQueryResolvesAgainstTopologyDirectory(t *testing.T) {
	_, root := workspaceTestRouter(t)
	writeTopologyFixture(t, root, "repo/labs/lab.clab.gotmpl", "name: lab\n")
	writeTopologyFixture(t, root, "repo/labs/prod.yml", "{}\n")
	topology := filepath.Join(root, "repo", "labs", "lab.clab.gotmpl")

	ctx, recorder := newQueryContext("varsPath=prod.yml")
	varsFiles, ok := varsFilesFromQuery(ctx, topology, currentTestUsername(t))
	require.True(t, ok, recorder.Body.String())
	require.Equal(t, []string{filepath.Join(root, "repo", "labs", "prod.yml")}, varsFiles)

	ctx, _ = newQueryContext("")
	varsFiles, ok = varsFilesFromQuery(ctx, topology, currentTestUsername(t))
	require.True(t, ok)
	require.Nil(t, varsFiles)

	ctx, recorder = newQueryContext("varsPath=prod.yml")
	_, ok = varsFilesFromQuery(ctx, "https://example.com/lab.clab.yml", currentTestUsername(t))
	require.False(t, ok)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestRootLevelTemplateResolvesForRenderAndDeploy(t *testing.T) {
	router, root := renderTestRouter(t)
	writeTopologyFixture(t, root, "fabric.clab.gotmpl", "name: {{ .name }}\n")
	writeTopologyFixture(t, root, "fabric.clab_vars.yml", "name: fabric\n")
	writeTopologyFixture(t, root, "prod.yml", "name: prod\n")

	entries, err := listTopologyEntries(root)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "fabric", entries[0].LabName)
	require.Equal(t, "fabric.clab.gotmpl", entries[0].YamlFileName)

	// Deploy resolves the listed path through the canonical root-level names.
	username := currentTestUsername(t)
	for requested, expected := range map[string]string{
		"fabric.clab.gotmpl":                  "fabric.clab.gotmpl",
		"fabric.clab.gotmpl.annotations.json": "fabric.clab.gotmpl.annotations.json",
	} {
		resolved, _, _, _, err := resolveTopologyFilePath(username, "fabric", requested)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(root, expected), resolved)
	}
	topology, err := resolveTopologyInput(username, "fabric", "fabric.clab.gotmpl")
	require.NoError(t, err)
	ctx, recorder := newQueryContext("varsPath=prod.yml")
	varsFiles, ok := varsFilesFromQuery(ctx, topology.absPath, username)
	require.True(t, ok, recorder.Body.String())
	require.Equal(t, []string{filepath.Join(root, "prod.yml")}, varsFiles)

	rendered := performWorkspaceRequest(router, http.MethodGet, renderQuery("fabric.clab.gotmpl", ""), nil)
	require.Equal(t, http.StatusOK, rendered.Code, rendered.Body.String())
	var response models.RenderedTopologyResponse
	require.NoError(t, json.Unmarshal(rendered.Body.Bytes(), &response))
	require.Equal(t, "fabric", response.LabName)
	require.Equal(t, []string{"fabric.clab_vars.yml"}, response.VarsFiles)
	require.Equal(t, "name: fabric\n", response.Content)
}

func TestRenderTopologyHandlerSharedWorkspace(t *testing.T) {
	router, _ := renderTestRouter(t)
	sharedRoot := t.TempDir()
	setTestSharedLabsRoot(t, sharedRoot)
	writeTopologyFixture(t, sharedRoot, "demo/demo.clab.gotmpl", "name: {{ .name }}\n")
	writeTopologyFixture(t, sharedRoot, "demo/demo.clab_vars.yml", "name: shared-demo\n")
	writeTopologyFixture(t, sharedRoot, "common/prod.yml", "name: shared-prod\n")

	rendered := performWorkspaceRequest(router, http.MethodGet, renderQuery("@shared/demo/demo.clab.gotmpl", ""), nil)
	require.Equal(t, http.StatusOK, rendered.Code, rendered.Body.String())
	var response models.RenderedTopologyResponse
	require.NoError(t, json.Unmarshal(rendered.Body.Bytes(), &response))
	require.Equal(t, "shared-demo", response.LabName)
	require.Equal(t, []string{"demo.clab_vars.yml"}, response.VarsFiles)

	explicit := performWorkspaceRequest(router, http.MethodGet, renderQuery("@shared/demo/demo.clab.gotmpl", "../common/prod.yml"), nil)
	require.Equal(t, http.StatusOK, explicit.Code, explicit.Body.String())
	response = models.RenderedTopologyResponse{}
	require.NoError(t, json.Unmarshal(explicit.Body.Bytes(), &response))
	require.Equal(t, "shared-prod", response.LabName)

	escaped := performWorkspaceRequest(router, http.MethodGet, renderQuery("@shared/demo/demo.clab.gotmpl", "../../outside.yml"), nil)
	requireJSONError(t, escaped, http.StatusBadRequest)
}

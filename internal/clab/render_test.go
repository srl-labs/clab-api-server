package clab

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	gogitplumbing "github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	clabcore "github.com/srl-labs/containerlab/core"
)

func writeRenderFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func commitFixture(t *testing.T, repo *gogit.Repository, dir string) gogitplumbing.Hash {
	t.Helper()
	writeRenderFixture(t, filepath.Join(dir, "lab.clab.yml"), "name: lab\n")
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatalf("open worktree: %v", err)
	}
	if _, err := worktree.Add("lab.clab.yml"); err != nil {
		t.Fatalf("stage file: %v", err)
	}
	hash, err := worktree.Commit("initial", &gogit.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	return hash
}

func TestExpandLabNameGitTokens(t *testing.T) {
	const name = "lab-__gitBranch__-__gitHash__"

	if got := ExpandLabNameGitTokens("plain", t.TempDir()); got != "plain" {
		t.Fatalf("name without tokens = %q, want plain", got)
	}
	if got := ExpandLabNameGitTokens(name, t.TempDir()); got != "lab-none-none" {
		t.Fatalf("name outside a repository = %q, want lab-none-none", got)
	}

	unbornDir := t.TempDir()
	if _, err := gogit.PlainInit(unbornDir, false); err != nil {
		t.Fatalf("init repository: %v", err)
	}
	if got := ExpandLabNameGitTokens(name, unbornDir); got != "lab-master-none" {
		t.Fatalf("name in a repository without commits = %q, want lab-master-none", got)
	}

	repoDir := t.TempDir()
	repo, err := gogit.PlainInit(repoDir, false)
	if err != nil {
		t.Fatalf("init repository: %v", err)
	}
	hash := commitFixture(t, repo, repoDir)
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatalf("open worktree: %v", err)
	}
	if err := worktree.Checkout(&gogit.CheckoutOptions{
		Branch: gogitplumbing.NewBranchReferenceName("feature/templates"),
		Create: true,
	}); err != nil {
		t.Fatalf("create branch: %v", err)
	}
	want := "lab-feature-templates-" + hash.String()[:7]
	if got := ExpandLabNameGitTokens(name, repoDir); got != want {
		t.Fatalf("name on a branch = %q, want %q", got, want)
	}

	// Like containerlab, only a repository rooted at the topology directory counts.
	nested := filepath.Join(repoDir, "labs")
	if err := os.MkdirAll(nested, 0750); err != nil {
		t.Fatalf("create nested directory: %v", err)
	}
	if got := ExpandLabNameGitTokens(name, nested); got != "lab-none-none" {
		t.Fatalf("name below a repository root = %q, want lab-none-none", got)
	}
}

func TestTopologyVarsFilesMirrorsContainerlabDiscovery(t *testing.T) {
	dir := t.TempDir()
	topology := filepath.Join(dir, "lab.clab.gotmpl")
	for _, name := range []string{"lab.clab.gotmpl", "lab.clab_vars.yml", "lab.clab_vars.extra.json", "lab.clab_vars.txt", "other.clab_vars.yml"} {
		writeRenderFixture(t, filepath.Join(dir, name), "{}\n")
	}

	got, err := TopologyVarsFiles(topology, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(dir, "lab.clab_vars.extra.json"), filepath.Join(dir, "lab.clab_vars.yml")}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("discovered vars files = %v, want %v", got, want)
	}

	explicit := filepath.Join(dir, "custom.yml")
	got, err = TopologyVarsFiles(topology, []string{"", explicit})
	if err != nil || len(got) != 1 || got[0] != explicit {
		t.Fatalf("explicit vars files = %v, %v", got, err)
	}
}

func TestRenderTopologyUsesContainerlabLoader(t *testing.T) {
	dir := t.TempDir()
	topology := filepath.Join(dir, "fabric.clab.gotmpl")
	writeRenderFixture(t, topology, `name: {{ .name }}
topology:
  defaults:
    image: ${CLAB_API_SERVER_RENDER_TEST_IMAGE:=alpine:3}
  nodes:
{{- range .nodes }}
{{ template "node.gotmpl" . }}
{{- end }}
`)
	writeRenderFixture(t, filepath.Join(dir, "clab_templates", "node.gotmpl"), "    {{ . }}:\n      kind: linux\n")
	writeRenderFixture(t, filepath.Join(dir, "fabric.clab_vars.yml"), "name: fabric\nnodes: [n1, n2]\n")

	result, err := NewService().RenderTopology(topology, nil)
	if err != nil {
		t.Fatalf("render topology: %v", err)
	}
	if result.LoadError != nil {
		t.Fatalf("rendered topology rejected: %v", result.LoadError)
	}
	want := "name: fabric\ntopology:\n  defaults:\n    image: alpine:3\n  nodes:\n    n1:\n      kind: linux\n\n    n2:\n      kind: linux\n\n"
	if string(result.Content) != want {
		t.Fatalf("rendered topology = %q, want %q", result.Content, want)
	}
	if clabcore.ExportRenderedTopology != "" {
		t.Fatalf("export path left set to %q", clabcore.ExportRenderedTopology)
	}

	invalid := filepath.Join(dir, "invalid.clab.yml")
	writeRenderFixture(t, invalid, "name: invalid\nunknown: true\n")
	result, err = NewService().RenderTopology(invalid, nil)
	if err != nil {
		t.Fatalf("render invalid topology: %v", err)
	}
	if result.LoadError == nil || string(result.Content) != "name: invalid\nunknown: true\n" {
		t.Fatalf("invalid topology result = %q, %v", result.Content, result.LoadError)
	}

	broken := filepath.Join(dir, "broken.clab.gotmpl")
	writeRenderFixture(t, broken, "name: {{ .name \n")
	_, err = NewService().RenderTopology(broken, nil)
	var templateErr *TopologyTemplateError
	if !errors.As(err, &templateErr) {
		t.Fatalf("broken template error = %v, want TopologyTemplateError", err)
	}
}

func TestDeployClabOptionsUseVarsFiles(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatalf("get current user: %v", err)
	}

	dir := t.TempDir()
	topology := filepath.Join(dir, "lab.clab.gotmpl")
	writeRenderFixture(t, topology, `name: lab
topology:
  nodes:
    {{ .node }}:
      kind: linux
      image: alpine:3
`)
	writeRenderFixture(t, filepath.Join(dir, "lab.clab_vars.yml"), "node: discovered\n")
	explicit := filepath.Join(dir, "prod.yml")
	writeRenderFixture(t, explicit, "node: explicit\n")

	for _, tc := range []struct {
		varsFiles []string
		wantNode  string
	}{
		{varsFiles: nil, wantNode: "discovered"},
		{varsFiles: []string{explicit}, wantNode: "explicit"},
	} {
		lab, err := newContainerLabForOwner(
			current.Username,
			deployClabOptions(topology, "authorized", DeployOptions{VarsFiles: tc.varsFiles})...,
		)
		if err != nil {
			t.Fatalf("create containerlab: %v", err)
		}
		if _, ok := lab.Config.Topology.Nodes[tc.wantNode]; !ok {
			t.Fatalf("nodes = %v, want %s", lab.Config.Topology.Nodes, tc.wantNode)
		}
	}
}

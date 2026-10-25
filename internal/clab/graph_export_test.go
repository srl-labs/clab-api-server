package clab

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

const graphExportTopology = `name: graph
topology:
  nodes:
    n1:
      kind: linux
      image: alpine
    n2:
      kind: linux
      image: alpine
  links:
    - endpoints: ["n1:eth1", "n2:eth1"]
`

func TestGenerateGraphExport(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skipf("cannot determine current user: %v", err)
	}

	tests := []struct {
		name      string
		format    string
		direction string
		wantFile  string
		wantText  []string
	}{
		{
			name:      "mermaid",
			format:    GraphFormatMermaid,
			direction: "LR",
			wantFile:  "graph.clab.mermaid",
			wantText:  []string{"title: graph", "graph LR", "---"},
		},
		{
			name:     "mermaid default direction",
			format:   GraphFormatMermaid,
			wantFile: "graph.clab.mermaid",
			wantText: []string{"graph TD"},
		},
		{
			name:     "dot",
			format:   GraphFormatDot,
			wantFile: "graph.clab.dot",
			wantText: []string{`"graph.clab"`, "n1", "n2", "--"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			topoPath := filepath.Join(dir, "graph.clab.yml")
			if err := os.WriteFile(topoPath, []byte(graphExportTopology), 0o600); err != nil {
				t.Fatal(err)
			}

			result, err := (&Service{}).GenerateGraphExport(context.Background(), GraphExportOptions{
				TopoPath:  topoPath,
				Username:  current.Username,
				Format:    tt.format,
				Direction: tt.direction,
			})
			if err != nil {
				t.Fatalf("GenerateGraphExport: %v", err)
			}

			wantPath := filepath.Join(dir, "clab-graph", "graph", tt.wantFile)
			if result.Path != wantPath {
				t.Fatalf("path = %q, want %q", result.Path, wantPath)
			}
			for _, text := range tt.wantText {
				if !strings.Contains(result.Content, text) {
					t.Fatalf("content %q does not contain %q", result.Content, text)
				}
			}
			onDisk, err := os.ReadFile(wantPath)
			if err != nil || string(onDisk) != result.Content {
				t.Fatalf("file content mismatch (err=%v)", err)
			}
		})
	}
}

func TestGenerateGraphExportRejectsInvalidInput(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skipf("cannot determine current user: %v", err)
	}

	dir := t.TempDir()
	badTopo := filepath.Join(dir, "bad.clab.yml")
	if err := os.WriteFile(badTopo, []byte(`name: bad
topology:
  nodes:
    n1:
      kind: linux
      image: alpine
  links:
    - endpoints: ["n1:eth1", "missing:eth1"]
`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = (&Service{}).GenerateGraphExport(context.Background(), GraphExportOptions{
		TopoPath: badTopo,
		Username: current.Username,
		Format:   GraphFormatMermaid,
	})
	if !errors.Is(err, ErrInvalidTopology) {
		t.Fatalf("error = %v, want ErrInvalidTopology", err)
	}

	_, err = (&Service{}).GenerateGraphExport(context.Background(), GraphExportOptions{
		TopoPath: badTopo,
		Username: current.Username,
		Format:   "png",
	})
	if err == nil || errors.Is(err, ErrInvalidTopology) {
		t.Fatalf("unsupported format error = %v", err)
	}
}

func TestGenerateTopologyRejectsUngenerateableKind(t *testing.T) {
	for _, tiers := range [][]TierDefinition{
		{{Count: 1, Kind: "not_a_kind"}},
		{{Count: 2, Kind: "srl"}, {Count: 1, Kind: "not_a_kind"}},
		{{Count: 1, Kind: "ipinfusion_ocnos"}, {Count: 1, Kind: "srl"}},
	} {
		_, err := (&Service{}).GenerateTopology(context.Background(), GenerateTopologyOptions{
			Name:   "gen",
			Tiers:  tiers,
			Images: map[string]string{"srl": "ghcr.io/nokia/srlinux"},
		})
		var kindErr *GenerateKindError
		if !errors.As(err, &kindErr) {
			t.Fatalf("tiers %+v: error = %v, want GenerateKindError", tiers, err)
		}
		if !strings.HasSuffix(err.Error(), "cannot be used to generate a topology") {
			t.Fatalf("error message = %q", err.Error())
		}
	}

	out, err := (&Service{}).GenerateTopology(context.Background(), GenerateTopologyOptions{
		Name:   "gen",
		Tiers:  []TierDefinition{{Count: 2, Kind: "srl"}, {Count: 1, Kind: "linux"}},
		Images: map[string]string{"srl": "ghcr.io/nokia/srlinux", "linux": "alpine"},
	})
	if err != nil {
		t.Fatalf("GenerateTopology with generateable kinds: %v", err)
	}
	if !strings.Contains(string(out), "node1-1") || !strings.Contains(string(out), "node2-1") {
		t.Fatalf("unexpected generated topology:\n%s", out)
	}
}

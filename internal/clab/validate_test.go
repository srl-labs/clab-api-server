package clab

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func TestValidateTopology(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skipf("cannot determine current user: %v", err)
	}

	tests := []struct {
		name      string
		topology  string
		wantValid bool
		wantNodes int
		wantLinks int
	}{
		{
			name: "valid",
			topology: `name: val
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
`,
			wantValid: true,
			wantNodes: 2,
			wantLinks: 1,
		},
		{
			name: "link to unknown node",
			topology: `name: val
topology:
  nodes:
    n1:
      kind: linux
      image: alpine
  links:
    - endpoints: ["n1:eth1", "missing:eth1"]
`,
		},
		{
			name: "unknown kind",
			topology: `name: val
topology:
  nodes:
    n1:
      kind: not_a_kind
      image: alpine
`,
		},
		{
			name:     "no nodes",
			topology: "name: val\ntopology:\n  nodes: {}\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			topoPath := filepath.Join(t.TempDir(), "val.clab.yml")
			if err := os.WriteFile(topoPath, []byte(tt.topology), 0o600); err != nil {
				t.Fatal(err)
			}

			result, err := (&Service{}).Validate(context.Background(), ValidateOptions{
				TopoPath: topoPath,
				Username: current.Username,
			})
			if !tt.wantValid {
				if !errors.Is(err, ErrInvalidTopology) {
					t.Fatalf("Validate error = %v, want ErrInvalidTopology", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if result.LabName != "val" || result.Nodes != tt.wantNodes || result.Links != tt.wantLinks {
				t.Fatalf("result = %+v, want name val, %d nodes, %d links", result, tt.wantNodes, tt.wantLinks)
			}
		})
	}
}

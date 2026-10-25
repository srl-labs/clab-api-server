package clab

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	gogitplumbing "github.com/go-git/go-git/v5/plumbing"
	clabcore "github.com/srl-labs/containerlab/core"
	clabtypes "github.com/srl-labs/containerlab/types"
)

// TopologyTemplateSuffix is the conventional suffix of containerlab topology templates.
const TopologyTemplateSuffix = ".clab.gotmpl"

const (
	gitBranchNameToken = "__gitBranch__"
	gitHashNameToken   = "__gitHash__"
	varsFileSuffix     = "_vars"
)

// TopologyTemplateError is a topology containerlab could not render, for
// example because the template does not parse or execute.
type TopologyTemplateError struct {
	Err error
}

func (e *TopologyTemplateError) Error() string { return e.Err.Error() }

func (e *TopologyTemplateError) Unwrap() error { return e.Err }

// RenderTopologyResult is a topology rendered by containerlab without deploying it.
type RenderTopologyResult struct {
	// Content is the topology after template and environment variable expansion.
	Content []byte
	// LoadError is set when containerlab rejects the rendered content.
	LoadError error
}

// TopologyVarsFiles returns the template variable files containerlab reads for
// a topology: the explicit files, or <topology name without ext>_vars.{yaml,yml,json}
// next to the topology when none are given.
func TopologyVarsFiles(topoPath string, varsFiles []string) ([]string, error) {
	explicit := make([]string, 0, len(varsFiles))
	for _, varsFile := range varsFiles {
		if varsFile != "" {
			explicit = append(explicit, varsFile)
		}
	}
	if len(varsFiles) > 0 {
		return explicit, nil
	}

	topoDir := filepath.Dir(topoPath)
	base := filepath.Base(topoPath)
	pattern := strings.TrimSuffix(base, filepath.Ext(base)) + varsFileSuffix + ".*"
	candidates, err := fs.Glob(os.DirFS(topoDir), pattern)
	if err != nil {
		return nil, err
	}
	found := []string{}
	for _, candidate := range candidates {
		if slices.Contains([]string{".yaml", ".yml", ".json"}, filepath.Ext(candidate)) {
			found = append(found, filepath.Join(topoDir, candidate))
		}
	}
	return found, nil
}

// TopologySubtemplates returns the clab_templates/*.gotmpl files containerlab
// makes available to a topology template.
func TopologySubtemplates(topoPath string) ([]string, error) {
	topoDir := filepath.Dir(topoPath)
	matches, err := fs.Glob(os.DirFS(topoDir), "clab_templates/*.gotmpl")
	if err != nil {
		return nil, err
	}
	for i, match := range matches {
		matches[i] = filepath.Join(topoDir, match)
	}
	return matches, nil
}

// RenderTopology renders a topology file with containerlab's own loader without
// touching the container runtime. Failures before content exists are returned
// as *TopologyTemplateError; content containerlab rejects comes with LoadError.
func (s *Service) RenderTopology(topoPath string, varsFiles []string) (*RenderTopologyResult, error) {
	tmpDir, err := os.MkdirTemp("", "clab-render-")
	if err != nil {
		return nil, fmt.Errorf("failed to create render directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()
	exportPath := filepath.Join(tmpDir, "rendered.clab.yml")

	loadErr := loadTopologyWithExport(topoPath, varsFiles, exportPath)

	content, readErr := os.ReadFile(exportPath)
	if readErr != nil {
		if !os.IsNotExist(readErr) {
			return nil, fmt.Errorf("failed to read rendered topology: %w", readErr)
		}
		if loadErr == nil {
			return nil, fmt.Errorf("containerlab did not produce a rendered topology")
		}
		return nil, &TopologyTemplateError{Err: loadErr}
	}

	return &RenderTopologyResult{Content: content, LoadError: loadErr}, nil
}

// loadTopologyWithExport runs containerlab's topology loader with the rendered
// topology export pointed at exportPath. The export path is a process-wide
// containerlab setting, so it is only changed while holding containerlabMu.
func loadTopologyWithExport(topoPath string, varsFiles []string, exportPath string) (err error) {
	containerlabMu.Lock()
	previous := clabcore.ExportRenderedTopology
	clabcore.ExportRenderedTopology = exportPath
	defer func() {
		clabcore.ExportRenderedTopology = previous
		containerlabMu.Unlock()
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to load rendered topology: %v", r)
		}
	}()

	lab := &clabcore.CLab{
		Config: &clabcore.Config{
			Mgmt:     new(clabtypes.MgmtNet),
			Topology: clabtypes.NewTopology(),
		},
	}
	return lab.LoadTopologyFromFile(topoPath, varsFiles)
}

// ExpandLabNameGitTokens replaces __gitBranch__ and __gitHash__ in a lab name the
// way containerlab does when it parses the topology in topologyDir.
func ExpandLabNameGitTokens(name, topologyDir string) string {
	if !strings.Contains(name, gitBranchNameToken) && !strings.Contains(name, gitHashNameToken) {
		return name
	}
	branch, hash := topologyGitInfo(topologyDir)
	return strings.NewReplacer(
		gitBranchNameToken, strings.ReplaceAll(branch, "/", "-"),
		gitHashNameToken, hash,
	).Replace(name)
}

// topologyGitInfo mirrors containerlab's branch and short hash lookup. Like
// containerlab it only opens a repository rooted at topologyDir.
func topologyGitInfo(topologyDir string) (branch, hash string) {
	repo, err := gogit.PlainOpen(topologyDir)
	if err != nil {
		return "none", "none"
	}

	head, err := repo.Head()
	if err != nil {
		symbolicHead, refErr := repo.Storer.Reference(gogitplumbing.HEAD)
		if refErr != nil || symbolicHead.Type() != gogitplumbing.SymbolicReference {
			return "none", "none"
		}
		return strings.TrimPrefix(symbolicHead.Target().String(), "refs/heads/"), "none"
	}

	return head.Name().Short(), head.Hash().String()[:7]
}

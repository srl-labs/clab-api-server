package clab

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/charmbracelet/log"
	clabconst "github.com/srl-labs/containerlab/constants"
	clabcore "github.com/srl-labs/containerlab/core"
	claberrors "github.com/srl-labs/containerlab/errors"
	clabexec "github.com/srl-labs/containerlab/exec"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	clabtypes "github.com/srl-labs/containerlab/types"
)

// ErrNoMatchingContainers is returned when exec filters match no container of the lab.
var ErrNoMatchingContainers = errors.New("no lab containers match the filters")

// ErrIncorrectInput is containerlab's error for invalid input such as node
// names that are not part of the topology.
var ErrIncorrectInput = claberrors.ErrIncorrectInput

// LabelFilter matches a container label exactly, like `containerlab exec --label key=value`.
type LabelFilter struct {
	Key   string
	Value string
}

// ExecFilterOptions selects lab containers by topology node names and labels.
// All filters combine with AND, and the lab name filter is always applied.
type ExecFilterOptions struct {
	LabName   string
	NodeNames []string
	Labels    []LabelFilter
	Commands  []string
	Username  string
}

// execListFilters builds runtime filters that always restrict the listing to labName.
func execListFilters(labName string, labels []LabelFilter) []*clabtypes.GenericFilter {
	filters := make([]*clabtypes.GenericFilter, 0, len(labels))
	for _, label := range labels {
		filters = append(filters, &clabtypes.GenericFilter{
			FilterType: "label",
			Field:      label.Key,
			Operator:   "=",
			Match:      label.Value,
		})
	}
	// The lab filter goes last so a caller-supplied label cannot replace it.
	return append(filters, &clabtypes.GenericFilter{
		FilterType: "label",
		Field:      clabconst.Containerlab,
		Operator:   "=",
		Match:      labName,
	})
}

// selectExecContainers keeps the non-internal containers of labName whose
// topology node name is in nodeNames (all when nodeNames is empty) and whose
// labels match every filter. It re-checks the runtime filters so the result
// never leaves the lab even if a runtime ignored a filter.
func selectExecContainers(
	containers []clabruntime.GenericContainer,
	labName string,
	nodeNames []string,
	labels []LabelFilter,
) []clabruntime.GenericContainer {
	selected := make([]clabruntime.GenericContainer, 0, len(containers))
	for _, container := range containers {
		if isInternalContainer(container) || len(container.Names) == 0 {
			continue
		}
		if container.Labels[clabconst.Containerlab] != labName {
			continue
		}
		if len(nodeNames) > 0 && !slices.Contains(nodeNames, container.Labels[clabconst.NodeName]) {
			continue
		}
		matches := true
		for _, label := range labels {
			if value, ok := container.Labels[label.Key]; !ok || value != label.Value {
				matches = false
				break
			}
		}
		if matches {
			selected = append(selected, container)
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Names[0] < selected[j].Names[0] })
	return selected
}

// ExecFiltered runs commands on the lab containers selected by node names and labels.
func (s *Service) ExecFiltered(ctx context.Context, opts ExecFilterOptions) (*clabexec.ExecCollection, error) {
	ctx, cancel := s.ensureTimeout(ctx)
	defer cancel()

	labName := strings.TrimSpace(opts.LabName)
	if labName == "" {
		return nil, fmt.Errorf("lab name is required")
	}
	if len(opts.Commands) == 0 {
		return nil, fmt.Errorf("at least one command is required")
	}

	execCmds := make([]*clabexec.ExecCmd, 0, len(opts.Commands))
	for _, command := range opts.Commands {
		execCmd, err := clabexec.NewExecCmdFromString(command)
		if err != nil {
			return nil, err
		}
		execCmds = append(execCmds, execCmd)
	}

	if IsLabRuntime() {
		return s.execFilteredWithLabRuntime(ctx, opts, execCmds)
	}

	clab, err := newContainerLab(append([]clabcore.ClabOption{
		clabcore.WithTimeout(defaultTimeout),
	}, runtimeOptions(nil, defaultTimeout)...)...)
	if err != nil {
		return nil, fmt.Errorf("failed to create containerlab instance: %w", err)
	}

	containers, err := clab.ListContainers(ctx,
		clabcore.WithListclabLabelExists(),
		clabcore.WithListFilter(execListFilters(labName, opts.Labels)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	containers = selectExecContainers(containers, labName, opts.NodeNames, opts.Labels)
	if len(containers) == 0 {
		return nil, ErrNoMatchingContainers
	}

	log.Debug("Executing commands on filtered containers",
		"username", opts.Username,
		"labName", labName,
		"nodes", opts.NodeNames,
		"labels", opts.Labels,
		"containers", len(containers),
	)

	results := clabexec.NewExecCollection()
	for idx := range containers {
		for _, execCmd := range execCmds {
			result, err := containers[idx].RunExec(ctx, execCmd)
			if err != nil {
				if errors.Is(err, clabexec.ErrRunExecNotSupported) {
					continue
				}
				log.Warnf("exec on %s failed: %v", containers[idx].Names[0], err)
				continue
			}
			results.Add(containers[idx].Names[0], result)
		}
	}

	return results, nil
}

// MissingLabNodes returns the requested topology node names that have no
// container in the lab, in request order.
func (s *Service) MissingLabNodes(ctx context.Context, username, labName string, nodeNames []string) ([]string, error) {
	containers, err := s.ListContainers(ctx, ListOptions{Username: username, LabName: labName})
	if err != nil {
		return nil, err
	}
	return missingNodeNames(containers, nodeNames), nil
}

func missingNodeNames(containers []clabruntime.GenericContainer, nodeNames []string) []string {
	present := make(map[string]struct{}, len(containers))
	for _, container := range containers {
		if name := container.Labels[clabconst.NodeName]; name != "" {
			present[name] = struct{}{}
		}
	}
	var missing []string
	for _, name := range nodeNames {
		if _, ok := present[name]; !ok && !slices.Contains(missing, name) {
			missing = append(missing, name)
		}
	}
	return missing
}

// InspectLabDetails returns the lab's runtime container objects grouped by lab
// name, like `containerlab inspect --name <lab> --details`. Internal helper
// containers are excluded as in the regular inspect.
func (s *Service) InspectLabDetails(
	ctx context.Context,
	opts InspectOptions,
) (map[string][]clabruntime.GenericContainer, error) {
	if !opts.Details {
		return nil, fmt.Errorf("details inspection requires the Details option")
	}
	labName := strings.TrimSpace(opts.LabName)
	if labName == "" {
		return nil, fmt.Errorf("lab name is required")
	}
	containers, err := s.ListContainers(ctx, ListOptions{Username: opts.Username, LabName: labName})
	if err != nil {
		return nil, err
	}
	return groupContainerDetails(containers), nil
}

// groupContainerDetails mirrors containerlab's printContainerDetailsJSON:
// containers sorted by lab and name, grouped by lab name. The runtime handle is
// dropped because it is process state rather than container data.
func groupContainerDetails(containers []clabruntime.GenericContainer) map[string][]clabruntime.GenericContainer {
	sorted := slices.Clone(containers)
	sort.SliceStable(sorted, func(i, j int) bool {
		labI := sorted[i].Labels[clabconst.Containerlab]
		labJ := sorted[j].Labels[clabconst.Containerlab]
		if labI == labJ {
			return GetContainerName(&sorted[i]) < GetContainerName(&sorted[j])
		}
		return labI < labJ
	})

	grouped := make(map[string][]clabruntime.GenericContainer)
	for _, container := range sorted {
		labName := container.Labels[clabconst.Containerlab]
		if labName == "" {
			labName = "_unknown_lab_"
		}
		container.Runtime = nil
		grouped[labName] = append(grouped[labName], container)
	}
	return grouped
}

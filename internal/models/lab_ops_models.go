package models

// SnapshotSaveRequest selects the nodes and destination for VM snapshots.
type SnapshotSaveRequest struct {
	// Nodes limits the snapshot to these topology node names (all nodes when empty).
	Nodes []string `json:"nodes,omitempty" example:"r1,r2"`
	// OutputDir is a path relative to the topology directory, or an absolute path,
	// inside the user's workspace (or the shared root for shared labs). Defaults to "snapshots".
	OutputDir *string `json:"outputDir,omitempty" example:"snapshots"`
	// Timeout is the per-node wait as a Go duration (default 5m, maximum 30m).
	Timeout *string `json:"timeout,omitempty" example:"5m"`
}

// SnapshotNodeResult is the snapshot outcome for one node.
type SnapshotNodeResult struct {
	Node string `json:"node" example:"r1"`
	// Status is "success", "failed" or "skipped".
	Status string `json:"status" enums:"success,failed,skipped" example:"success"`
	// Path is the snapshot file, workspace-relative (or @shared/...) when inside a workspace root.
	Path       string `json:"path,omitempty" example:"lab1/snapshots/r1.tar"`
	SizeBytes  int64  `json:"sizeBytes" example:"104857600"`
	DurationMs int64  `json:"durationMs" example:"45000"`
	Error      string `json:"error,omitempty"`
	// Reason explains skipped nodes.
	Reason string `json:"reason,omitempty" example:"not a vrnetlab node (kind=nokia_srlinux, image=ghcr.io/nokia/srlinux)"`
}

// SnapshotSaveResponse reports per-node snapshot results.
type SnapshotSaveResponse struct {
	// OutputDir is workspace-relative (or @shared/...) when inside a workspace root.
	OutputDir string               `json:"outputDir" example:"lab1/snapshots"`
	Results   []SnapshotNodeResult `json:"results"`
	Summary   string               `json:"summary" example:"2 succeeded, 0 failed, 1 skipped"`
}

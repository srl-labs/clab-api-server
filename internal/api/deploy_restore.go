package api

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

const snapshotFileSuffix = ".tar"

// restoreQuery holds the deploy restoreAll/restore query parameters before
// their paths are resolved against the topology being deployed.
type restoreQuery struct {
	all   string
	nodes []restoreNodeQuery
}

type restoreNodeQuery struct {
	node string
	path string
}

func (q restoreQuery) empty() bool {
	return q.all == "" && len(q.nodes) == 0
}

// parseRestoreQuery reads `restoreAll` (a directory of <node>.tar files) and the
// repeatable `restore` (node=path). It writes a 400 response and returns false
// on invalid input.
func parseRestoreQuery(c *gin.Context) (restoreQuery, bool) {
	restoreAll, restoreAllSet := c.GetQuery("restoreAll")
	query, err := parseRestoreValues(restoreAll, restoreAllSet, c.QueryArray("restore"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return restoreQuery{}, false
	}
	return query, true
}

func parseRestoreValues(restoreAll string, restoreAllSet bool, restore []string) (restoreQuery, error) {
	var query restoreQuery
	if restoreAllSet {
		if strings.TrimSpace(restoreAll) == "" {
			return query, fmt.Errorf("'restoreAll' query parameter must not be empty")
		}
		query.all = restoreAll
	}
	seen := map[string]struct{}{}
	for _, entry := range restore {
		node, path, ok := strings.Cut(entry, "=")
		node = strings.TrimSpace(node)
		if !ok || strings.TrimSpace(path) == "" {
			return query, fmt.Errorf("invalid 'restore' value %q: use node=path", entry)
		}
		if !isValidNodeName(node) {
			return query, fmt.Errorf("invalid node name %q in 'restore'", node)
		}
		if _, dup := seen[node]; dup {
			return query, fmt.Errorf("node %q is listed more than once in 'restore'", node)
		}
		seen[node] = struct{}{}
		query.nodes = append(query.nodes, restoreNodeQuery{node: node, path: path})
	}
	return query, nil
}

// restoreSnapshotPath is a node's confined snapshot path.
type restoreSnapshotPath struct {
	node string
	path resolvedLabPath
}

// resolveRestoreSnapshots turns a restore query into one confined snapshot path
// per node. Paths are lab paths resolved against the topology directory,
// confined to the allowed roots and symlink-checked; every snapshot must be a
// regular file. restoreAll is expanded to one entry per <node>.tar so
// containerlab never follows links inside that directory itself. Explicit
// restore entries override restoreAll, as in containerlab.
func (s labPathScope) resolveRestoreSnapshots(query restoreQuery) ([]restoreSnapshotPath, error) {
	snapshots := map[string]resolvedLabPath{}

	if query.all != "" {
		dir, err := s.resolve(query.all)
		if err != nil {
			return nil, fmt.Errorf("invalid 'restoreAll': %w", err)
		}
		info, err := os.Stat(dir.Path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("invalid 'restoreAll': directory %s does not exist", dir.display())
			}
			return nil, fmt.Errorf("invalid 'restoreAll': %w", err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("invalid 'restoreAll': %s is not a directory", dir.display())
		}
		entries, err := os.ReadDir(dir.Path)
		if err != nil {
			return nil, fmt.Errorf("invalid 'restoreAll': %w", err)
		}
		for _, entry := range entries {
			name := entry.Name()
			node := strings.TrimSuffix(name, snapshotFileSuffix)
			if !strings.HasSuffix(name, snapshotFileSuffix) || !isValidNodeName(node) || entry.IsDir() {
				continue
			}
			snapshot, err := s.resolveSnapshotFile(filepath.Join(dir.Path, name))
			if err != nil {
				return nil, fmt.Errorf("invalid snapshot %s in 'restoreAll': %w", name, err)
			}
			snapshots[node] = snapshot
		}
	}

	for _, entry := range query.nodes {
		snapshot, err := s.resolveSnapshotFile(entry.path)
		if err != nil {
			return nil, fmt.Errorf("invalid 'restore' path for node %q: %w", entry.node, err)
		}
		snapshots[entry.node] = snapshot
	}

	nodes := make([]string, 0, len(snapshots))
	for node := range snapshots {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	result := make([]restoreSnapshotPath, 0, len(nodes))
	for _, node := range nodes {
		result = append(result, restoreSnapshotPath{node: node, path: snapshots[node]})
	}
	return result, nil
}

// resolveSnapshotFile confines a snapshot file and returns its real path.
func (s labPathScope) resolveSnapshotFile(raw string) (resolvedLabPath, error) {
	resolved, err := s.resolve(raw)
	if err != nil {
		return resolvedLabPath{}, err
	}
	info, err := os.Stat(resolved.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return resolvedLabPath{}, fmt.Errorf("snapshot file %s does not exist", resolved.display())
		}
		return resolvedLabPath{}, err
	}
	if !info.Mode().IsRegular() {
		return resolvedLabPath{}, fmt.Errorf("snapshot %s is not a regular file", resolved.display())
	}
	return resolved, nil
}

// openRestoreSnapshots opens every resolved snapshot without following links,
// so what is staged is exactly the file that passed the checks even if the
// path changes afterwards. Files in the user's workspace must be owned by or
// readable for the user; the shared root is server-managed and open to every
// API user. On error, files opened so far are closed.
func (s labPathScope) openRestoreSnapshots(paths []restoreSnapshotPath) ([]clab.RestoreSnapshot, error) {
	opened := make([]clab.RestoreSnapshot, 0, len(paths))
	for _, entry := range paths {
		reader := s.reader
		if entry.path.Shared {
			reader = clab.FileReader{UID: -1}
		}
		file, err := clab.OpenSnapshotFile(entry.path.Path, reader)
		if err != nil {
			closeRestoreSnapshots(opened)
			return nil, fmt.Errorf("invalid snapshot %s for node %q: %w", entry.path.display(), entry.node, err)
		}
		opened = append(opened, clab.RestoreSnapshot{Node: entry.node, File: file})
	}
	return opened, nil
}

func closeRestoreSnapshots(snapshots []clab.RestoreSnapshot) {
	for _, snapshot := range snapshots {
		_ = snapshot.File.Close()
	}
}

// prepareRestoreSnapshots resolves, opens and stages the restore query for
// labName and returns containerlab restore entries that point at the
// server-owned staged copies. Invalid input is reported as a restoreInputError.
func prepareRestoreSnapshots(username, topoPath, labName string, query restoreQuery) ([]string, error) {
	if query.empty() {
		return nil, nil
	}
	scope, err := labPathScopeFor(username, topoPath)
	if err != nil {
		return nil, err
	}
	paths, err := scope.resolveRestoreSnapshots(query)
	if err != nil {
		return nil, restoreInputError{err}
	}
	if len(paths) == 0 {
		return nil, nil
	}
	snapshots, err := scope.openRestoreSnapshots(paths)
	if err != nil {
		return nil, restoreInputError{err}
	}
	defer closeRestoreSnapshots(snapshots)
	return clab.StageRestoreSnapshots(labName, snapshots)
}

// restoreInputError marks restore failures caused by the request.
type restoreInputError struct{ err error }

func (e restoreInputError) Error() string { return e.err.Error() }
func (e restoreInputError) Unwrap() error { return e.err }

// applyRestoreQuery stages the restore query for the lab being deployed and
// stores the result in the deploy options. It writes a 400 response for
// invalid paths and a 500 response when staging fails, and returns false then.
// Callers must hold the lab operation lock.
func applyRestoreQuery(c *gin.Context, username, topoPath, labName string, query restoreQuery, opts *clab.DeployOptions) bool {
	snapshots, err := prepareRestoreSnapshots(username, topoPath, labName, query)
	if err != nil {
		var inputErr restoreInputError
		if errors.As(err, &inputErr) {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
			return false
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to prepare restore snapshots: " + err.Error()})
		return false
	}
	opts.RestoreNodeSnapshots = snapshots
	return true
}

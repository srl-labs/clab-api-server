package clab

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	clabconst "github.com/srl-labs/containerlab/constants"
	clabexec "github.com/srl-labs/containerlab/exec"
	clabruntime "github.com/srl-labs/containerlab/runtime"
	clabdocker "github.com/srl-labs/containerlab/runtime/docker"
)

// Snapshot result states, matching `containerlab tools snapshot save`.
const (
	SnapshotStatusSuccess = "success"
	SnapshotStatusFailed  = "failed"
	SnapshotStatusSkipped = "skipped"
)

const (
	// DefaultSnapshotTimeout is the per-node wait for vrnetlab to write a snapshot.
	DefaultSnapshotTimeout = 5 * time.Minute
	// MaxSnapshotTimeout caps the per-node wait.
	MaxSnapshotTimeout = 30 * time.Minute

	snapshotTriggerFile   = "/snapshot-save"
	snapshotContainerPath = "/snapshot-output.tar"
	snapshotSavedLogLine  = "Snapshot saved to " + snapshotContainerPath
	snapshotFailedLogLine = "Snapshot save failed:"
)

// ErrSnapshotNodesNotFound is returned when requested nodes are not part of the lab.
var ErrSnapshotNodesNotFound = errors.New("nodes not found in lab")

// SnapshotSaveOptions configures SaveSnapshots.
type SnapshotSaveOptions struct {
	LabName   string
	NodeNames []string
	Output    OutputDir
	// Timeout bounds triggering and waiting for each node's snapshot.
	Timeout time.Duration
}

// SnapshotNodeResult is the outcome for one node.
type SnapshotNodeResult struct {
	Node      string
	Status    string
	Path      string
	SizeBytes int64
	Duration  time.Duration
	Error     string
	Reason    string
}

// SummarizeSnapshotResults returns "N succeeded, N failed, N skipped".
func SummarizeSnapshotResults(results []SnapshotNodeResult) string {
	var success, failed, skipped int
	for _, result := range results {
		switch result.Status {
		case SnapshotStatusSuccess:
			success++
		case SnapshotStatusFailed:
			failed++
		case SnapshotStatusSkipped:
			skipped++
		}
	}
	return fmt.Sprintf("%d succeeded, %d failed, %d skipped", success, failed, skipped)
}

// isVrnetlabContainer reports whether a container runs a vrnetlab image, which
// is the only kind that supports VM snapshots. Containerlab checks for the
// "vrnetlab/" prefix; registry-qualified vrnetlab images are accepted too.
func isVrnetlabContainer(container clabruntime.GenericContainer) bool {
	image := strings.ToLower(container.Image)
	return strings.HasPrefix(image, "vrnetlab/") || strings.Contains(image, "/vrnetlab/")
}

// selectSnapshotContainers returns the lab's node containers, filtered by node
// names, sorted by node name. Unknown node names are reported.
func selectSnapshotContainers(
	containers []clabruntime.GenericContainer,
	nodeNames []string,
) ([]clabruntime.GenericContainer, []string) {
	var selected []clabruntime.GenericContainer
	for _, container := range containers {
		if isInternalContainer(container) || len(container.Names) == 0 {
			continue
		}
		if len(nodeNames) > 0 && !slices.Contains(nodeNames, container.Labels[clabconst.NodeName]) {
			continue
		}
		selected = append(selected, container)
	}
	slices.SortFunc(selected, func(a, b clabruntime.GenericContainer) int {
		return strings.Compare(a.Labels[clabconst.NodeName], b.Labels[clabconst.NodeName])
	})
	return selected, missingNodeNames(containers, nodeNames)
}

// SaveSnapshots reimplements `containerlab tools snapshot save` for one lab:
// non-vrnetlab nodes are skipped; for the rest /snapshot-save is touched, the
// vrnetlab completion log line is awaited and /snapshot-output.tar is copied to
// <output>/<node>.tar. Nodes run concurrently.
func (s *Service) SaveSnapshots(ctx context.Context, opts SnapshotSaveOptions) ([]SnapshotNodeResult, error) {
	labName := strings.TrimSpace(opts.LabName)
	if labName == "" {
		return nil, fmt.Errorf("lab name is required")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultSnapshotTimeout
	}
	if timeout > MaxSnapshotTimeout {
		timeout = MaxSnapshotTimeout
	}

	containers, err := s.ListContainers(ctx, ListOptions{LabName: labName})
	if err != nil {
		return nil, err
	}
	selected, missing := selectSnapshotContainers(containers, opts.NodeNames)
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrSnapshotNodesNotFound, strings.Join(missing, ", "))
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("%w: lab %q has no nodes", ErrSnapshotNodesNotFound, labName)
	}

	root, err := openOutputRoot(opts.Output)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	results := make([]SnapshotNodeResult, len(selected))
	var wg sync.WaitGroup
	for idx := range selected {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = s.snapshotNode(ctx, selected[idx], root, opts.Output, timeout)
		}(idx)
	}
	wg.Wait()

	log.Info("Snapshot save finished", "lab", labName, "summary", SummarizeSnapshotResults(results))
	return results, nil
}

func (s *Service) snapshotNode(
	ctx context.Context,
	container clabruntime.GenericContainer,
	root *os.Root,
	output OutputDir,
	timeout time.Duration,
) SnapshotNodeResult {
	start := time.Now()
	nodeName := container.Labels[clabconst.NodeName]
	result := SnapshotNodeResult{Node: nodeName}
	fail := func(err error) SnapshotNodeResult {
		result.Status = SnapshotStatusFailed
		result.Error = err.Error()
		result.Duration = time.Since(start)
		log.Warn("Snapshot failed", "node", nodeName, "error", err)
		return result
	}

	if !isVrnetlabContainer(container) {
		result.Status = SnapshotStatusSkipped
		result.Reason = fmt.Sprintf("not a vrnetlab node (kind=%s, image=%s)",
			container.Labels[clabconst.NodeKind], container.Image)
		return result
	}
	if !isPlainName(nodeName) {
		return fail(fmt.Errorf("invalid node name %q", nodeName))
	}
	rt := container.Runtime
	if rt == nil {
		return fail(fmt.Errorf("container runtime unavailable"))
	}
	containerName := container.Names[0]
	fileName := nodeName + ".tar"
	result.Path = filepath.Join(output.Path(), fileName)

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Follow the logs before triggering so the completion line cannot be missed.
	logs, err := rt.StreamLogs(waitCtx, containerName)
	if err != nil {
		return fail(fmt.Errorf("failed to stream logs: %w", err))
	}
	defer func() { _ = logs.Close() }()

	trigger := clabexec.NewExecCmdFromSlice([]string{"touch", snapshotTriggerFile})
	if err := rt.ExecNotWait(waitCtx, containerName, trigger); err != nil {
		return fail(fmt.Errorf("failed to trigger snapshot: %w", err))
	}

	if err := waitForSnapshotLog(waitCtx, logs); err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			err = fmt.Errorf("timeout waiting for snapshot after %v", timeout)
		}
		return fail(err)
	}

	size, err := s.copySnapshotOut(ctx, rt, containerName, root, filepath.Join(output.Rel, fileName), output)
	if err != nil {
		return fail(fmt.Errorf("failed to copy snapshot: %w", err))
	}

	result.Status = SnapshotStatusSuccess
	result.SizeBytes = size
	result.Duration = time.Since(start)
	log.Info("Snapshot saved", "node", nodeName, "path", result.Path, "size", size)
	return result
}

// waitForSnapshotLog reads container logs until vrnetlab reports the snapshot
// result. Docker multiplexed log frames are demultiplexed first.
func waitForSnapshotLog(ctx context.Context, logs io.ReadCloser) error {
	type outcome struct{ err error }
	done := make(chan outcome, 1)

	go func() {
		scanner := bufio.NewScanner(newLogDemuxReader(logs))
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if idx := strings.Index(line, snapshotFailedLogLine); idx >= 0 {
				done <- outcome{fmt.Errorf("snapshot save failed: %s", strings.TrimSpace(line[idx+len(snapshotFailedLogLine):]))}
				return
			}
			if strings.Contains(line, snapshotSavedLogLine) {
				done <- outcome{nil}
				return
			}
		}
		if err := scanner.Err(); err != nil {
			done <- outcome{fmt.Errorf("error reading logs: %w", err)}
			return
		}
		done <- outcome{fmt.Errorf("log stream closed before snapshot completed")}
	}()

	select {
	case <-ctx.Done():
		// Closing the stream unblocks the reader goroutine.
		_ = logs.Close()
		return ctx.Err()
	case result := <-done:
		return result.err
	}
}

// logDemuxReader strips Docker's 8-byte stdout/stderr frame headers when the
// stream is multiplexed and passes plain streams through unchanged.
type logDemuxReader struct {
	src         *bufio.Reader
	detected    bool
	multiplexed bool
	remaining   uint32
}

func newLogDemuxReader(src io.Reader) io.Reader {
	return &logDemuxReader{src: bufio.NewReader(src)}
}

func (r *logDemuxReader) Read(p []byte) (int, error) {
	if !r.detected {
		header, err := r.src.Peek(8)
		if err != nil && len(header) == 0 {
			return 0, err
		}
		r.detected = true
		r.multiplexed = len(header) == 8 && header[0] <= 2 && header[1] == 0 && header[2] == 0 && header[3] == 0
	}
	if !r.multiplexed {
		return r.src.Read(p)
	}
	for r.remaining == 0 {
		var header [8]byte
		if _, err := io.ReadFull(r.src, header[:]); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, io.EOF
			}
			return 0, err
		}
		r.remaining = binary.BigEndian.Uint32(header[4:])
	}
	if uint32(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.src.Read(p)
	r.remaining -= uint32(n)
	return n, err
}

// copySnapshotOut copies the snapshot archive out of the container into
// root/rel and returns its size. The file is written to a temporary name and
// renamed so a failed copy never leaves a truncated snapshot behind.
func (s *Service) copySnapshotOut(
	ctx context.Context,
	rt clabruntime.ContainerRuntime,
	containerName string,
	root *os.Root,
	rel string,
	owner OutputDir,
) (int64, error) {
	archive, wait, err := openContainerFileArchive(ctx, rt, containerName, snapshotContainerPath)
	if err != nil {
		return 0, err
	}
	defer func() { _ = archive.Close() }()

	tmpRel := filepath.Join(filepath.Dir(rel), fmt.Sprintf(".%s.%d.partial", filepath.Base(rel), time.Now().UnixNano()))
	tmp, err := root.OpenFile(tmpRel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return 0, fmt.Errorf("failed to create output file: %w", err)
	}
	cleanup := func() {
		_ = tmp.Close()
		_ = root.Remove(tmpRel)
	}

	size, err := extractSingleFile(archive, filepath.Base(snapshotContainerPath), tmp)
	if err == nil {
		err = wait()
	}
	if err != nil {
		cleanup()
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		_ = root.Remove(tmpRel)
		return 0, fmt.Errorf("failed to write output file: %w", err)
	}
	if err := lchownInRoot(root, tmpRel, owner); err != nil {
		_ = root.Remove(tmpRel)
		return 0, err
	}
	if info, statErr := root.Lstat(rel); statErr == nil && info.IsDir() {
		_ = root.Remove(tmpRel)
		return 0, fmt.Errorf("%s exists and is a directory", filepath.Base(rel))
	} else if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		_ = root.Remove(tmpRel)
		return 0, statErr
	}
	if err := root.Rename(tmpRel, rel); err != nil {
		_ = root.Remove(tmpRel)
		return 0, fmt.Errorf("failed to move snapshot into place: %w", err)
	}
	return size, nil
}

// openContainerFileArchive returns a tar stream holding path from the container.
// Docker uses the runtime's API client; other runtimes use their CLI's
// `cp <container>:<path> -`, which writes a tar stream to stdout. The returned
// wait function reports errors that happen after the stream was consumed.
func openContainerFileArchive(
	ctx context.Context,
	rt clabruntime.ContainerRuntime,
	containerName, path string,
) (io.ReadCloser, func() error, error) {
	if docker, ok := rt.(*clabdocker.DockerRuntime); ok && docker.Client != nil {
		reader, _, err := docker.Client.CopyFromContainer(ctx, containerName, path)
		if err != nil {
			return nil, nil, err
		}
		return reader, func() error { return nil }, nil
	}

	runtimeName := rt.GetName()
	if runtimeName == "" {
		return nil, nil, fmt.Errorf("unsupported container runtime")
	}
	cliPath, err := exec.LookPath(runtimeName)
	if err != nil {
		return nil, nil, fmt.Errorf("%s CLI not found: %w", runtimeName, err)
	}
	cmd := exec.CommandContext(ctx, cliPath, "cp", containerName+":"+path, "-")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	wait := func() error {
		if err := cmd.Wait(); err != nil {
			return fmt.Errorf("%s cp failed: %w: %s", runtimeName, err, strings.TrimSpace(stderr.String()))
		}
		return nil
	}
	return readCloserFunc{Reader: stdout, close: func() error {
		_ = stdout.Close()
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		return nil
	}}, wait, nil
}

type readCloserFunc struct {
	io.Reader
	close func() error
}

func (r readCloserFunc) Close() error { return r.close() }

// extractSingleFile copies the regular file named name from a tar stream to dst.
// Links and other entry types are rejected.
func extractSingleFile(archive io.Reader, name string, dst io.Writer) (int64, error) {
	reader := tar.NewReader(archive)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return 0, fmt.Errorf("%s not found in container archive", name)
		}
		if err != nil {
			return 0, fmt.Errorf("failed to read container archive: %w", err)
		}
		if filepath.Base(filepath.Clean(header.Name)) != name {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return 0, fmt.Errorf("%s in container is not a regular file", name)
		}
		written, err := io.Copy(dst, reader)
		if err != nil {
			return written, fmt.Errorf("failed to write snapshot: %w", err)
		}
		return written, nil
	}
}

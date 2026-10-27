package clab

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	clabruntime "github.com/srl-labs/containerlab/runtime"
	clabdocker "github.com/srl-labs/containerlab/runtime/docker"
)

// statsConcurrency bounds the stats requests sent to the runtime at once.
const statsConcurrency = 8

// ContainerStatsCounters are the raw resource counters of one container. CPU
// usage is a percentage only between two samples.
type ContainerStatsCounters struct {
	// CPUNanos is the CPU time the container used, summed over all CPUs.
	CPUNanos uint64
	// ClockNanos advances by one second per second of wall time; the CPU time
	// of one fully busy CPU advances as fast.
	ClockNanos uint64
	// OnlineCPUs is the number of CPUs the container can use, 0 when unknown.
	OnlineCPUs       int
	MemoryBytes      uint64
	MemoryLimitBytes uint64
	Pids             uint64
}

// CPUPercent is the CPU usage between two samples, where 100 is one busy CPU.
// It reports false when the samples cannot be compared, e.g. after a restart.
func CPUPercent(previous, current ContainerStatsCounters) (float64, bool) {
	if current.ClockNanos <= previous.ClockNanos || current.CPUNanos < previous.CPUNanos {
		return 0, false
	}
	cpu := float64(current.CPUNanos - previous.CPUNanos)
	clock := float64(current.ClockNanos - previous.ClockNanos)
	return cpu / clock * 100, true
}

// ContainerStats samples the resource counters of running containers, keyed by
// container ID. Containers whose stats cannot be read are left out.
func (s *Service) ContainerStats(
	ctx context.Context,
	containers []clabruntime.GenericContainer,
) (map[string]ContainerStatsCounters, error) {
	if err := RequireContainerRuntime("container stats"); err != nil {
		return nil, err
	}
	rt, err := s.getContainerRuntime()
	if err != nil {
		return nil, err
	}
	if docker, ok := rt.(*clabdocker.DockerRuntime); ok && docker.Client != nil {
		return dockerContainerStats(ctx, docker, containers), nil
	}
	return cliContainerStats(ctx, rt.GetName(), containers)
}

// dockerStatsResponse is the part of the Docker Engine stats response that is read.
type dockerStatsResponse struct {
	CPUStats struct {
		CPUUsage struct {
			TotalUsage  uint64   `json:"total_usage"`
			PercpuUsage []uint64 `json:"percpu_usage"`
		} `json:"cpu_usage"`
		SystemUsage uint64 `json:"system_cpu_usage"`
		OnlineCPUs  int    `json:"online_cpus"`
	} `json:"cpu_stats"`
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
	PidsStats struct {
		Current uint64 `json:"current"`
	} `json:"pids_stats"`
}

func dockerContainerStats(
	ctx context.Context,
	docker *clabdocker.DockerRuntime,
	containers []clabruntime.GenericContainer,
) map[string]ContainerStatsCounters {
	result := make(map[string]ContainerStatsCounters, len(containers))
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, statsConcurrency)
	for _, container := range containers {
		if container.ID == "" {
			continue
		}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			reader, err := docker.Client.ContainerStatsOneShot(ctx, id)
			if err != nil {
				return
			}
			defer reader.Body.Close()
			counters, err := parseDockerStats(reader.Body)
			if err != nil {
				return
			}
			mu.Lock()
			result[id] = counters
			mu.Unlock()
		}(container.ID)
	}
	wg.Wait()
	return result
}

func parseDockerStats(body io.Reader) (ContainerStatsCounters, error) {
	var stats dockerStatsResponse
	if err := json.NewDecoder(body).Decode(&stats); err != nil {
		return ContainerStatsCounters{}, err
	}
	cpus := stats.CPUStats.OnlineCPUs
	if cpus == 0 {
		cpus = len(stats.CPUStats.CPUUsage.PercpuUsage)
	}
	counters := ContainerStatsCounters{
		CPUNanos:         stats.CPUStats.CPUUsage.TotalUsage,
		OnlineCPUs:       cpus,
		MemoryBytes:      dockerMemoryUsage(stats.MemoryStats.Usage, stats.MemoryStats.Stats),
		MemoryLimitBytes: stats.MemoryStats.Limit,
		Pids:             stats.PidsStats.Current,
	}
	// system_cpu_usage is the host CPU time summed over all CPUs.
	if cpus > 0 {
		counters.ClockNanos = stats.CPUStats.SystemUsage / uint64(cpus)
	}
	return counters, nil
}

// dockerMemoryUsage leaves out page cache that can be reclaimed, as `docker stats` does.
func dockerMemoryUsage(usage uint64, stats map[string]uint64) uint64 {
	inactive, ok := stats["inactive_file"] // cgroup v2
	if !ok {
		inactive = stats["total_inactive_file"] // cgroup v1
	}
	if inactive < usage {
		return usage - inactive
	}
	return usage
}

// cliStatsFormat prints one container per line: ID, CPU time, clock (both ns),
// memory usage and limit, and PIDs. Podman names these fields this way.
const cliStatsFormat = "{{.ContainerID}}\t{{.CPUNano}}\t{{.SystemNano}}\t{{.MemUsage}}\t{{.MemLimit}}\t{{.PIDs}}"

// cliContainerStats reads stats through a runtime CLI such as podman.
func cliContainerStats(
	ctx context.Context,
	runtimeName string,
	containers []clabruntime.GenericContainer,
) (map[string]ContainerStatsCounters, error) {
	if runtimeName == "" {
		return nil, fmt.Errorf("unsupported container runtime")
	}
	ids := make([]string, 0, len(containers))
	for _, container := range containers {
		if container.ID != "" {
			ids = append(ids, container.ID)
		}
	}
	if len(ids) == 0 {
		return map[string]ContainerStatsCounters{}, nil
	}
	cliPath, err := exec.LookPath(runtimeName)
	if err != nil {
		return nil, fmt.Errorf("%s CLI not found: %w", runtimeName, err)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	args := append([]string{"stats", "--no-stream", "--no-reset", "--format", cliStatsFormat}, ids...)
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, cliPath, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s stats failed: %w: %s", runtimeName, err, strings.TrimSpace(stderr.String()))
	}
	return parseCLIStats(stdout.String(), ids), nil
}

// parseCLIStats reads cliStatsFormat lines. The CLI may print a shortened
// container ID, so lines are matched to the full IDs by prefix.
func parseCLIStats(output string, ids []string) map[string]ContainerStatsCounters {
	result := make(map[string]ContainerStatsCounters)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) != 6 || fields[0] == "" {
			continue
		}
		values := make([]uint64, 5)
		valid := true
		for i, field := range fields[1:] {
			value, err := strconv.ParseUint(strings.TrimSpace(field), 10, 64)
			if err != nil {
				valid = false
				break
			}
			values[i] = value
		}
		if !valid {
			continue
		}
		for _, id := range ids {
			if strings.HasPrefix(id, fields[0]) || strings.HasPrefix(fields[0], id) {
				result[id] = ContainerStatsCounters{
					CPUNanos:         values[0],
					ClockNanos:       values[1],
					MemoryBytes:      values[2],
					MemoryLimitBytes: values[3],
					Pids:             values[4],
				}
				break
			}
		}
	}
	return result
}

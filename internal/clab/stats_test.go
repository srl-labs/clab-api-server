package clab

import (
	"math"
	"strings"
	"testing"
)

func TestParseDockerStatsLeavesOutReclaimableCache(t *testing.T) {
	counters, err := parseDockerStats(strings.NewReader(`{
		"cpu_stats": {"cpu_usage": {"total_usage": 4000000000}, "system_cpu_usage": 80000000000, "online_cpus": 4},
		"memory_stats": {"usage": 300, "limit": 1000, "stats": {"inactive_file": 100}},
		"pids_stats": {"current": 7}
	}`))
	if err != nil {
		t.Fatalf("parseDockerStats: %v", err)
	}
	want := ContainerStatsCounters{
		CPUNanos:         4000000000,
		ClockNanos:       20000000000,
		OnlineCPUs:       4,
		MemoryBytes:      200,
		MemoryLimitBytes: 1000,
		Pids:             7,
	}
	if counters != want {
		t.Fatalf("counters = %+v, want %+v", counters, want)
	}
}

func TestParseDockerStatsCountsPerCPUUsageWithoutOnlineCPUs(t *testing.T) {
	counters, err := parseDockerStats(strings.NewReader(`{
		"cpu_stats": {"cpu_usage": {"total_usage": 1, "percpu_usage": [1, 0]}, "system_cpu_usage": 10},
		"memory_stats": {"usage": 50, "stats": {"total_inactive_file": 80}}
	}`))
	if err != nil {
		t.Fatalf("parseDockerStats: %v", err)
	}
	if counters.OnlineCPUs != 2 || counters.ClockNanos != 5 {
		t.Fatalf("CPUs %d clock %d, want 2 and 5", counters.OnlineCPUs, counters.ClockNanos)
	}
	if counters.MemoryBytes != 50 {
		t.Fatalf("memory %d, want the usage when the cache is larger", counters.MemoryBytes)
	}
}

func TestCPUPercentIsUsageOfOneCPU(t *testing.T) {
	previous := ContainerStatsCounters{CPUNanos: 1_000_000_000, ClockNanos: 10_000_000_000}
	current := ContainerStatsCounters{CPUNanos: 4_000_000_000, ClockNanos: 12_000_000_000}
	percent, ok := CPUPercent(previous, current)
	if !ok || math.Abs(percent-150) > 1e-9 {
		t.Fatalf("CPUPercent = %v %v, want 150 true", percent, ok)
	}
	// A restarted container starts its counters over.
	if _, ok := CPUPercent(current, ContainerStatsCounters{CPUNanos: 1, ClockNanos: 13_000_000_000}); ok {
		t.Fatalf("CPUPercent compared counters across a restart")
	}
}

func TestParseCLIStatsMatchesShortenedIDs(t *testing.T) {
	ids := []string{"0123456789abcdef0123", "fedcba9876543210fedc"}
	stats := parseCLIStats("0123456789ab\t5\t10\t300\t1000\t3\nbad line\nfedcba987654\tx\t1\t1\t1\t1\n", ids)
	if len(stats) != 1 {
		t.Fatalf("parsed %d containers, want 1: %+v", len(stats), stats)
	}
	want := ContainerStatsCounters{CPUNanos: 5, ClockNanos: 10, MemoryBytes: 300, MemoryLimitBytes: 1000, Pids: 3}
	if stats[ids[0]] != want {
		t.Fatalf("stats = %+v, want %+v", stats[ids[0]], want)
	}
}

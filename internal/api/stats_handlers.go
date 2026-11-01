package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"
	clabruntime "github.com/srl-labs/containerlab/runtime"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

const (
	labStatsDefaultInterval = 2 * time.Second
	labStatsMinInterval     = time.Second
	labStatsMaxInterval     = 20 * time.Second
	// labStatsContainerRefresh is how often the stream looks for added or removed nodes.
	labStatsContainerRefresh = 10 * time.Second
	labStatsStreamTimeout    = 12 * time.Hour
)

// @Summary Stream lab node resource usage
// @Description Streams the CPU, memory and process count of every running node of a lab as NDJSON, one `stats` object per interval.
// @Description
// @Description **Notes**
// @Description - `cpuPercent` is the usage since the previous sample, where 100 is one busy CPU; the first sample of a node has none.
// @Description - Memory usage leaves out page cache that can be reclaimed, like `docker stats`.
// @Description - Nodes that start or stop while streaming appear or disappear within 10 seconds.
// @Description - The stream ends when the client disconnects or after 12 hours.
// @Tags Labs
// @Security BearerAuth
// @Produce application/x-ndjson
// @Param labName path string true "Name of the lab" example="my-lab"
// @Param interval query string false "Time between samples, from 1s to 20s." default(2s)
// @Success 200 {object} models.LabStatsSample "NDJSON stream of samples"
// @Failure 400 {object} models.ErrorResponse "Invalid lab name or interval"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Lab not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/stats [get]
func StreamLabStatsHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}

	interval := labStatsDefaultInterval
	if raw := strings.TrimSpace(c.Query("interval")); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed < labStatsMinInterval || parsed > labStatsMaxInterval {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid interval. Use a duration from 1s to 20s, e.g. 2s."})
			return
		}
		interval = parsed
	}

	if _, err := verifyLabOwnership(c, username, labName); err != nil {
		return
	}
	svc := GetClabService()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "containerlab service not initialized"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), labStatsStreamTimeout)
	defer cancel()

	// Without a resource metrics API a lab runtime cannot sample nodes at all.
	if clab.IsLabRuntime() {
		if _, err := svc.SampleNodeStats(ctx, username, labName); errors.Is(err, clab.ErrMetricsUnavailable) {
			c.JSON(http.StatusNotImplemented, models.ErrorResponse{
				Error: fmt.Sprintf("node stats are not supported by lab runtime %s here: %v", clab.RuntimeKind(), err),
			})
			return
		}
	}

	c.Writer.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Status(http.StatusOK)
	c.Writer.WriteHeaderNow()
	writer := bufio.NewWriter(c.Writer)
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		return
	}
	flusher.Flush()

	sampler := labStatsSampler{svc: svc, username: username, labName: labName, interval: interval}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		sample, err := sampler.next(ctx)
		if err != nil && ctx.Err() == nil {
			log.Warnf("StreamLabStats user '%s' lab '%s': %v", username, labName, err)
		}
		if ctx.Err() != nil {
			return
		}
		payload, err := json.Marshal(sample)
		if err != nil {
			log.Errorf("StreamLabStats failed to marshal sample: %v", err)
			return
		}
		if !writeNDJSONLine(writer, flusher, string(payload)) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// labStatsSampler turns raw counters into samples; CPU usage needs the previous counters.
type labStatsSampler struct {
	svc      *clab.Service
	username string
	labName  string
	interval time.Duration

	containers []clabruntime.GenericContainer
	listedAt   time.Time
	previous   map[string]clab.ContainerStatsCounters
}

func (s *labStatsSampler) next(ctx context.Context) (models.LabStatsSample, error) {
	sample := models.LabStatsSample{
		Type:            "stats",
		Time:            time.Now().UTC(),
		IntervalSeconds: s.interval.Seconds(),
		Nodes:           []models.NodeStats{},
	}
	if clab.IsLabRuntime() {
		return s.nextLabRuntime(ctx, sample)
	}
	if s.containers == nil || time.Since(s.listedAt) >= labStatsContainerRefresh {
		containers, err := s.svc.ListContainers(ctx, clab.ListOptions{Username: s.username, LabName: s.labName})
		if err != nil {
			return sample, err
		}
		s.containers = runningContainers(containers)
		s.listedAt = time.Now()
	}

	counters, err := s.svc.ContainerStats(ctx, s.containers)
	if err != nil {
		return sample, err
	}
	for i := range s.containers {
		container := &s.containers[i]
		current, ok := counters[container.ID]
		if !ok {
			continue
		}
		node := models.NodeStats{
			Name:             clab.GetContainerName(container),
			NodeName:         resolveTopologyNodeName(s.labName, container),
			CPUCount:         current.OnlineCPUs,
			MemoryBytes:      current.MemoryBytes,
			MemoryLimitBytes: current.MemoryLimitBytes,
			Pids:             current.Pids,
		}
		if previous, ok := s.previous[container.ID]; ok {
			if percent, ok := clab.CPUPercent(previous, current); ok {
				rounded := math.Round(percent*10) / 10
				node.CPUPercent = &rounded
			}
		}
		sample.Nodes = append(sample.Nodes, node)
	}
	s.previous = counters
	return sample, nil
}

func runningContainers(containers []clabruntime.GenericContainer) []clabruntime.GenericContainer {
	running := make([]clabruntime.GenericContainer, 0, len(containers))
	for _, container := range containers {
		if strings.EqualFold(container.State, "running") {
			running = append(running, container)
		}
	}
	return running
}

// nextLabRuntime samples a lab on a lab runtime from the cluster's resource metrics
// (metrics.k8s.io). The metrics API already reports CPU usage over its own sampling window,
// so every sample has a CPU value; memory is the working set of the device containers.
func (s *labStatsSampler) nextLabRuntime(ctx context.Context, sample models.LabStatsSample) (models.LabStatsSample, error) {
	stats, err := s.svc.SampleNodeStats(ctx, s.username, s.labName)
	if err != nil {
		return sample, err
	}
	for _, node := range stats {
		cpu := math.Round(float64(node.CPUMilliCores)/10*10) / 10
		memory := uint64(0)
		if node.MemoryBytes > 0 {
			memory = uint64(node.MemoryBytes)
		}
		sample.Nodes = append(sample.Nodes, models.NodeStats{
			Name:        s.labName + "-" + node.NodeName,
			NodeName:    node.NodeName,
			CPUPercent:  &cpu,
			MemoryBytes: memory,
		})
	}
	return sample, nil
}

// internal/api/health_handlers.go
package api

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// Global server start time
var serverStartTime time.Time

// API server version (set in main during initialization)
var apiServerVersion = "development"

// InitHealth sets the server start time for uptime tracking and stores the version
func InitHealth(version string) {
	serverStartTime = time.Now()
	apiServerVersion = version
}

// @Summary Get API Server Basic Health
// @Description Returns basic health status of the API server.
// @Tags Health
// @Produce json
// @Success 200 {object} models.HealthResponse "Basic health information"
// @Router /health [get]
func HealthCheckHandler(c *gin.Context) {
	// Calculate uptime
	uptime := time.Since(serverStartTime)
	uptimeStr := formatUptime(uptime)

	// Basic response
	response := models.HealthResponse{
		Status:    "healthy",
		Uptime:    uptimeStr,
		StartTime: serverStartTime,
		Version:   apiServerVersion,
	}

	c.JSON(http.StatusOK, response)
}

// @Summary Get Detailed System Metrics
// @Description Returns detailed CPU, memory, and disk metrics for the API server. Requires SUPERUSER privileges.
// @Tags Health
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.MetricsResponse "System metrics"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden (User is not a superuser)"
// @Failure 500 {object} models.ErrorResponse "Internal server error gathering metrics"
// @Router /api/v1/health/metrics [get]
func SystemMetricsHandler(c *gin.Context) {
	username := c.GetString("username")

	// --- Authorization: Superuser Only ---
	if !isSuperuser(username) {
		log.Warnf("User '%s' attempted to access system metrics without superuser privileges.", username)
		c.JSON(http.StatusForbidden, models.ErrorResponse{Error: "superuser privileges required for this operation"})
		return
	}

	// Get metrics
	metrics, err := gatherSystemMetrics()
	if err != nil {
		log.Error("error gathering system metrics", "error", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error: fmt.Sprintf("error gathering system metrics: %s", err.Error()),
		})
		return
	}

	response := models.MetricsResponse{
		ServerInfo: models.ServerInfo{
			Version:   apiServerVersion,
			Uptime:    formatUptime(time.Since(serverStartTime)),
			StartTime: serverStartTime,
		},
		Metrics: metrics,
	}

	c.JSON(http.StatusOK, response)
}

// formatUptime formats duration into a human-readable string
func formatUptime(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	} else if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// gatherSystemMetrics collects CPU, memory, and disk metrics
func gatherSystemMetrics() (*models.Metrics, error) {
	metrics := &models.Metrics{}

	// Get CPU metrics
	cpuMetrics, err := getCPUMetrics()
	if err != nil {
		return nil, fmt.Errorf("cpu metrics error: %w", err)
	}
	metrics.CPU = cpuMetrics

	// Get memory metrics
	memMetrics, err := getMemoryMetrics()
	if err != nil {
		return nil, fmt.Errorf("memory metrics error: %w", err)
	}
	metrics.Mem = memMetrics

	// Get disk metrics
	diskMetrics, err := getDiskMetrics("/")
	if err != nil {
		return nil, fmt.Errorf("disk metrics error: %w", err)
	}
	metrics.Disk = diskMetrics

	return metrics, nil
}

// getCPUMetrics returns CPU usage statistics
func getCPUMetrics() (*models.CPUMetrics, error) {
	// Get overall CPU percent (all cores combined)
	percent, err := cpu.Percent(time.Second, false)
	if err != nil {
		return nil, err
	}

	// Get load averages
	loadAvg, err := load.Avg()
	loadAvg1, loadAvg5, loadAvg15 := 0.0, 0.0, 0.0
	if err == nil && loadAvg != nil {
		loadAvg1 = loadAvg.Load1
		loadAvg5 = loadAvg.Load5
		loadAvg15 = loadAvg.Load15
	}

	// Get this process's CPU usage
	processPercent := 0.0
	pid := int32(os.Getpid())
	proc, err := process.NewProcess(pid)
	if err == nil {
		procPercent, err := proc.CPUPercent()
		if err == nil {
			processPercent = procPercent
		}
	}

	cpuMetrics := &models.CPUMetrics{
		NumCPU:         runtime.NumCPU(),
		LoadAvg1:       loadAvg1,
		LoadAvg5:       loadAvg5,
		LoadAvg15:      loadAvg15,
		ProcessPercent: processPercent,
	}

	// Only set UsagePercent if we got valid data
	if len(percent) > 0 {
		cpuMetrics.UsagePercent = percent[0]
	}

	return cpuMetrics, nil
}

// getMemoryMetrics returns memory usage statistics
func getMemoryMetrics() (*models.MemMetrics, error) {
	// Get system memory stats
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	// Get this process's memory usage
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	processMemMB := float64(memStats.Alloc) / 1024 / 1024
	processMemPct := 0.0
	if memInfo.Total > 0 {
		processMemPct = (float64(memStats.Alloc) / float64(memInfo.Total)) * 100
	}

	return &models.MemMetrics{
		TotalMem:      memInfo.Total,
		UsedMem:       memInfo.Used,
		AvailableMem:  memInfo.Available,
		UsagePercent:  memInfo.UsedPercent,
		ProcessMemMB:  processMemMB,
		ProcessMemPct: processMemPct,
	}, nil
}

// getDiskMetrics returns disk usage statistics for a specific path
func getDiskMetrics(path string) (*models.DiskMetrics, error) {
	diskInfo, err := disk.Usage(path)
	if err != nil {
		return nil, err
	}

	return &models.DiskMetrics{
		Path:         path,
		TotalDisk:    diskInfo.Total,
		UsedDisk:     diskInfo.Used,
		FreeDisk:     diskInfo.Free,
		UsagePercent: diskInfo.UsedPercent,
	}, nil
}

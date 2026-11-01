// internal/models/health_models.go
package models

import "time"

// HealthResponse represents basic health information about the API server
type HealthResponse struct {
	Status    string    `json:"status"`            // "healthy" or other status indicators
	Uptime    string    `json:"uptime"`            // Human-readable uptime
	StartTime time.Time `json:"startTime"`         // When the server started
	Version   string    `json:"version,omitempty"` // API server version
	// Features lists optional API features this server supports, so clients can
	// hide what older servers do not provide.
	Features []string `json:"features" example:"validate,exec-filters"`
	// Runtime is the lab runtime the server runs labs with: docker, podman or c9s.
	Runtime string `json:"runtime" example:"docker" enums:"docker,podman,c9s"`
	// NamespaceMode is how c9s labs get namespaces: per-lab (one namespace per lab) or
	// fixed (one namespace for every lab). It is only set for c9s.
	NamespaceMode string `json:"namespaceMode,omitempty" example:"per-lab" enums:"per-lab,fixed"`
}

// MetricsResponse represents detailed system metrics with server info
type MetricsResponse struct {
	ServerInfo ServerInfo `json:"serverInfo"` // Basic server information
	Metrics    *Metrics   `json:"metrics"`    // Detailed system metrics
}

// ServerInfo contains basic server information
type ServerInfo struct {
	Version   string    `json:"version"`   // API server version
	Uptime    string    `json:"uptime"`    // Human-readable uptime
	StartTime time.Time `json:"startTime"` // When the server started
}

// Metrics represents system resource usage metrics
type Metrics struct {
	CPU  *CPUMetrics  `json:"cpu,omitempty"`  // CPU usage metrics
	Mem  *MemMetrics  `json:"mem,omitempty"`  // Memory usage metrics
	Disk *DiskMetrics `json:"disk,omitempty"` // Disk usage metrics
}

// CPUMetrics represents CPU usage information
type CPUMetrics struct {
	UsagePercent   float64 `json:"usagePercent"`             // Overall CPU usage percentage
	NumCPU         int     `json:"numCPU"`                   // Number of CPUs/cores
	LoadAvg1       float64 `json:"loadAvg1,omitempty"`       // 1-minute load average
	LoadAvg5       float64 `json:"loadAvg5,omitempty"`       // 5-minute load average
	LoadAvg15      float64 `json:"loadAvg15,omitempty"`      // 15-minute load average
	ProcessPercent float64 `json:"processPercent,omitempty"` // This process's CPU usage
}

// MemMetrics represents memory usage information
type MemMetrics struct {
	TotalMem      uint64  `json:"totalMem"`                // Total physical memory in bytes
	UsedMem       uint64  `json:"usedMem"`                 // Used physical memory in bytes
	AvailableMem  uint64  `json:"availableMem"`            // Available memory in bytes
	UsagePercent  float64 `json:"usagePercent"`            // Memory usage percentage
	ProcessMemMB  float64 `json:"processMemMB,omitempty"`  // This process's memory in MB
	ProcessMemPct float64 `json:"processMemPct,omitempty"` // This process's memory percentage
}

// DiskMetrics represents disk usage information
type DiskMetrics struct {
	Path         string  `json:"path"`         // Mount path (usually "/")
	TotalDisk    uint64  `json:"totalDisk"`    // Total disk space in bytes
	UsedDisk     uint64  `json:"usedDisk"`     // Used disk space in bytes
	FreeDisk     uint64  `json:"freeDisk"`     // Free disk space in bytes
	UsagePercent float64 `json:"usagePercent"` // Disk usage percentage
}

package models

import "time"

// LabStatsSample is one line of the lab stats stream: the resource usage of
// every running node of a lab.
type LabStatsSample struct {
	// Type is always "stats".
	Type string    `json:"type" example:"stats"`
	Time time.Time `json:"time"`
	// IntervalSeconds is the time between samples.
	IntervalSeconds float64     `json:"intervalSeconds" example:"2"`
	Nodes           []NodeStats `json:"nodes"`
}

// NodeStats is the resource usage of one running lab node.
type NodeStats struct {
	// Name is the container name.
	Name string `json:"name" example:"clab-my-lab-srl1"`
	// NodeName is the node name in the topology.
	NodeName string `json:"nodeName" example:"srl1"`
	// CPUPercent is the CPU usage since the previous sample, where 100 is one busy CPU.
	// It is missing in the first sample of a node.
	CPUPercent *float64 `json:"cpuPercent,omitempty" example:"12.5"`
	// CPUCount is the number of CPUs the node can use, when known.
	CPUCount         int    `json:"cpuCount,omitempty" example:"8"`
	MemoryBytes      uint64 `json:"memoryBytes" example:"536870912"`
	MemoryLimitBytes uint64 `json:"memoryLimitBytes,omitempty" example:"8589934592"`
	Pids             uint64 `json:"pids,omitempty" example:"42"`
}

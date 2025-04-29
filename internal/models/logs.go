// Add to internal/models/logs.go or appropriate models file

package models

// ContainerLogInfo contains information about a container needed for logs retrieval
type ContainerLogInfo struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// LogsResponse represents the response for container logs in JSON format
type LogsResponse struct {
	ContainerName string `json:"containerName"`
	Logs          string `json:"logs"`
}

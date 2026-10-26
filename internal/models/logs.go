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

// LogLine represents a single streamed log line in NDJSON format
type LogLine struct {
	ContainerName string `json:"containerName"`
	Line          string `json:"line"`
	// Stream is the container output the line came from: stdout or stderr.
	Stream string `json:"stream,omitempty"`
}

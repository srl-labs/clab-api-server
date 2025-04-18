// internal/models/ssh_models.go
package models

import "time"

// SSHAccessRequest represents the payload for requesting SSH access to a node
type SSHAccessRequest struct {
	SSHUsername string `json:"sshUsername,omitempty"` // Optional override for container's SSH user
	Duration    string `json:"duration,omitempty"`    // How long the access should be valid for (e.g., "1h", "30m")
}

// SSHAccessResponse represents the response with SSH connection details
type SSHAccessResponse struct {
	Port       int       `json:"port"`       // Allocated port on API server
	Host       string    `json:"host"`       // API server's hostname or IP
	Username   string    `json:"username"`   // Username to use for SSH
	Expiration time.Time `json:"expiration"` // When this access expires
	Command    string    `json:"command"`    // Example SSH command
}

// SSHSessionInfo represents information about an active SSH session
type SSHSessionInfo struct {
	Port       int       `json:"port"`       // Allocated port on API server
	LabName    string    `json:"labName"`    // Lab name
	NodeName   string    `json:"nodeName"`   // Node name
	Username   string    `json:"username"`   // SSH username
	Expiration time.Time `json:"expiration"` // When this access expires
	Created    time.Time `json:"created"`    // When this access was created
}

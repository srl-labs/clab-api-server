package models

// LoginRequest represents the payload for the login endpoint
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents the payload returned after successful login
type LoginResponse struct {
	Token string `json:"token"`
}

// DeployRequest represents the payload for deploying a lab
type DeployRequest struct {
	TopologyContent string `json:"topologyContent" binding:"required" example:"name: my-lab\ntopology:\n  nodes:\n    srl1:\n      kind: srl\n      image: ghcr.io/nokia/srlinux"` // YAML content as a string
}

// ErrorResponse represents a standard error message format
type ErrorResponse struct {
	Error string `json:"error"`
}

// GenericSuccessResponse for simple success messages
type GenericSuccessResponse struct {
	Message string `json:"message"`
}

// --- Structs for parsing `clab inspect --format json` output ---

// ClabInspectOutput matches the top-level structure of `clab inspect --all --format json`
type ClabInspectOutput struct {
	Containers []ClabContainerInfo `json:"containers"`
}

// ClabContainerInfo matches the structure of each item in the "Containers" array
type ClabContainerInfo struct {
	Name        string `json:"name"`         // Name of the container node
	ContainerID string `json:"container_id"` // Docker container ID (short)
	Image       string `json:"image"`        // Container image used
	Kind        string `json:"kind"`         // e.g., "srl", "linux", "nokia_srlinux"
	State       string `json:"state"`        // e.g., "running"
	IPv4Address string `json:"ipv4_address"` // Management IPv4 Address/Mask
	IPv6Address string `json:"ipv6_address"` // Management IPv6 Address/Mask
	LabName     string `json:"lab_name"`     // Name of the lab this node belongs to
	LabPath     string `json:"labPath"`      // Path to the topology file used
	Group       string `json:"group"`        // Group assigned in topology (Might not always be present)
	Owner       string `json:"owner"`        // OS user from clab inspect output (Used for authorization)
}

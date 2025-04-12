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

// TopologyListItem represents a single topology file entry found in the user's home
type TopologyListItem struct {
	Filename     string `json:"filename"`     // e.g., my-lab.clab.yml
	RelativePath string `json:"relativePath"` // Path relative to user's home (same as filename in this case)
}

// --- Structs for parsing `clab inspect --format json` output ---

// ClabInspectOutput matches the top-level structure of `clab inspect --all --format json`
type ClabInspectOutput struct {
	Containers []ClabContainerInfo `json:"Containers"`
}

// ClabContainerInfo matches the structure of each item in the "Containers" array
type ClabContainerInfo struct {
	// Add fields you care about from the `clab inspect` output
	Name           string `json:"name"`            // Name of the container node
	ContainerID    string `json:"container_id"`  // Docker container ID (short)
	Image          string `json:"image"`           // Container image used
	Kind           string `json:"kind"`            // e.g., "srl", "linux"
	State          string `json:"state"`           // e.g., "running"
	IPv4Address    string `json:"ipv4_address"`    // Management IPv4 Address/Mask
	IPv6Address    string `json:"ipv6_address"`    // Management IPv6 Address/Mask
	LabName        string `json:"lab_name"`        // Name of the lab this node belongs to
	LabPath        string `json:"LabPath"`         // Path to the topology file used (often relative)
	Group          string `json:"group"`           // Group assigned in topology
	Owner          string `json:"Owner"`           // Linux username who owns/ran the lab (CRUCIAL FOR FILTERING)
	DeploymentStatus string `json:"deployment_status"` // e.g., "deployed"
	// Add other fields as needed... e.g., ports, labels etc.
}
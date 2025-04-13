// internal/models/models.go
package models

// Required for RawMessage

// LoginRequest represents the payload for the login endpoint
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents the payload returned after successful login
type LoginResponse struct {
	Token string `json:"token"`
}

// DeployRequest represents the payload for deploying a lab.
// Provide EITHER 'topologyContent' OR 'topologySourceUrl', but not both.
type DeployRequest struct {
	// Option 1: Direct Topology Content.
	// Provide the full containerlab topology YAML as a single string.
	// If this is provided, 'topologySourceUrl' MUST be empty.
	TopologyContent string `json:"topologyContent,omitempty" example:"# topology documentation: http://containerlab.dev/lab-examples/single-srl/\nname: srl01\ntopology:\n  kinds:\n    nokia_srlinux:\n      type: ixrd3\n      image: ghcr.io/nokia/srlinux\n\n  nodes:\n    srl1:\n      kind: nokia_srlinux\n    srl2:\n      kind: nokia_srlinux\n\n  links:\n    - endpoints: [\"srl1:e1-1\",\"srl2:e1-1\"]"`

	// Option 2: Remote Topology Source URL.
	// Provide a URL to a Git repository, a specific .clab.yml file in Git (github/gitlab), or a raw HTTP(S) URL.
	// If this is provided, 'topologyContent' MUST be empty.
	TopologySourceUrl string `json:"topologySourceUrl,omitempty"`

	// --- Optional Flags are now Query Parameters ---
	// LabNameOverride string `json:"labNameOverride,omitempty"`
	// Reconfigure     bool   `json:"reconfigure,omitempty"`
	// MaxWorkers      int    `json:"maxWorkers,omitempty"`
	// ExportTemplate  string `json:"exportTemplate,omitempty"`
	// NodeFilter      string `json:"nodeFilter,omitempty"`
	// SkipPostDeploy  bool   `json:"skipPostDeploy,omitempty"`
	// SkipLabdirAcl   bool   `json:"skipLabdirAcl,omitempty"`
}

// RedeployRequest represents the payload for redeploying a lab
type RedeployRequest struct {
	Cleanup        bool   `json:"cleanup,omitempty"`        // Corresponds to --cleanup flag
	Graceful       bool   `json:"graceful,omitempty"`       // Corresponds to --graceful flag
	Graph          bool   `json:"graph,omitempty"`          // Corresponds to --graph flag
	Network        string `json:"network,omitempty"`        // Corresponds to --network flag
	Ipv4Subnet     string `json:"ipv4Subnet,omitempty"`     // Corresponds to --ipv4-subnet flag
	Ipv6Subnet     string `json:"ipv6Subnet,omitempty"`     // Corresponds to --ipv6-subnet flag
	MaxWorkers     int    `json:"maxWorkers,omitempty"`     // Corresponds to --max-workers flag (0 means default)
	KeepMgmtNet    bool   `json:"keepMgmtNet,omitempty"`    // Corresponds to --keep-mgmt-net flag
	SkipPostDeploy bool   `json:"skipPostDeploy,omitempty"` // Corresponds to --skip-post-deploy flag
	ExportTemplate string `json:"exportTemplate,omitempty"` // Corresponds to --export-template flag (__full is special)
	SkipLabdirAcl  bool   `json:"skipLabdirAcl,omitempty"`  // Corresponds to --skip-labdir-acl flag
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

	// Fields potentially added by --details (use RawMessage if structure is too variable)
	// Details json.RawMessage `json:"details,omitempty"` // Example if using RawMessage
}

// --- Structs for parsing `clab inspect interfaces --format json` output ---

// ClabInspectInterfacesOutput is the top-level array structure
type ClabInspectInterfacesOutput []NodeInterfaceInfo

// NodeInterfaceInfo holds interfaces for a single node
type NodeInterfaceInfo struct {
	NodeName   string          `json:"name"` // Name of the container node
	Interfaces []InterfaceInfo `json:"interfaces"`
}

// InterfaceInfo describes a single network interface
type InterfaceInfo struct {
	Name    string `json:"name"`    // Interface name (e.g., "eth0", "e1-1")
	Alias   string `json:"alias"`   // Interface alias (e.g., "ethernet-1/1", "" if none)
	Mac     string `json:"mac"`     // MAC Address
	IfIndex int    `json:"ifindex"` // Interface index
	Mtu     int    `json:"mtu"`     // MTU size
	Type    string `json:"type"`    // Interface type (e.g., "veth", "device", "dummy")
	State   string `json:"state"`   // Interface state (e.g., "up", "down", "unknown")
}

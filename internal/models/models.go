// internal/models/models.go
package models

import (
	"encoding/json"
)

// Required for RawMessage

// LoginRequest represents the payload for the login endpoint
type LoginRequest struct {
	Username        string `json:"username" binding:"required"`
	Password        string `json:"password" binding:"required"`
	SessionDuration string `json:"sessionDuration,omitempty" example:"24h"`
}

// LoginResponse represents the payload returned after successful login
type LoginResponse struct {
	Token string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzA2OTIyMDAwfQ.abc123"`
}

// DeployRequest represents the payload for deploying a lab.
// Provide EITHER 'topologyContent' OR 'topologySourceUrl', but not both.
type DeployRequest struct {
	// Option 1: Direct Topology Content.
	// Provide the full containerlab topology YAML as a json string.
	// If this is provided, 'topologySourceUrl' MUST be empty.
	// {
	// 	"topologyContent": {
	// 	  "name": "your-lab-name",
	// 	  "topology": {
	// 		"kinds": {
	// 		  "nokia_srlinux": {
	// 			"type": "ixrd3",
	// 			"image": "ghcr.io/nokia/srlinux"
	// 		  }
	// 		},
	// 		"nodes": {
	// 		  "srl1": {
	// 			"kind": "nokia_srlinux"
	// 		  },
	// 		  "srl2": {
	// 			"kind": "nokia_srlinux"
	// 		  }
	// 		},
	// 		"links": [
	// 		  {
	// 			"endpoints": [
	// 			  "srl1:e1-1",
	// 			  "srl2:e1-1"
	// 			]
	// 		  }
	// 		]
	// 	  }
	// 	}
	//   }
	TopologyContent json.RawMessage `json:"topologyContent" swaggertype:"object"`

	// Option 2: Remote Topology Source URL.
	// Provide a URL to a Git repository, a specific .clab.yml file in Git (github/gitlab), or a raw HTTP(S) URL.
	// If this is provided, 'topologyContent' MUST be empty.
	TopologySourceUrl string `json:"topologySourceUrl,omitempty"`
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

// ApplyLabResponse summarizes changes from a containerlab apply operation.
type ApplyLabResponse struct {
	DryRun            bool              `json:"dryRun"`
	DeployedLab       bool              `json:"deployedLab"`
	LabName           string            `json:"labName"`
	AddedNodes        []string          `json:"addedNodes"`
	DeletedNodes      []string          `json:"deletedNodes"`
	RecreatedNodes    []string          `json:"recreatedNodes"`
	StartedNodes      []string          `json:"startedNodes"`
	AddedLinks        []string          `json:"addedLinks"`
	DeletedEndpoints  []string          `json:"deletedEndpoints"`
	RestartedNodes    []string          `json:"restartedNodes"`
	NodeChangeReasons map[string]string `json:"nodeChangeReasons"`
}

// ErrorResponse represents a standard error message format
type ErrorResponse struct {
	Error string `json:"error" example:"Invalid credentials or user not in allowed group"`
}

// GenericSuccessResponse for simple success messages
type GenericSuccessResponse struct {
	Message string `json:"message"`
}

// SimpleSuccessResponse for operations that only return a boolean success flag.
type SimpleSuccessResponse struct {
	Success bool `json:"success" example:"true"`
}

// TopologyDocEventResponse describes a streamed topology document change event.
type TopologyDocEventResponse struct {
	Type         string `json:"type" example:"topology-doc"`
	LabName      string `json:"labName" example:"mylab"`
	Path         string `json:"path" example:"mylab.clab.yml.annotations.json"`
	DocumentKind string `json:"documentKind" example:"annotations"`
	Action       string `json:"action" example:"change"`
	Revision     string `json:"revision" example:"yaml=123-456;annotations=78-910"`
}

// WorkspaceFileEventResponse describes a streamed workspace filesystem change event.
type WorkspaceFileEventResponse struct {
	Type       string `json:"type" example:"workspace-file"`
	Path       string `json:"path" example:"lab1/configs/startup.cfg"`
	ParentPath string `json:"parentPath" example:"lab1/configs"`
	Kind       string `json:"kind,omitempty" example:"file"`
	Action     string `json:"action" example:"delete"`
}

// --- Structs for parsing `clab inspect --format json` output ---

// ClabInspectOutput matches the top-level structure of `clab inspect --all --format json`
type ClabInspectOutput map[string][]ClabContainerInfo

type ClabInspectOutputDetails map[string][]json.RawMessage

// ClabContainerInfo matches the structure of each item in the "Containers" array
type ClabContainerInfo struct {
	Name        string `json:"name"`         // Name of the container node (e.g., "lab01-client1")
	ContainerID string `json:"container_id"` // Docker container ID (short)
	Image       string `json:"image"`        // Container image used
	Kind        string `json:"kind"`         // e.g., "linux", "nokia_srlinux"
	State       string `json:"state"`        // e.g., "running"
	Status      string `json:"status"`       // e.g., "Up 18 hours"
	IPv4Address string `json:"ipv4_address"` // Management IPv4 Address/Mask
	IPv6Address string `json:"ipv6_address"` // Management IPv6 Address/Mask
	LabName     string `json:"lab_name"`     // Name of the lab this node belongs to (redundant with map key but present)
	NodeName    string `json:"nodeName"`     // Topology node name from containerlab labels
	LabPath     string `json:"labPath"`      // Path to the topology file used (relative)
	AbsLabPath  string `json:"absLabPath"`   // Absolute path to topology file
	Group       string `json:"group"`        // Group assigned in topology (Might not always be present)
	Owner       string `json:"owner"`        // OS user from clab inspect output (Used for authorization)
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

// ExecRequest represents the payload for executing a command on lab nodes.
type ExecRequest struct {
	Command string `json:"command" binding:"required" example:"ip addr show eth1"`
}

// ClabExecInternalResult matches the structure within the array in clab's JSON output.
// It contains details about a single command execution attempt on a node.
type ClabExecInternalResult struct {
	Cmd        []string `json:"cmd"`         // The command and its arguments as executed
	ReturnCode int      `json:"return-code"` // Exit code of the command inside the container
	Stdout     string   `json:"stdout"`      // Standard output of the command
	Stderr     string   `json:"stderr"`      // Standard error of the command
}

// ExecResponse represents the structured output (JSON format) from the exec command.
// The keys are the container names. Values are arrays of results (usually one element per array).
type ExecResponse map[string][]ClabExecInternalResult // <--- Changed value to []ClabExecInternalResult

// --- Structs for `clab generate` ---

// GenerateNodeTier defines a tier in the CLOS topology for generation.
type GenerateNodeTier struct {
	Count int    `json:"count" binding:"required,min=1" example:"4"` // Number of nodes in this tier
	Kind  string `json:"kind,omitempty" example:"nokia_srlinux"`     // Node kind (defaults to 'srl'/'nokia_srlinux' if omitted)
	Type  string `json:"type,omitempty" example:"ixrd3"`             // Node type within the kind
}

// GenerateRequest represents the payload for generating a topology file.
type GenerateRequest struct {
	Name  string             `json:"name"           binding:"required" example:"3-tier-clos"`
	Tiers []GenerateNodeTier `json:"tiers"          binding:"required,min=1"`

	DefaultKind string `json:"defaultKind,omitempty"       example:"nokia_srlinux"`

	Images   map[string]string `json:"images"   example:"nokia_srlinux:ghcr.io/nokia/srlinux:latest"`
	Licenses map[string]string `json:"licenses,omitempty" example:"nokia_srlinux:/opt/licenses/srl.lic"`

	NodePrefix        string `json:"nodePrefix,omitempty"        example:"clos-node"`
	GroupPrefix       string `json:"groupPrefix,omitempty"       example:"clos-tier"`
	ManagementNetwork string `json:"managementNetwork,omitempty" example:"clos-mgmt"`
	IPv4Subnet        string `json:"ipv4Subnet,omitempty"        example:"172.20.20.0/24"`
	IPv6Subnet        string `json:"ipv6Subnet,omitempty"        example:"2001:172:20:20::/64"`
	Deploy            bool   `json:"deploy,omitempty"            example:"true"`
	MaxWorkers        int    `json:"maxWorkers,omitempty"        example:"4"`
	OutputFile        string `json:"outputFile,omitempty"        example:"clos.yml"`
}

// GenerateResponse represents the result of the generate command.
type GenerateResponse struct {
	// Message indicating success or failure.
	Message string `json:"message"`
	// The generated topology YAML (only if Deploy=false and OutputFile is empty).
	TopologyYAML string `json:"topologyYaml,omitempty"`
	// The output from the deploy command (only if Deploy=true). JSON object keyed by lab name.
	// Use swaggertype:"object" to represent json.RawMessage in Swagger.
	DeployOutput json.RawMessage `json:"deployOutput,omitempty" swaggertype:"object"`
	// Path where the file was saved (if Deploy=true, it's the path in the user's managed lab directory; if Deploy=false, it's the OutputFile path if provided).
	SavedFilePath string `json:"savedFilePath,omitempty"`
}

// SaveConfigResponse represents the result of the save config command.
type SaveConfigResponse struct {
	// Message indicating overall success.
	Message string `json:"message"`
	// Detailed output from the 'clab save' command (often from stderr).
	Output string `json:"output"`
}

// TopologyEntry describes an editable topology file exposed to the standalone UI.
type TopologyEntry struct {
	LabName             string `json:"labName"`
	YamlFileName        string `json:"yamlFileName"`        // Topology path relative to the managed workspace root.
	AnnotationsFileName string `json:"annotationsFileName"` // Sidecar path relative to the managed workspace root.
	HasAnnotations      bool   `json:"hasAnnotations"`
	DeploymentState     string `json:"deploymentState"` // undeployed (runtime state is derived from events stream)
}

// TopologyFileRenameRequest describes a scoped file rename operation inside a lab directory.
type TopologyFileRenameRequest struct {
	OldPath string `json:"oldPath" binding:"required" example:"configs/startup.cfg"`
	NewPath string `json:"newPath" binding:"required" example:"configs/startup.bak.cfg"`
}

// WorkspaceFileEntry describes one file or directory inside the user's editable lab workspace.
type WorkspaceFileEntry struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Kind        string `json:"kind"` // file or directory
	Size        int64  `json:"size"`
	ModifiedAt  string `json:"modifiedAt"`
	HasChildren bool   `json:"hasChildren"`
}

// WorkspaceFileRenameRequest describes a scoped workspace file rename operation.
type WorkspaceFileRenameRequest struct {
	OldPath string `json:"oldPath" binding:"required" example:"lab1/configs/startup.cfg"`
	NewPath string `json:"newPath" binding:"required" example:"lab1/configs/startup.bak.cfg"`
}

// WorkspaceDirectoryRequest describes a scoped workspace directory creation operation.
type WorkspaceDirectoryRequest struct {
	Path string `json:"path" binding:"required" example:"lab1/configs"`
}

// ImportTopologyFromURLRequest describes an undeployed topology import from a remote source URL.
type ImportTopologyFromURLRequest struct {
	TopologySourceUrl string `json:"topologySourceUrl" binding:"required"`
}

// ImportTopologyFromURLResponse describes the result of an undeployed topology import.
type ImportTopologyFromURLResponse struct {
	Success  bool          `json:"success"`
	LabName  string        `json:"labName"`
	FileName string        `json:"fileName"`
	Topology TopologyEntry `json:"topology"`
}

// --- Structs for Tools ---

// DisableTxOffloadRequest represents the payload for disabling TX offload.
type DisableTxOffloadRequest struct {
	ContainerName string `json:"containerName" binding:"required" example:"clab-my-lab-srl1"`
}

// --- Structs for Cert Tool ---

// CACreateRequest mirrors flags for `clab tools cert ca create`
type CACreateRequest struct {
	Name         string `json:"name,omitempty" example:"my-root-ca"`           // Defaults to "ca" if empty
	Expiry       string `json:"expiry,omitempty" example:"8760h"`              // Duration string, defaults to "87600h" (10 years)
	CommonName   string `json:"commonName,omitempty" example:"ca.example.com"` // Defaults to "containerlab.dev"
	Country      string `json:"country,omitempty" example:"US"`                // Defaults to "Internet"
	Locality     string `json:"locality,omitempty" example:"City"`             // Defaults to "Server"
	Organization string `json:"organization,omitempty" example:"MyOrg"`        // Defaults to "Containerlab"
	OrgUnit      string `json:"orgUnit,omitempty" example:"IT"`                // Defaults to "Containerlab Tools"
	// Path is NOT included - determined by API server based on user
}

// CertSignRequest mirrors flags for `clab tools cert sign`
type CertSignRequest struct {
	Name         string   `json:"name" binding:"required" example:"node1.example.com"` // Required
	Hosts        []string `json:"hosts" binding:"required"`                            // SANs (DNS names or IPs), comma-separated in clab, array here
	CaName       string   `json:"caName" binding:"required" example:"my-root-ca"`      // Name of the CA cert/key files (without .pem/.key) previously generated
	CommonName   string   `json:"commonName,omitempty" example:"node1.example.com"`    // Defaults to Name if empty
	Country      string   `json:"country,omitempty" example:"US"`                      // Defaults to "Internet"
	Locality     string   `json:"locality,omitempty" example:"City"`                   // Defaults to "Server"
	Organization string   `json:"organization,omitempty" example:"MyOrg"`              // Defaults to "Containerlab"
	OrgUnit      string   `json:"orgUnit,omitempty" example:"Nodes"`                   // Defaults to "Containerlab Tools"
	KeySize      int      `json:"keySize,omitempty" example:"4096"`                    // Defaults to 2048
	// Path, CA Cert Path, CA Key Path are NOT included - determined by API server
}

// CertResponse provides paths to the generated certificate files (relative to user's cert dir)
type CertResponse struct {
	Message  string `json:"message"`
	CertPath string `json:"certPath,omitempty"` // e.g., "my-root-ca/my-root-ca.pem" or "my-root-ca/node1.example.com.pem"
	KeyPath  string `json:"keyPath,omitempty"`  // e.g., "my-root-ca/my-root-ca.key" or "my-root-ca/node1.example.com.key"
	CSRPath  string `json:"csrPath,omitempty"`  // e.g., "my-root-ca/my-root-ca.csr" or "my-root-ca/node1.example.com.csr"
}

// VethCreateRequest represents the payload for `clab tools veth create`.
type VethCreateRequest struct {
	// Endpoint A definition. Format: <node-name>:<interface-name> OR <kind>:<node-name>:<interface-name>
	// Example: "clab-demo-node1:eth1" or "bridge:br-1:br-eth1" or "host:veth-eth1"
	AEndpoint string `json:"aEndpoint" binding:"required" example:"clab-demo-node1:eth1"`

	// Endpoint B definition. Format: <node-name>:<interface-name> OR <kind>:<node-name>:<interface-name>
	// Example: "clab-demo-node2:eth1" or "ovs-bridge:ovsbr-1:br-eth1"
	BEndpoint string `json:"bEndpoint" binding:"required" example:"clab-demo-node2:eth1"`

	// MTU for the vEth pair. Defaults to 9500 if omitted.
	Mtu int `json:"mtu,omitempty" example:"1500"` // Use int, convert to string for command
}

// --- Structs for VxLAN Tool ---

// VxlanCreateRequest represents the payload for `clab tools vxlan create`.
type VxlanCreateRequest struct {
	// Remote VTEP IP address.
	Remote string `json:"remote" binding:"required" example:"10.0.0.20"`

	// Name of the existing interface in the root namespace to bridge traffic with.
	Link string `json:"link" binding:"required" example:"srl_e1-1"`

	// VxLAN Network Identifier (VNI). Defaults to 10 if omitted.
	ID int `json:"id,omitempty" example:"100"`

	// UDP port number for the VxLAN tunnel. Defaults to 14789 if omitted.
	Port int `json:"port,omitempty" example:"4789"` // Default is 4789 (IANA standard)

	// Optional: Linux device to use for the tunnel source. Auto-detected if omitted.
	Dev string `json:"dev,omitempty" example:"eth0"`

	// Optional: MTU for the VxLAN interface. Auto-calculated if omitted.
	Mtu int `json:"mtu,omitempty" example:"1400"`
}

// --- Structs for Netem Tool ---

// NetemSetRequest represents the parameters for setting network emulation.
// Use pointers to distinguish between unset and zero values if necessary,
// but clab defaults usually handle zero values correctly (meaning "unset").
type NetemSetRequest struct {
	// Container/node name to apply impairments on (e.g., "clab-my-lab-srl1").
	ContainerName string `json:"containerName" binding:"required" example:"clab-my-lab-srl1"`

	// Interface name or interface alias to apply impairments on (e.g., "eth1" or "mgmt0").
	Interface string `json:"interface" binding:"required" example:"eth1"`

	Delay      string  `json:"delay,omitempty" example:"50ms"`     // Duration string (e.g., "100ms", "1s")
	Jitter     string  `json:"jitter,omitempty" example:"5ms"`     // Duration string, requires Delay
	Loss       float64 `json:"loss,omitempty" example:"10.5"`      // Percentage (0.0 to 100.0)
	Rate       uint    `json:"rate,omitempty" example:"1000"`      // Kbit/s (non-negative integer)
	Corruption float64 `json:"corruption,omitempty" example:"0.1"` // Percentage (0.0 to 100.0)
}

// NetemResetRequest represents the parameters for resetting network emulation on an interface.
type NetemResetRequest struct {
	// Container/node name to reset impairments on (e.g., "clab-my-lab-srl1").
	ContainerName string `json:"containerName" binding:"required" example:"clab-my-lab-srl1"`

	// Interface name or interface alias to reset impairments on (e.g., "eth1" or "mgmt0").
	Interface string `json:"interface" binding:"required" example:"eth1"`
}

// NetemInterfaceInfo holds the netem details for a single interface from `clab tools netem show --format json`
type NetemInterfaceInfo struct {
	Interface  string  `json:"interface"`            // Interface name
	Delay      string  `json:"delay"`                // Duration string or empty
	Jitter     string  `json:"jitter"`               // Duration string or empty
	PacketLoss float64 `json:"packet_loss"`          // Percentage
	Rate       uint    `json:"rate"`                 // Kbit/s
	Corruption float64 `json:"corruption,omitempty"` // Percentage (might be missing in older clab versions)
}

// NetemShowResponse matches the JSON output of `clab tools netem show --format json`
// It's a map where the key is the node name (container name) and the value is a list of interface details.
type NetemShowResponse map[string][]NetemInterfaceInfo

// VersionResponse holds the output of the 'clab version' command.
type VersionResponse struct {
	// Raw output string from 'clab version'.
	VersionInfo string `json:"versionInfo" example:"version: 0.50.0\ncommit: 1234abcd\ndate: 2024-01-15T10:00:00Z\ngithub: https://github.com/srl-labs/containerlab\nrelease notes: https://containerlab.dev/rn/0.50/"`
}

// VersionCheckResponse holds the output of the 'clab version check' command.
type VersionCheckResponse struct {
	// Raw output string from 'clab version check'.
	CheckResult string `json:"checkResult" example:"🎉 A newer containerlab version (0.62.2) is available!\nRelease notes: https://containerlab.dev/rn/0.62/#0622\nRun 'sudo clab version upgrade' or see https://containerlab.dev/install/ for installation options."`
}

// --- Structs for Events ---

// EventResponse represents a single containerlab event in JSON format.
// Events are streamed as newline-delimited JSON (NDJSON).
type EventResponse struct {
	// Unix timestamp when the event occurred
	Time int64 `json:"time" example:"1706918400"`
	// Type of event (e.g., "container", "interface-stats")
	Type string `json:"type" example:"container"`
	// Event action (e.g., "start", "stop", "die", "stats")
	Action string `json:"action" example:"start"`
	// Event attributes containing details about the event
	Attributes EventAttributes `json:"attributes"`
}

// EventAttributes contains the details of a containerlab event.
type EventAttributes struct {
	// Container name
	Name string `json:"name,omitempty" example:"clab-mylab-srl1"`
	// Lab name this event belongs to
	Lab string `json:"lab,omitempty" example:"mylab"`
	// Alternative lab name field (containerlab label)
	Containerlab string `json:"containerlab,omitempty" example:"mylab"`
	// Node name within the lab
	NodeName string `json:"clab-node-name,omitempty" example:"srl1"`
	// Node kind (e.g., nokia_srlinux, linux)
	NodeKind string `json:"clab-node-kind,omitempty" example:"nokia_srlinux"`
	// Node type
	NodeType string `json:"clab-node-type,omitempty" example:"ixrd3"`
	// Container image
	Image string `json:"image,omitempty" example:"ghcr.io/nokia/srlinux:latest"`
	// Exit code (for stop/die events)
	ExitCode string `json:"exitCode,omitempty" example:"0"`
}

// InterfaceStatsEvent represents interface statistics event in JSON format.
type InterfaceStatsEvent struct {
	// Unix timestamp when the stats were collected
	Time int64 `json:"time" example:"1706918400"`
	// Type is always "interface-stats" for this event
	Type string `json:"type" example:"interface-stats"`
	// Action is always "stats" for this event
	Action string `json:"action" example:"stats"`
	// Interface statistics attributes
	Attributes InterfaceStatsAttributes `json:"attributes"`
}

// InterfaceStatsAttributes contains interface statistics details.
type InterfaceStatsAttributes struct {
	// Container name
	Name string `json:"name" example:"clab-mylab-srl1"`
	// Lab name
	Lab string `json:"lab" example:"mylab"`
	// Interface name
	Interface string `json:"interface" example:"e1-1"`
	// Bytes received
	RxBytes uint64 `json:"rx_bytes" example:"123456"`
	// Packets received
	RxPackets uint64 `json:"rx_packets" example:"1000"`
	// Receive errors
	RxErrors uint64 `json:"rx_errors" example:"0"`
	// Receive drops
	RxDropped uint64 `json:"rx_dropped" example:"0"`
	// Bytes transmitted
	TxBytes uint64 `json:"tx_bytes" example:"654321"`
	// Packets transmitted
	TxPackets uint64 `json:"tx_packets" example:"900"`
	// Transmit errors
	TxErrors uint64 `json:"tx_errors" example:"0"`
	// Transmit drops
	TxDropped uint64 `json:"tx_dropped" example:"0"`
}

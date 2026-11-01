package models

import "time"

type CaptureTarget struct {
	ContainerName string `json:"containerName" binding:"required"`
	InterfaceName string `json:"interfaceName" binding:"required"`
	// NodeNamespace marks InterfaceName as the port's name inside the node's
	// network namespace. It is captured there as-is, instead of being resolved
	// through its alias to the host-side end of a stitched link, so a node's
	// links and its own interfaces (e.g. eth0) can share one capture stream.
	NodeNamespace bool `json:"nodeNamespace,omitempty"`
}

type CapturePacketflixRequest struct {
	Targets        []CaptureTarget `json:"targets" binding:"required,min=1"`
	RemoteHostname string          `json:"remoteHostname,omitempty"`
}

type CapturePacketflixURI struct {
	ContainerName  string   `json:"containerName"`
	InterfaceNames []string `json:"interfaceNames"`
	PacketflixURI  string   `json:"packetflixUri"`
}

type CapturePacketflixResponse struct {
	Captures []CapturePacketflixURI `json:"captures"`
}

type CaptureWiresharkVncRequest struct {
	Targets []CaptureTarget `json:"targets" binding:"required,min=1"`
	Theme   string          `json:"theme,omitempty"`
}

type CaptureWiresharkVncSession struct {
	SessionID      string    `json:"sessionId"`
	LabName        string    `json:"labName"`
	ContainerName  string    `json:"containerName"`
	InterfaceNames []string  `json:"interfaceNames"`
	VncPath        string    `json:"vncPath"`
	ShowVolumeTip  bool      `json:"showVolumeTip"`
	CreatedAt      time.Time `json:"createdAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type CaptureWiresharkVncCreateResponse struct {
	Sessions []CaptureWiresharkVncSession `json:"sessions"`
}

type CaptureWiresharkVncReadyResponse struct {
	Ready bool   `json:"ready"`
	URL   string `json:"url"`
}

type EdgeSharkStatusResponse struct {
	Running        bool   `json:"running"`
	Version        string `json:"version,omitempty"`
	PacketflixPort int    `json:"packetflixPort"`
	Runtime        string `json:"runtime"`
}

// CaptureInterfaceInfo is a lab link interface a lab runtime (c9s) captures, with the far end
// of its link.
type CaptureInterfaceInfo struct {
	// Node is the node name as the topology spells it.
	Node string `json:"node" example:"srl1"`
	// Interface is the interface name in the node; capture output names it <node>:<interface>.
	Interface string `json:"interface" example:"e1-1"`
	// Alias is the topology's name for the interface when the node kind maps it.
	Alias string `json:"alias,omitempty" example:"ethernet-1/1"`
	// PeerNode is the node at the other end of the link, "host" for a host endpoint.
	PeerNode string `json:"peerNode" example:"srl2"`
	// PeerInterface is the peer's interface as the topology wrote it.
	PeerInterface string `json:"peerInterface" example:"e1-1"`
}

package models

type NodeBrowserPort struct {
	HostIP        string `json:"hostIp,omitempty"`
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol,omitempty"`
	Description   string `json:"description,omitempty"`
}

type NodeBrowserPortsResponse struct {
	NodeName      string            `json:"nodeName"`
	ContainerName string            `json:"containerName"`
	Ports         []NodeBrowserPort `json:"ports"`
}

type ShareToolResponse struct {
	Message string `json:"message"`
	Link    string `json:"link,omitempty"`
	// ReadOnlyLink is the SSHX read-only access link when readers are enabled.
	ReadOnlyLink string `json:"readOnlyLink,omitempty"`
	// Username is the effective GoTTY login name (attach/reattach only).
	Username string `json:"username,omitempty"`
	// Shell is the effective GoTTY shell (attach/reattach only).
	Shell  string `json:"shell,omitempty"`
	Output string `json:"output,omitempty"`
}

// SSHXShareRequest holds optional SSHX attach/reattach options.
type SSHXShareRequest struct {
	// EnableReaders also creates a read-only access link.
	EnableReaders bool `json:"enableReaders,omitempty" example:"true"`
}

// GoTTYShareRequest holds optional GoTTY attach/reattach options.
// Username and password must be given together.
type GoTTYShareRequest struct {
	Port     int    `json:"port,omitempty" example:"8080"`
	Username string `json:"username,omitempty" example:"admin"`
	Password string `json:"password,omitempty" example:"secret"`
	Shell    string `json:"shell,omitempty" example:"bash"`
}

type FcliCommandRequest struct {
	Command string `json:"command" binding:"required"`
}

type FcliCommandResponse struct {
	Command string `json:"command"`
	Output  string `json:"output"`
}

type DrawioGenerateRequest struct {
	Layout string `json:"layout,omitempty" example:"horizontal"`
	Theme  string `json:"theme,omitempty" example:"nokia_modern"`
}

type DrawioGenerateResponse struct {
	FileName string `json:"fileName"`
	Content  string `json:"content"`
	Layout   string `json:"layout"`
	Message  string `json:"message,omitempty"`
	Output   string `json:"output,omitempty"`
}

// GraphExportRequest holds optional text graph export options.
type GraphExportRequest struct {
	// Direction of the mermaid flowchart: TD, TB, BT, RL or LR (default TD).
	Direction string `json:"direction,omitempty" example:"TD"`
}

// GraphExportResponse returns a generated text graph of a lab topology.
type GraphExportResponse struct {
	FileName  string `json:"fileName" example:"lab01.clab.mermaid"`
	Content   string `json:"content"`
	Format    string `json:"format" example:"mermaid" enums:"mermaid,dot"`
	Direction string `json:"direction,omitempty" example:"TD"`
	Output    string `json:"output,omitempty"`
}

type CaptureCloseAllResponse struct {
	Message string `json:"message"`
	Closed  int    `json:"closed"`
}

type RuntimeImageSummary struct {
	ID          string   `json:"id"`
	ShortID     string   `json:"shortId,omitempty"`
	RepoTags    []string `json:"repoTags"`
	RepoDigests []string `json:"repoDigests"`
	CreatedAt   string   `json:"createdAt,omitempty"`
	Size        string   `json:"size,omitempty"`
	VirtualSize string   `json:"virtualSize,omitempty"`
}

type RuntimeImagesResponse struct {
	Runtime string                `json:"runtime"`
	Images  []RuntimeImageSummary `json:"images"`
}

type RuntimeImagePullRequest struct {
	Image string `json:"image" binding:"required"`
}

type RuntimeImageActionResponse struct {
	Success bool   `json:"success"`
	Image   string `json:"image,omitempty"`
	Message string `json:"message,omitempty"`
	Output  string `json:"output,omitempty"`
}

// Tailscale device roles reported by the lab Tailscale status endpoint.
const (
	TailscaleRoleProxy   = "proxy"
	TailscaleRoleSidecar = "sidecar"
	TailscaleRoleNode    = "node"
)

// TailscaleStatusResponse describes the Tailscale management attachment of a lab
// (mgmt.tailscale in the topology, or nodes of the tailscale kind).
type TailscaleStatusResponse struct {
	LabName string            `json:"labName" example:"mylab"`
	Devices []TailscaleDevice `json:"devices"`
}

// TailscaleDevice is a container of the lab joined to a tailnet.
type TailscaleDevice struct {
	// Role is "proxy" for the SSO proxy (mgmt.tailscale.auth-mode: sso), "sidecar"
	// for the auth-key sidecar of nodeName, or "node" for a node of the tailscale kind.
	Role          string `json:"role" example:"proxy"`
	NodeName      string `json:"nodeName,omitempty" example:"srl1"`
	ContainerName string `json:"containerName" example:"clab-mylab-ts"`
	State         string `json:"state" example:"running"`
	// BackendState is the tailscaled state, e.g. NeedsLogin or Running.
	BackendState string `json:"backendState,omitempty" example:"NeedsLogin"`
	// AuthURL is the login URL to open while the device waits for authentication.
	AuthURL      string   `json:"authUrl,omitempty" example:"https://login.tailscale.com/a/0123456789ab"`
	HostName     string   `json:"hostName,omitempty" example:"clab-mylab"`
	DNSName      string   `json:"dnsName,omitempty" example:"clab-mylab.tailnet-1234.ts.net"`
	TailscaleIPs []string `json:"tailscaleIps,omitempty"`
	Online       bool     `json:"online"`
	// Forwards lists the tailnet ports the SSO proxy forwards to nodes (/ts ports).
	Forwards []TailscaleForward `json:"forwards,omitempty"`
	// Error reports why the tailnet state could not be read.
	Error string `json:"error,omitempty"`
}

// TailscaleForward is a tailnet port of the SSO proxy forwarded to a node.
type TailscaleForward struct {
	ListenPort int    `json:"listenPort" example:"2201"`
	Target     string `json:"target" example:"172.20.20.2:22"`
	NodeName   string `json:"nodeName,omitempty" example:"srl1"`
}

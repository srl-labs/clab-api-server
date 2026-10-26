package models

import "time"

type TerminalProtocol string

const (
	TerminalProtocolSSH    TerminalProtocol = "ssh"
	TerminalProtocolShell  TerminalProtocol = "shell"
	TerminalProtocolTelnet TerminalProtocol = "telnet"
)

type TerminalSessionRequest struct {
	// Protocol selects the terminal transport: ssh, shell, or telnet.
	Protocol TerminalProtocol `json:"protocol" binding:"required"`
	// Cols is the requested terminal width in characters.
	Cols int `json:"cols"`
	// Rows is the requested terminal height in characters.
	Rows int `json:"rows"`
	// SSHUsername optionally overrides the SSH username for protocol=ssh.
	SSHUsername string `json:"sshUsername,omitempty"`
	// TelnetPort optionally overrides the telnet destination port for protocol=telnet.
	TelnetPort int `json:"telnetPort,omitempty"`
	// Resumable keeps the session running when its stream disconnects, so the
	// client can attach again. Without it the session ends with its stream.
	Resumable bool `json:"resumable,omitempty"`
}

type TerminalSessionInfo struct {
	SessionID    string           `json:"sessionId"`
	Username     string           `json:"username"`
	LabName      string           `json:"labName"`
	NodeName     string           `json:"nodeName"`
	Protocol     TerminalProtocol `json:"protocol"`
	State        string           `json:"state"`
	CreatedAt    time.Time        `json:"createdAt"`
	ExpiresAt    time.Time        `json:"expiresAt"`
	LastActivity time.Time        `json:"lastActivity"`
	// Resumable reports whether the session outlives a disconnected stream.
	Resumable bool `json:"resumable"`
	// Attached reports whether a client is connected to the session's stream.
	Attached bool   `json:"attached"`
	ExitCode *int   `json:"exitCode,omitempty"`
	Error    string `json:"error,omitempty"`
}

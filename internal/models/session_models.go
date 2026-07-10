package models

import "time"

// SessionResponse describes the authenticated API identity represented by the
// bearer token. Role names are stable API values, not configurable Linux group
// names.
type SessionResponse struct {
	Username  string     `json:"username"`
	Roles     []string   `json:"roles"`
	IssuedAt  *time.Time `json:"issuedAt,omitempty"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// CapabilitiesResponse advertises the stable API contract level and optional
// protocol features supported by this server build.
type CapabilitiesResponse struct {
	APIVersion    string   `json:"apiVersion" example:"v1"`
	ServerVersion string   `json:"serverVersion" example:"v0.5.0"`
	Runtime       string   `json:"runtime" example:"docker"`
	Features      []string `json:"features"`
}

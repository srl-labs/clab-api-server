// internal/models/user_models.go
package models

// UserDetails represents information about a system user
type UserDetails struct {
	Username    string   `json:"username"`
	UID         string   `json:"uid,omitempty"`
	GID         string   `json:"gid,omitempty"`
	DisplayName string   `json:"displayName,omitempty"` // Full name from GECOS field
	HomeDir     string   `json:"homeDir,omitempty"`
	Shell       string   `json:"shell,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	IsSuperuser bool     `json:"isSuperuser,omitempty"`
	IsAPIUser   bool     `json:"isApiUser,omitempty"`
}

// UserCreateRequest represents a request to create a new system user
type UserCreateRequest struct {
	Username    string   `json:"username" binding:"required"`
	Password    string   `json:"password" binding:"required"`
	DisplayName string   `json:"displayName,omitempty"`
	Shell       string   `json:"shell,omitempty"` // Default to /bin/bash if empty
	Groups      []string `json:"groups,omitempty"`
	IsSuperuser bool     `json:"isSuperuser,omitempty"`
}

// UserUpdateRequest represents a request to update user information
type UserUpdateRequest struct {
	DisplayName string   `json:"displayName,omitempty"`
	Shell       string   `json:"shell,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	IsSuperuser bool     `json:"isSuperuser,omitempty"`
}

// PasswordChangeRequest represents a request to change a user's password
type PasswordChangeRequest struct {
	CurrentPassword string `json:"currentPassword,omitempty"` // Required if not superuser
	NewPassword     string `json:"newPassword" binding:"required"`
}

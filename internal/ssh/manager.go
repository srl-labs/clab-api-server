// internal/ssh/manager.go
package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// Configuration constants for SSH proxy service
const (
	DefaultSSHBasePort       = 2223           // Starting port for SSH proxy allocation
	DefaultSSHMaxPort        = 2322           // Maximum port (allows 100 concurrent sessions)
	DefaultSSHCleanupTick    = time.Minute    // Cleanup interval for expired sessions
	DefaultSSHSessionTimeout = time.Hour      // Default session duration if not specified
	MaxSSHSessionDuration    = 24 * time.Hour // Maximum allowed session duration
)

// SSHSession represents an active SSH proxy session
type SSHSession struct {
	Port        int       // Allocated port on API server
	LabName     string    // Name of the lab
	NodeName    string    // Name of the node within the lab
	Username    string    // SSH username to use
	ApiUsername string    // API user who created this session
	Expiration  time.Time // When this session expires
	Created     time.Time // When this session was created
	cmd         *exec.Cmd // Proxy process
	cmdCancel   func()    // Function to cancel the proxy process
}

// SSHManager handles SSH session creation, management, and cleanup
type SSHManager struct {
	mu              sync.Mutex
	sessions        map[int]*SSHSession
	basePort        int
	maxPort         int
	cleanupTick     time.Duration
	defaultDuration time.Duration
	shutdownCh      chan struct{}
}

// NewSSHManager creates a new SSH manager with the given configuration
func NewSSHManager(basePort, maxPort int, cleanupTick, defaultDuration time.Duration) *SSHManager {
	if basePort <= 0 {
		basePort = DefaultSSHBasePort
	}
	if maxPort <= basePort {
		maxPort = basePort + 100 // Ensure at least some ports are available
	}
	if cleanupTick <= 0 {
		cleanupTick = DefaultSSHCleanupTick
	}
	if defaultDuration <= 0 {
		defaultDuration = DefaultSSHSessionTimeout
	}

	m := &SSHManager{
		sessions:        make(map[int]*SSHSession),
		basePort:        basePort,
		maxPort:         maxPort,
		cleanupTick:     cleanupTick,
		defaultDuration: defaultDuration,
		shutdownCh:      make(chan struct{}),
	}

	// Start background cleanup
	go m.cleanupRoutine()

	log.Info("SSH Manager initialized",
		"basePort", basePort,
		"maxPort", maxPort,
		"cleanupInterval", cleanupTick.String(),
		"defaultDuration", defaultDuration.String())

	return m
}

// CreateSession creates a new SSH proxy session for the specified lab node
func (m *SSHManager) CreateSession(apiUsername, labName, nodeName, sshUsername string,
	containerIP string, containerPort int, duration time.Duration) (*SSHSession, error) {

	if duration > MaxSSHSessionDuration {
		duration = MaxSSHSessionDuration
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Allocate port
	port, err := m.allocatePort()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate port: %w", err)
	}

	// Create session
	now := time.Now()
	session := &SSHSession{
		Port:        port,
		LabName:     labName,
		NodeName:    nodeName,
		Username:    sshUsername,
		ApiUsername: apiUsername,
		Created:     now,
		Expiration:  now.Add(duration),
	}

	// Start proxy
	err = m.startProxy(session, containerIP, containerPort)
	if err != nil {
		// Free the port if proxy fails to start
		m.sessions[port] = nil
		return nil, fmt.Errorf("failed to start SSH proxy: %w", err)
	}

	// Store session
	m.sessions[port] = session

	log.Info("SSH session created",
		"user", apiUsername,
		"lab", labName,
		"node", nodeName,
		"port", port,
		"expiration", session.Expiration.Format(time.RFC3339))

	return session, nil
}

// GetSession retrieves a session by port
func (m *SSHManager) GetSession(port int) (*SSHSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[port]
	if !exists || session == nil {
		return nil, false
	}
	return session, true
}

// ListSessions returns all sessions for the specified user
// If isSuperuser is true, all sessions are returned
func (m *SSHManager) ListSessions(username string, isSuperuser bool) []models.SSHSessionInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Initialize as an empty slice, NOT a nil slice
	result := make([]models.SSHSessionInfo, 0) // <--- CHANGE THIS LINE

	// Add logging to see map content (optional, for debugging)
	log.Debugf("Listing SSH sessions. Current map size: %d", len(m.sessions))

	for port, session := range m.sessions {
		if session == nil {
			log.Debugf("Skipping nil session entry for port %d", port)
			continue
		}

		// Add logging for filtering logic (optional, for debugging)
		log.Debugf("Checking session on port %d: ApiUsername=%s, targetUsername=%s, isSuperuser=%t",
			port, session.ApiUsername, username, isSuperuser)

		if isSuperuser || session.ApiUsername == username {
			result = append(result, models.SSHSessionInfo{
				Port:       session.Port,
				LabName:    session.LabName,
				NodeName:   session.NodeName,
				Username:   session.Username,
				Expiration: session.Expiration,
				Created:    session.Created,
			})
			log.Debugf("Added session on port %d to results.", port)
		}
	}

	// Add logging to see the final result before returning (optional, for debugging)
	log.Debugf("Returning %d SSH sessions.", len(result))

	return result
}

// TerminateSession terminates a specific SSH session
func (m *SSHManager) TerminateSession(port int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[port]
	if !exists || session == nil {
		return fmt.Errorf("session not found")
	}

	// Terminate proxy
	if session.cmdCancel != nil {
		session.cmdCancel()
	}

	// Remove session
	delete(m.sessions, port)

	log.Info("SSH session terminated", "port", port, "lab", session.LabName, "node", session.NodeName)
	return nil
}

// Shutdown terminates all sessions and stops the manager
func (m *SSHManager) Shutdown() {
	close(m.shutdownCh)

	// Terminate all sessions
	m.mu.Lock()
	defer m.mu.Unlock()

	for port, session := range m.sessions {
		if session != nil && session.cmdCancel != nil {
			session.cmdCancel()
		}
		delete(m.sessions, port)
	}

	log.Info("SSH Manager shutdown complete")
}

// allocatePort finds and allocates an available port
func (m *SSHManager) allocatePort() (int, error) {
	// Try each port in the range
	for port := m.basePort; port <= m.maxPort; port++ {
		// Skip if port is already in use by another session
		if _, exists := m.sessions[port]; exists {
			continue
		}

		// Test if port is available on the system
		addr := fmt.Sprintf(":%d", port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			// Port is in use by another process
			continue
		}
		ln.Close()

		// Reserve this port by creating a nil entry
		m.sessions[port] = nil
		return port, nil
	}

	return 0, fmt.Errorf("no available ports in range %d-%d", m.basePort, m.maxPort)
}

// startProxy starts a proxy process for the given session
func (m *SSHManager) startProxy(session *SSHSession, containerIP string, containerPort int) error {
	// We'll use a TCP proxy in Go instead of relying on external tools like socat
	go func() {
		localAddr := fmt.Sprintf("0.0.0.0:%d", session.Port)
		remoteAddr := fmt.Sprintf("%s:%d", containerIP, containerPort)

		log.Debug("Starting TCP proxy",
			"localAddr", localAddr,
			"remoteAddr", remoteAddr,
			"session", session.Port)

		listener, err := net.Listen("tcp", localAddr)
		if err != nil {
			log.Error("Failed to listen on proxy port",
				"port", session.Port,
				"error", err)
			return
		}
		defer listener.Close()

		// Create a context with cancel function for termination
		ctx, cancel := context.WithCancel(context.Background())
		session.cmdCancel = cancel

		// Run the proxy until canceled or expired
		go func() {
			select {
			case <-ctx.Done():
				listener.Close()
			case <-time.After(session.Expiration.Sub(time.Now())):
				// Session expired
				listener.Close()
				m.TerminateSession(session.Port)
			}
		}()

		for {
			client, err := listener.Accept()
			if err != nil {
				// Check if this is due to listener being closed
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					continue
				}
				return
			}

			go handleConnection(client, remoteAddr)
		}
	}()

	return nil
}

// handleConnection manages a single proxied connection
func handleConnection(client net.Conn, remoteAddr string) {
	defer client.Close()

	remote, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		log.Error("Failed to connect to remote address",
			"remoteAddr", remoteAddr,
			"error", err)
		return
	}
	defer remote.Close()

	// Copy bidirectionally
	errCh := make(chan error, 2)

	// client -> remote
	go func() {
		_, err := io.Copy(remote, client)
		errCh <- err
	}()

	// remote -> client
	go func() {
		_, err := io.Copy(client, remote)
		errCh <- err
	}()

	// Wait for either direction to finish
	<-errCh
}

// cleanupRoutine periodically removes expired sessions
func (m *SSHManager) cleanupRoutine() {
	ticker := time.NewTicker(m.cleanupTick)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanupExpiredSessions()
		case <-m.shutdownCh:
			return
		}
	}
}

// cleanupExpiredSessions removes all expired sessions
func (m *SSHManager) cleanupExpiredSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for port, session := range m.sessions {
		if session == nil {
			// This is a reserved port without a session, clean it up
			delete(m.sessions, port)
			continue
		}

		if now.After(session.Expiration) {
			// Terminate the proxy
			if session.cmdCancel != nil {
				session.cmdCancel()
			}

			// Remove the session
			delete(m.sessions, port)
			log.Info("Expired SSH session cleaned up",
				"port", port,
				"lab", session.LabName,
				"node", session.NodeName)
		}
	}
}

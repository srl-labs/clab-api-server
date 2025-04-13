// internal/clab/executor.go
package clab

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/FloSch62/clab-api/internal/config"
	"github.com/charmbracelet/log"
)

const clabExecutable = "clab"          // Assumes clab is in PATH
const defaultTimeout = 5 * time.Minute // Timeout for clab commands

// RunClabCommand executes a clab command directly as the user running the API server.
func RunClabCommand(ctx context.Context, username string, args ...string) (stdout string, stderr string, err error) {
	// Add timeout to context if not already present
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}

	// --- Prepare final arguments including runtime ---
	finalArgs := []string{}
	if len(args) > 0 {
		finalArgs = append(finalArgs, args[0]) // Add the subcommand (deploy, inspect, etc.)

		// Add --runtime flag if needed (and not the default)
		configuredRuntime := config.AppConfig.ClabRuntime
		if configuredRuntime != "" && configuredRuntime != "docker" {
			// Use log.Debug (key-value) instead of log.Debugf
			log.Debug("Using non-default container runtime", "runtime", configuredRuntime)
			finalArgs = append(finalArgs, "--runtime", configuredRuntime)
		} else {
			// Use log.Debug (key-value) instead of log.Debugf
			log.Debug("Using default container runtime", "runtime", "docker")
		}

		// Add the rest of the original arguments
		if len(args) > 1 {
			finalArgs = append(finalArgs, args[1:]...)
		}
	} else {
		// Should not happen with current usage, but handle gracefully
		finalArgs = args
	}
	// --- End argument preparation ---

	// Construct the command string for logging using the final arguments
	commandString := fmt.Sprintf("%s %s", clabExecutable, strings.Join(finalArgs, " "))
	cmd := exec.CommandContext(ctx, clabExecutable, finalArgs...) // Use finalArgs

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	// Log which *authenticated* user triggered the command, even though it runs as the server user.
	// Use log.Debug (key-value) instead of log.Debugf
	log.Debug("Executing command",
		"triggered_by_user", username,
		"runtime", config.AppConfig.ClabRuntime,
		"command", commandString,
		"cwd", cmd.Dir, // cmd.Dir might be empty if not set, which is fine
	)

	startTime := time.Now()
	err = cmd.Run()
	duration := time.Since(startTime)

	stdout = outBuf.String()
	stderr = errBuf.String()

	if ctx.Err() == context.DeadlineExceeded {
		// Use log.Error (key-value) instead of log.Errorf
		log.Error("Command timed out",
			"duration", duration,
			"triggered_by_user", username,
			"command", commandString,
		)
		return stdout, stderr, fmt.Errorf("clab command timed out after %s (triggered by user: %s)", duration, username)
	}

	if err != nil {
		// Include stderr in the error message for better debugging context
		// Use log.Error (key-value) instead of log.Errorf
		log.Error("Command failed",
			"triggered_by_user", username,
			"duration", duration,
			"error", err,
			"stderr", stderr, // Include stderr directly in structured log
		)
		return stdout, stderr, fmt.Errorf("clab command failed (triggered by user: %s, duration: %s): %w\nstderr: %s", username, duration, err, stderr)
	}

	// Use log.Debug (key-value) instead of log.Debugf
	log.Debug("Command successful",
		"triggered_by_user", username,
		"duration", duration,
		"stdout_len", len(stdout),
		"stderr_len", len(stderr),
	)
	return stdout, stderr, nil
}

// SanitizePath prevents path traversal.
// Returns the cleaned path if valid, otherwise an error.
func SanitizePath(relativePath string) (string, error) {
	// Clean the input path first (removes redundant slashes, dots)
	cleanedPath := filepath.Clean(relativePath)

	// Security Check: Prevent absolute paths or paths starting with '../' in the input
	// Allow paths starting with './' or just filename.
	if filepath.IsAbs(cleanedPath) || strings.HasPrefix(cleanedPath, ".."+string(filepath.Separator)) || cleanedPath == ".." {
		log.Warnf("Path traversal attempt blocked", "requested_path", relativePath, "cleaned_path", cleanedPath) // Warnf is ok here
		return "", fmt.Errorf("invalid path: '%s' must be relative and cannot start with '..'", relativePath)
	}

	// Use log.Debug (key-value) instead of log.Debugf
	log.Debug("Sanitized path", "original", relativePath, "cleaned", cleanedPath)
	return cleanedPath, nil
}

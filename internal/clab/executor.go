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

	"github.com/FloSch62/clab-api/internal/config" // Ensure config is imported
	"github.com/charmbracelet/log"
)

const clabExecutable = "clab"          // Assumes clab is in PATH
const defaultTimeout = 5 * time.Minute // Timeout for clab commands

// RunClabCommand executes a clab command directly as the user running the API server.
// It captures and returns stdout and stderr.
// It now includes the configured --runtime flag if it's not the default 'docker'.
// The 'username' parameter is now primarily for logging and potential labeling,
// NOT for setting the execution user.
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
			log.Debugf("Using non-default container runtime: %s", configuredRuntime)
			finalArgs = append(finalArgs, "--runtime", configuredRuntime)
		} else {
			log.Debugf("Using default container runtime: docker")
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

	// Working directory: Let clab run from the API server's CWD by default.
	// If specific CWD is needed (e.g., for relative paths in non-temporary topologies),
	// it must be handled by the caller or configured globally.
	// cmd.Dir = ??? // Removed user home dir logic

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	// Log which *authenticated* user triggered the command, even though it runs as the server user.
	log.Debugf("Executing command", "triggered_by_user", username, "runtime", config.AppConfig.ClabRuntime, "command", commandString, "cwd", cmd.Dir)

	startTime := time.Now()
	err = cmd.Run()
	duration := time.Since(startTime)

	stdout = outBuf.String()
	stderr = errBuf.String()

	if ctx.Err() == context.DeadlineExceeded {
		log.Errorf("Command timed out after %s", duration, "triggered_by_user", username, "command", commandString)
		return stdout, stderr, fmt.Errorf("clab command timed out after %s (triggered by user: %s)", duration, username)
	}

	if err != nil {
		// Include stderr in the error message for better debugging context
		log.Errorf("Command failed", "triggered_by_user", username, "duration", duration, "error", err, "stderr", stderr)
		return stdout, stderr, fmt.Errorf("clab command failed (triggered by user: %s, duration: %s): %w\nstderr: %s", username, duration, err, stderr)
	}

	log.Debugf("Command successful", "triggered_by_user", username, "duration", duration, "stdout_len", len(stdout), "stderr_len", len(stderr))
	return stdout, stderr, nil
}

// SanitizePath prevents path traversal.
// It no longer assumes paths are relative to a specific user's home directory.
// It's less critical now as paths are handled differently, but basic cleaning is good.
// Returns the cleaned path if valid, otherwise an error.
func SanitizePath(relativePath string) (string, error) {
	// Clean the input path first (removes redundant slashes, dots)
	cleanedPath := filepath.Clean(relativePath)

	// Security Check: Prevent absolute paths or paths starting with '../' in the input
	// Allow paths starting with './' or just filename.
	if filepath.IsAbs(cleanedPath) || strings.HasPrefix(cleanedPath, ".."+string(filepath.Separator)) || cleanedPath == ".." {
		log.Warnf("Path traversal attempt blocked", "requested_path", relativePath, "cleaned_path", cleanedPath)
		return "", fmt.Errorf("invalid path: '%s' must be relative and cannot start with '..'", relativePath)
	}

	log.Debugf("Sanitized path: '%s' -> '%s'", relativePath, cleanedPath)
	return cleanedPath, nil
}

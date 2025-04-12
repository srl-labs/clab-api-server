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

	"github.com/charmbracelet/log"
)

const clabExecutable = "clab" // Assumes clab is in PATH
const defaultTimeout = 5 * time.Minute // Timeout for clab commands

// RunClabCommand executes a clab command directly as the user running the API server.
// It captures and returns stdout and stderr.
// The 'username' parameter is now primarily for logging and potential labeling,
// NOT for setting the execution user.
func RunClabCommand(ctx context.Context, username string, args ...string) (stdout string, stderr string, err error) {
	// Add timeout to context if not already present
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}

	// Construct the command: just 'clab <args...>'
	commandString := fmt.Sprintf("%s %s", clabExecutable, strings.Join(args, " ")) // For logging
	cmd := exec.CommandContext(ctx, clabExecutable, args...)

	// Working directory: Let clab run from the API server's CWD by default.
	// If specific CWD is needed (e.g., for relative paths in non-temporary topologies),
	// it must be handled by the caller or configured globally.
	// cmd.Dir = ??? // Removed user home dir logic

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	// Log which *authenticated* user triggered the command, even though it runs as the server user.
	log.Debugf("Executing command", "triggered_by_user", username, "command", commandString, "cwd", cmd.Dir)

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

	// Security Check: Ensure the filename ends with .clab.yml or .clab.yaml if it's likely a topology file
	// This check might be too strict depending on how the path is used. Consider removing if needed.
	// if strings.Contains(cleanedPath, ".") && !strings.HasSuffix(cleanedPath, ".clab.yml") && !strings.HasSuffix(cleanedPath, ".clab.yaml") {
	// 	log.Warnf("Path validation warning: Path '%s' does not have expected .clab suffix", cleanedPath)
	// 	// Decide if this should be an error or just a warning
	// 	// return "", fmt.Errorf("invalid topology filename: must end with .clab.yml or .clab.yaml")
	// }

	log.Debugf("Sanitized path: '%s' -> '%s'", relativePath, cleanedPath)
	return cleanedPath, nil
}
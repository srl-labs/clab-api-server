// internal/clab/executor.go
package clab

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/srl-labs/clab-api-server/internal/config"
)

const clabExecutable = "containerlab"  // Assumes clab is in PATH
const defaultTimeout = 5 * time.Minute // Timeout for clab commands

// RunClabCommand executes a clab command directly as the user running the API server,
// using the authenticated user's ~/.clab/ directory as the working directory.
func RunClabCommand(ctx context.Context, username string, args ...string) (stdout string, stderr string, err error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}

	// Find the user's home directory and create path to ~/.clab/
	usr, lookupErr := user.Lookup(username)
	if lookupErr != nil {
		return "", "", fmt.Errorf("failed to lookup user: %w", lookupErr)
	}

	// Create path to ~/.clab/ directory and ensure it exists
	clabDir := filepath.Join(usr.HomeDir, ".clab")
	if mkdirErr := os.MkdirAll(clabDir, 0750); mkdirErr != nil {
		return "", "", fmt.Errorf("failed to create .clab directory: %w", mkdirErr)
	}

	// Try to set ownership of the .clab directory to the actual user
	uid, uidErr := strconv.Atoi(usr.Uid)
	gid, gidErr := strconv.Atoi(usr.Gid)
	if uidErr == nil && gidErr == nil {
		if chownErr := os.Chown(clabDir, uid, gid); chownErr != nil {
			// Just log a warning if we can't set ownership
			log.Warn("Failed to set ownership on .clab directory",
				"dir", clabDir,
				"user", username,
				"error", chownErr,
			)
		}
	}

	// --- Prepare final arguments including runtime ---
	finalArgs := []string{}
	if len(args) > 0 {
		finalArgs = append(finalArgs, args[0]) // Add the subcommand (deploy, inspect, etc.)

		// Add --runtime flag if needed (and not the default)
		configuredRuntime := config.AppConfig.ClabRuntime
		if configuredRuntime != "" && configuredRuntime != "docker" {
			log.Debug("Using non-default container runtime", "runtime", configuredRuntime)
			finalArgs = append(finalArgs, "--runtime", configuredRuntime)
		} else {
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

	// Set working directory to user's ~/.clab/ directory
	cmd.Dir = clabDir

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	// Log which *authenticated* user triggered the command, even though it runs as the server user.
	log.Debug("Executing command",
		"triggered_by_user", username,
		"runtime", config.AppConfig.ClabRuntime,
		"command", commandString,
		"cwd", cmd.Dir,
	)

	startTime := time.Now()
	err = cmd.Run()
	duration := time.Since(startTime)

	stdout = outBuf.String()
	stderr = errBuf.String()

	if ctx.Err() == context.DeadlineExceeded {
		log.Error("Command timed out",
			"duration", duration,
			"triggered_by_user", username,
			"command", commandString,
		)
		return stdout, stderr, fmt.Errorf("clab command timed out after %s (triggered by user: %s)", duration, username)
	}

	if err != nil {
		// Include stderr in the error message for better debugging context
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
		log.Warn("Path traversal attempt blocked", "requested_path", relativePath, "cleaned_path", cleanedPath)
		return "", fmt.Errorf("invalid path: '%s' must be relative and cannot start with '..'", relativePath)
	}

	// Use log.Debug (key-value) instead of log.Debugf
	log.Debug("Sanitized path", "original", relativePath, "cleaned", cleanedPath)
	return cleanedPath, nil
}

func RunCommandWithWriters(ctx context.Context, stdout io.Writer, stderr io.Writer, command string, args ...string) (string, string, error) {
	// Create command with context for cancellation
	cmd := exec.CommandContext(ctx, command, args...)

	// Create pipes for stdout and stderr
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", "", err
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return "", "", err
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return "", "", err
	}

	// Use WaitGroup to ensure both goroutines complete
	var wg sync.WaitGroup
	wg.Add(2)

	// Copy stdout to writer and buffer simultaneously if needed
	go func() {
		defer wg.Done()
		io.Copy(stdout, stdoutPipe)
	}()

	// Copy stderr to writer and buffer simultaneously if needed
	go func() {
		defer wg.Done()
		io.Copy(stderr, stderrPipe)
	}()

	// Wait for both pipes to be closed
	wg.Wait()

	// Wait for the command to complete
	err = cmd.Wait()

	// For consistency with RunCommand, we return empty strings for stdout and stderr
	// since we've already streamed them to the provided writers
	return "", "", err
}

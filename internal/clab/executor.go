package clab

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/log"
)

const clabExecutable = "clab" // Assumes clab is in PATH
const defaultTimeout = 5 * time.Minute // Timeout for clab commands

// RunClabCommand executes a clab command as a specific Linux user using sudo.
// It captures and returns stdout and stderr.
// Assumes the user running *this* process has passwordless sudo rights for clab.
func RunClabCommand(ctx context.Context, username string, args ...string) (stdout string, stderr string, err error) {
	// Find the user to get the home directory, needed for working directory
	usr, err := user.Lookup(username)
	if err != nil {
		// Handle root user lookup failure gracefully if possible
		if username == "root" {
			usr = &user.User{Uid: "0", Gid: "0", Username: "root", Name: "root", HomeDir: "/root"}
			log.Warn("Could not look up user 'root', proceeding with default HomeDir=/root")
		} else {
			log.Errorf("Failed to lookup user '%s' for clab command: %v", username, err)
			return "", "", fmt.Errorf("failed to lookup user '%s': %w", username, err)
		}
	}

	// Add timeout to context if not already present
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}

	// Construct the command using sudo -u <username> clab ...
	// We run 'clab' itself via sudo, not just the container actions.
	// This ensures clab operates within the user's context (e.g., finding relative topo files).
	fullArgs := append([]string{"-u", username, clabExecutable}, args...)
	commandString := fmt.Sprintf("sudo %s", strings.Join(fullArgs, " ")) // For logging
	cmd := exec.CommandContext(ctx, "sudo", fullArgs...)

	// Set working directory to the target user's home directory
	// This helps clab resolve relative topology paths correctly.
	cmd.Dir = usr.HomeDir

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	log.Debugf("Executing command", "user", username, "command", commandString, "cwd", cmd.Dir)

	startTime := time.Now()
	err = cmd.Run()
	duration := time.Since(startTime)

	stdout = outBuf.String()
	stderr = errBuf.String()

	if ctx.Err() == context.DeadlineExceeded {
		log.Errorf("Command timed out after %s", duration, "user", username, "command", commandString)
		return stdout, stderr, fmt.Errorf("clab command timed out after %s (user: %s)", duration, username)
	}

	if err != nil {
		// Include stderr in the error message for better debugging context
		log.Errorf("Command failed", "user", username, "duration", duration, "error", err, "stderr", stderr)
		return stdout, stderr, fmt.Errorf("clab command failed (user: %s, duration: %s): %w\nstderr: %s", username, duration, err, stderr)
	}

	log.Debugf("Command successful", "user", username, "duration", duration, "stdout_len", len(stdout), "stderr_len", len(stderr))
	return stdout, stderr, nil
}

// SanitizePath prevents path traversal and ensures the path is relative
// to the user's home directory and has the correct suffix.
// Returns the absolute, cleaned path if valid, otherwise an error.
func SanitizePath(username, relativePath string) (string, error) {
	usr, err := user.Lookup(username)
	if err != nil {
		if username == "root" {
			usr = &user.User{Uid: "0", Gid: "0", Username: "root", Name: "root", HomeDir: "/root"}
		} else {
			return "", fmt.Errorf("failed to lookup user '%s': %w", username, err)
		}
	}
	homeDir := usr.HomeDir

	// Clean the input path first (removes redundant slashes, dots)
	cleanedRelativePath := filepath.Clean(relativePath)

	// Security Check: Prevent absolute paths or paths starting with '../' in the input
	if filepath.IsAbs(cleanedRelativePath) || strings.HasPrefix(cleanedRelativePath, ".."+string(filepath.Separator)) || cleanedRelativePath == ".." {
		log.Warnf("Path traversal attempt blocked", "username", username, "requested_path", relativePath, "cleaned_relative", cleanedRelativePath)
		return "", fmt.Errorf("invalid path: '%s' must be relative to the home directory and cannot start with '..'", relativePath)
	}

	// Join home directory with the cleaned relative path
	absPath := filepath.Join(homeDir, cleanedRelativePath)

	// Final clean on the absolute path (should be redundant but safe)
	finalPath := filepath.Clean(absPath)

	// Security Check: Ensure the final absolute path is still within the user's home directory.
	// This prevents issues if the relative path somehow resolved outside after joining (e.g., symlinks - though less likely with prior checks).
	if !strings.HasPrefix(finalPath, homeDir+string(filepath.Separator)) && finalPath != homeDir {
        // Special case for root user if home dir lookup failed but we defaulted
        isAllowedRootPath := username == "root" && (strings.HasPrefix(finalPath, "/root"+string(filepath.Separator)) || finalPath == "/root")
        if !isAllowedRootPath {
            log.Warnf("Path validation failed: Final path '%s' is outside expected home directory '%s'", finalPath, homeDir)
            return "", fmt.Errorf("invalid path: '%s' resolves outside allowed directory", relativePath)
        }
	}


	// Security Check: Ensure the filename ends with .clab.yml or .clab.yaml
	if !strings.HasSuffix(finalPath, ".clab.yml") && !strings.HasSuffix(finalPath, ".clab.yaml") {
		log.Warnf("Path validation failed: Filename '%s' does not have required suffix", finalPath)
		return "", fmt.Errorf("invalid topology filename: must end with .clab.yml or .clab.yaml")
	}

	log.Debugf("Sanitized path for user '%s': '%s' -> '%s'", username, relativePath, finalPath)
	return finalPath, nil
}
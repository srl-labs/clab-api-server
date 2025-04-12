package auth

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"os/user"
	"strings"
	"time"

	"github.com/charmbracelet/log"
)

// ValidateCredentials checks if the Linux user exists and attempts to validate
// the provided password using `sudo -S /bin/true`.
// This is more secure than the placeholder but requires sudo to be configured correctly.
// It relies on the principle that `sudo -S` reading the password from stdin
// will exit with 0 if the password is correct for the target user, and non-zero otherwise.
func ValidateCredentials(username, password string) (bool, error) {
	// 1. Check if the user exists on the system
	_, err := user.Lookup(username)
	if err != nil {
		if _, ok := err.(user.UnknownUserError); ok {
			log.Infof("Login attempt failed: User '%s' not found", username)
			return false, nil // User not found -> invalid credentials
		}
		// Other system error looking up user
		log.Errorf("Error looking up user '%s': %v", username, err)
		return false, fmt.Errorf("system error checking user existence: %w", err)
	}

	// 2. Attempt password validation using sudo
	// We use a short timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // 5-second timeout for sudo check
	defer cancel()

	// Command: sudo -k -S -u <username> /bin/true
	// -k: Invalidate cached credentials (force password prompt)
	// -S: Read password from stdin
	// -u <username>: Run command as the target user
	// /bin/true: A simple command that does nothing and exits successfully (if sudo auth passes)
	cmd := exec.CommandContext(ctx, "sudo", "-k", "-S", "-u", username, "/bin/true")

	// Pipe the password to the command's stdin
	cmd.Stdin = strings.NewReader(password)

	// Capture stderr for potential sudo error messages (e.g., "incorrect password")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	log.Debugf("Attempting password validation for user '%s' via sudo", username)

	// Run the command
	err = cmd.Run()

	// Analyze the result
	if ctx.Err() == context.DeadlineExceeded {
		log.Warnf("Password validation for user '%s' timed out", username)
		return false, fmt.Errorf("password validation timed out")
	}

	if err != nil {
		// Check if it's an exit error (command finished but with non-zero status)
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderrStr := strings.TrimSpace(stderr.String())
			log.Infof("Login attempt failed for user '%s': sudo validation failed (Exit code: %d). Stderr: %s", username, exitErr.ExitCode(), stderrStr)
			// Common sudo error messages indicate incorrect password
			if strings.Contains(stderrStr, "incorrect password attempt") || exitErr.ExitCode() == 1 {
				return false, nil // Incorrect password -> invalid credentials
			}
			// Other sudo error (e.g., user not allowed to run sudo, command not found)
			return false, fmt.Errorf("sudo validation failed: %s", stderrStr)
		}
		// Other error running the command (e.g., sudo not found)
		log.Errorf("Error executing sudo for password validation for user '%s': %v", username, err)
		return false, fmt.Errorf("failed to execute validation command: %w", err)
	}

	// If err is nil, the command exited successfully (status 0) -> password is correct
	log.Infof("Password validation successful for user '%s'", username)
	return true, nil
}
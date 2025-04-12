// internal/auth/credentials.go
package auth

import (
	"fmt"
	"os/user"

	"github.com/charmbracelet/log"
	"github.com/msteinert/pam"
)

// ValidateCredentials checks if the Linux user exists and validates the password using PAM.
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

	// 2. Attempt password validation using PAM
	log.Debugf("Attempting password validation for user '%s' via PAM", username)

	t, err := pam.StartFunc("login", username, func(s pam.Style, text string) (string, error) {
		switch s {
		case pam.PromptEchoOff: // Prompt for password
			return password, nil
		case pam.ErrorMsg, pam.TextInfo: // Handle messages from PAM modules
			log.Debugf("PAM message for user '%s': %s", username, text)
			return "", nil // No response needed for info/error messages
		}
		// Should not happen with standard password auth
		log.Warnf("Unhandled PAM style: %v, text: %s", s, text)
		return "", fmt.Errorf("unhandled PAM style: %v", s)
	})

	if err != nil {
		log.Errorf("PAM transaction start failed for user '%s': %v", username, err)
		// This could be a config error (e.g., pam.d service not found) or other issue.
		return false, fmt.Errorf("failed to start PAM transaction: %w", err)
	}

	// Authenticate the user
	err = t.Authenticate(0) // 0 is a flag, typically unused for standard auth
	if err != nil {
		log.Infof("Login attempt failed for user '%s': PAM authentication failed: %v", username, err)
		// This usually means incorrect password or account restrictions (locked, expired, etc.)
		return false, nil // Treat PAM auth failure as invalid credentials
	}

	// Optional: Check account validity (e.g., is the account locked or expired?)
	err = t.AcctMgmt(0)
	if err != nil {
		log.Warnf("PAM account management check failed for user '%s': %v", username, err)
		// Decide if this should prevent login. For now, let's treat it as a warning
		// and allow login if Authenticate succeeded. You might return false here for stricter checks.
		// return false, fmt.Errorf("PAM account validation failed: %w", err)
	}

	// If Authenticate succeeded (and optionally AcctMgmt)
	log.Infof("Password validation successful for user '%s' via PAM", username)
	return true, nil
}

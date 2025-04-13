// internal/auth/credentials.go
package auth

import (
	"fmt"
	"os/user"

	"github.com/charmbracelet/log"
	"github.com/msteinert/pam"
)

// Define the required group name as a constant
const requiredAdminGroup = "clab_admins"

// ValidateCredentials checks if the Linux user exists, validates the password using PAM,
// and verifies membership in the requiredAdminGroup.
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

	// 3. Authenticate the user via PAM (check password)
	err = t.Authenticate(0) // 0 is a flag, typically unused for standard auth
	if err != nil {
		log.Infof("Login attempt failed for user '%s': PAM authentication failed: %v", username, err)
		// This usually means incorrect password or account restrictions (locked, expired, etc.)
		return false, nil // Treat PAM auth failure as invalid credentials
	}

	// --- Group Membership Check (Added) ---
	// This check runs ONLY if PAM authentication (password check) was successful.
	log.Debugf("PAM authentication successful for '%s'. Checking membership in required group '%s'.", username, requiredAdminGroup)
	isInGroup, groupErr := IsUserInGroup(username, requiredAdminGroup) // Use the existing function from group.go

	if groupErr != nil {
		log.Errorf("Error checking group membership for user '%s' in group '%s': %v", username, requiredAdminGroup, groupErr)
		// Treat group check error as an internal server error, preventing login even if password was right
		return false, fmt.Errorf("error checking group membership: %w", groupErr)
	}

	if !isInGroup {
		// Password was correct, but user is not in the required group. Deny login.
		log.Infof("Login attempt denied for user '%s': Authenticated successfully via PAM, but is NOT a member of the required group '%s'.", username, requiredAdminGroup)
		return false, nil // Return false (not authorized) but no error (credentials technically valid, just not permitted)
	}
	// --- End Group Membership Check ---

	// 4. Optional: Check account validity (e.g., is the account locked or expired?)
	// This remains optional as before.
	err = t.AcctMgmt(0)
	if err != nil {
		log.Warnf("PAM account management check failed for user '%s' (but login allowed as Authenticate and Group Check passed): %v", username, err)
		// Decide if this should prevent login. For now, let's treat it as a warning
		// and allow login if Authenticate and Group Check succeeded. You might return false here for stricter checks.
		// return false, fmt.Errorf("PAM account validation failed: %w", err)
	}

	// 5. Success: Authenticated AND in the required group
	log.Infof("Authentication successful for user '%s': Valid password via PAM and member of group '%s'.", username, requiredAdminGroup)
	return true, nil
}

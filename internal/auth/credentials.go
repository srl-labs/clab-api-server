// internal/auth/credentials.go
package auth

import (
	"fmt"
	"os/user"

	"github.com/charmbracelet/log"
	"github.com/msteinert/pam"

	"github.com/srl-labs/clab-api-server/internal/config" // Ensure config is imported
)

// Define the primary required group name as a constant
const requiredAdminGroup = "clab_admins"

// ValidateCredentials checks if the Linux user exists, validates the password using PAM,
// and verifies membership in EITHER the requiredAdminGroup OR the configured APIUserGroup.
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

	// --- Login Group Membership Check ---
	// User MUST be in EITHER clab_admins OR the configured API_USER_GROUP to log in.
	log.Debugf("PAM authentication successful for '%s'. Checking login group memberships.", username)

	// 1. Check primary group (clab_admins)
	isInAdminGroup, adminGroupErr := IsUserInGroup(username, requiredAdminGroup)
	if adminGroupErr != nil {
		log.Errorf("Error checking group membership for user '%s' in group '%s': %v", username, requiredAdminGroup, adminGroupErr)
		// Treat group check error as an internal server error, preventing login
		return false, fmt.Errorf("error checking group membership for %s: %w", requiredAdminGroup, adminGroupErr)
	}

	if isInAdminGroup {
		// User is in the primary group, login authorization check passed.
		log.Debugf("User '%s' is a member of the primary login group '%s'. Login authorized.", username, requiredAdminGroup)
		// Proceed to optional AcctMgmt check below
	} else {
		// User is NOT in the primary group. Check the configured API_USER_GROUP.
		configuredApiUserGroup := config.AppConfig.APIUserGroup
		log.Debugf("User '%s' is NOT a member of '%s'. Checking configured API_USER_GROUP ('%s').", username, requiredAdminGroup, configuredApiUserGroup)

		if configuredApiUserGroup == "" {
			// No API_USER_GROUP configured, and user wasn't in the primary group. Deny login.
			log.Infof("Login attempt denied for user '%s': Authenticated successfully via PAM, but is NOT a member of the required group '%s' and no API_USER_GROUP is configured.", username, requiredAdminGroup)
			return false, nil // Not authorized for login
		}

		// 2. Check configured API_USER_GROUP
		isInApiUserGroup, apiUserGroupErr := IsUserInGroup(username, configuredApiUserGroup)
		if apiUserGroupErr != nil {
			log.Errorf("Error checking group membership for user '%s' in configured API_USER_GROUP '%s': %v", username, configuredApiUserGroup, apiUserGroupErr)
			// Treat group check error as an internal server error, preventing login
			return false, fmt.Errorf("error checking group membership for %s: %w", configuredApiUserGroup, apiUserGroupErr)
		}

		if !isInApiUserGroup {
			// User is in neither group. Deny login.
			log.Infof("Login attempt denied for user '%s': Authenticated successfully via PAM, but is NOT a member of required group '%s' OR configured API_USER_GROUP '%s'.", username, requiredAdminGroup, configuredApiUserGroup)
			return false, nil // Not authorized for login
		}

		// User is in the configured API_USER_GROUP. Login authorization check passed.
		log.Debugf("User '%s' is a member of the configured API_USER_GROUP '%s'. Login authorized.", username, configuredApiUserGroup)
		// Proceed to optional AcctMgmt check below
	}
	// --- End Login Group Membership Check ---

	// 4. Optional: Check account validity (e.g., is the account locked or expired?)
	// This check runs only if PAM authentication and the login group membership check succeeded.
	err = t.AcctMgmt(0)
	if err != nil {
		log.Warnf("PAM account management check failed for user '%s' (but login allowed as Authenticate and Group Check passed): %v", username, err)
		// Decide if this should prevent login. For now, treat it as a warning
		// and allow login if Authenticate and Group Check succeeded.
		// You might return false here for stricter checks:
		// return false, fmt.Errorf("PAM account validation failed: %w", err)
	}

	// 5. Success: Authenticated AND in one of the required login groups
	log.Infof("Authentication successful for user '%s': Valid password via PAM and member of an authorized login group.", username)
	return true, nil
}

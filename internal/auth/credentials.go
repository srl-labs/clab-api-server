// internal/auth/credentials.go
package auth

import (
	"fmt"
	"os/user"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/msteinert/pam"

	"github.com/srl-labs/clab-api-server/internal/config"
)

type groupMembershipChecker func(username, group string) (bool, error)

func configuredLoginGroups() []string {
	groups := make([]string, 0, 2)
	seen := make(map[string]struct{}, 2)
	for _, group := range []string{config.AppConfig.APIUserGroup, config.AppConfig.SuperuserGroup} {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		groups = append(groups, group)
	}
	return groups
}

func userHasConfiguredLoginAccess(username string, checker groupMembershipChecker) (bool, error) {
	groups := configuredLoginGroups()
	if len(groups) == 0 {
		return false, nil
	}

	for _, group := range groups {
		inGroup, err := checker(username, group)
		if err != nil {
			return false, fmt.Errorf("error checking group membership for %s: %w", group, err)
		}
		if inGroup {
			return true, nil
		}
	}

	return false, nil
}

// IsUserAuthorizedForAPI reports whether a Linux user belongs to either of the
// configured API access groups. Authentication and authorization deliberately
// share this policy so changing group names cannot create contradictory roles.
func IsUserAuthorizedForAPI(username string) (bool, error) {
	return userHasConfiguredLoginAccess(username, IsUserInGroup)
}

// ValidateCredentials checks if the Linux user exists, validates the password using PAM,
// and verifies membership in either configured API access group.
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
	// User MUST be in either API_USER_GROUP or SUPERUSER_GROUP to log in.
	log.Debugf("PAM authentication successful for '%s'. Checking login group memberships.", username)
	authorized, authorizationErr := IsUserAuthorizedForAPI(username)
	if authorizationErr != nil {
		log.Errorf("Error checking configured API group membership for user '%s': %v", username, authorizationErr)
		return false, authorizationErr
	}
	if !authorized {
		log.Infof("Login attempt denied for user '%s': authenticated via PAM but not a member of API_USER_GROUP or SUPERUSER_GROUP.", username)
		return false, nil
	}
	// --- End Login Group Membership Check ---

	// 4. Optional: Check account validity (e.g., is the account locked or expired?)
	// This check runs only if PAM authentication and the login group membership check succeeded.
	err = t.AcctMgmt(0)
	if err != nil {
		log.Warnf("PAM account management check failed for user '%s' (but login allowed as Authenticate and Group Check passed): %v", username, err)
	}

	// 5. Success: Authenticated AND in one of the required login groups
	log.Infof("Authentication successful for user '%s': Valid password via PAM and member of an authorized login group.", username)
	return true, nil
}

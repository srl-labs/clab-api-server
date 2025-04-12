package auth

import (
	"fmt"
	"os/user"

	"github.com/charmbracelet/log"
)

// IsUserInGroup checks if a Linux user is a member of a specific group.
// Returns false, nil if the group doesn't exist or the user isn't in it.
// Returns false, error for actual system errors during lookup.
func IsUserInGroup(username string, targetGroupName string) (bool, error) {
	if targetGroupName == "" {
		return false, nil // No superuser group configured
	}

	// 1. Look up the user
	usr, err := user.Lookup(username)
	if err != nil {
		if _, ok := err.(user.UnknownUserError); ok {
			log.Warnf("Group check: User '%s' not found.", username)
			return false, nil // User doesn't exist, so can't be in the group
		}
		log.Errorf("Group check: Error looking up user '%s': %v", username, err)
		return false, fmt.Errorf("error looking up user: %w", err)
	}

	// 2. Look up the target group by name to get its GID
	targetGroup, err := user.LookupGroup(targetGroupName)
	if err != nil {
		if _, ok := err.(user.UnknownGroupError); ok {
			log.Warnf("Group check: Configured superuser group '%s' does not exist on the system.", targetGroupName)
			return false, nil // Group doesn't exist, so user can't be in it
		}
		log.Errorf("Group check: Error looking up group '%s': %v", targetGroupName, err)
		return false, fmt.Errorf("error looking up group: %w", err)
	}
	targetGid := targetGroup.Gid

	// 3. Get the list of group IDs the user belongs to
	groupIds, err := usr.GroupIds()
	if err != nil {
		log.Errorf("Group check: Error getting group IDs for user '%s': %v", username, err)
		return false, fmt.Errorf("error getting user group IDs: %w", err)
	}

	// 4. Check if the target group's GID is in the user's list
	for _, gid := range groupIds {
		if gid == targetGid {
			log.Debugf("Group check: User '%s' is a member of group '%s' (GID: %s).", username, targetGroupName, targetGid)
			return true, nil
		}
	}

	log.Debugf("Group check: User '%s' is NOT a member of group '%s' (GID: %s).", username, targetGroupName, targetGid)
	return false, nil
}

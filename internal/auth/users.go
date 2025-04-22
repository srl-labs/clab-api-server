// internal/auth/users.go
package auth

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

const (
	useraddBin  = "/usr/sbin/useradd"
	userdelBin  = "/usr/sbin/userdel"
	usermodBin  = "/usr/sbin/usermod"
	groupaddBin = "/usr/sbin/groupadd"
	chpasswdBin = "/usr/sbin/chpasswd"
	passwdBin   = "/usr/bin/passwd"
	groupsBin   = "/usr/bin/groups"
)

// GetAllUsers returns a list of all system users that are relevant to the API
// Filters out system accounts or other internal users by their UID ranges
func GetAllUsers() ([]models.UserDetails, error) {
	var result []models.UserDetails

	// Open /etc/passwd file
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("error opening /etc/passwd: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}

		username := parts[0]
		uid := parts[2]
		gid := parts[3]
		gecos := parts[4]
		homeDir := parts[5]
		shell := parts[6]

		// Skip system users - they typically have UIDs < 1000
		uidInt := 0
		fmt.Sscanf(uid, "%d", &uidInt)
		if uidInt < 1000 && username != "containerlab" {
			continue
		}

		// Get user details
		userDetails, err := GetUserDetails(username)
		if err != nil {
			log.Warnf("Error getting details for user '%s': %v", username, err)
			// Create a basic entry with the info we have
			userDetails = models.UserDetails{
				Username:    username,
				UID:         uid,
				GID:         gid,
				DisplayName: gecos,
				HomeDir:     homeDir,
				Shell:       shell,
			}
		}

		result = append(result, userDetails)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading /etc/passwd: %w", err)
	}

	return result, nil
}

// GetUserDetails retrieves detailed information about a specific user
func GetUserDetails(username string) (models.UserDetails, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return models.UserDetails{}, fmt.Errorf("error looking up user: %w", err)
	}

	// Get groups
	groups, err := getUserGroups(username)
	if err != nil {
		log.Warnf("Error getting groups for user '%s': %v", username, err)
	}

	// Check if user is in superuser or API user group
	isSuperuser, _ := IsUserInGroup(username, config.AppConfig.SuperuserGroup)
	isAPIUser, _ := IsUserInGroup(username, config.AppConfig.APIUserGroup)
	isClabAdmin, _ := IsUserInGroup(username, requiredAdminGroup)

	// If user is in clab_admins but not explicitly in the configured API group, they're still an API user
	if isClabAdmin {
		isAPIUser = true
	}

	return models.UserDetails{
		Username:    u.Username,
		UID:         u.Uid,
		GID:         u.Gid,
		DisplayName: extractDisplayName(u),
		HomeDir:     u.HomeDir,
		Shell:       getLoginShell(username),
		Groups:      groups,
		IsSuperuser: isSuperuser,
		IsAPIUser:   isAPIUser,
	}, nil
}

// CreateUser creates a new Linux user with the specified details
func CreateUser(req models.UserCreateRequest) error {
	// Validate username
	if !isValidUsername(req.Username) {
		return fmt.Errorf("invalid username format")
	}

	// Check if user already exists
	_, err := user.Lookup(req.Username)
	if err == nil {
		return fmt.Errorf("user '%s' already exists", req.Username)
	}

	// Prepare command args for useradd
	args := []string{
		"-m",                               // Create home directory
		"-s", getShellOrDefault(req.Shell), // Set shell
	}

	// Add comment (full name) if provided
	if req.DisplayName != "" {
		args = append(args, "-c", req.DisplayName)
	}

	// Add username as the final argument
	args = append(args, req.Username)

	// Execute the useradd command
	cmd := exec.Command(useraddBin, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error creating user '%s': %w - %s", req.Username, err, string(output))
	}

	// Set password
	if err := setUserPassword(req.Username, req.Password); err != nil {
		// Attempt to remove the user if setting the password fails
		_ = exec.Command(userdelBin, req.Username).Run()
		return fmt.Errorf("error setting password for user '%s': %w", req.Username, err)
	}

	// Set group memberships
	groupsList := req.Groups

	// Add the user to superuser group if requested
	if req.IsSuperuser && config.AppConfig.SuperuserGroup != "" {
		if !contains(groupsList, config.AppConfig.SuperuserGroup) {
			groupsList = append(groupsList, config.AppConfig.SuperuserGroup)
		}
	}

	// Add to API access group if it's not the same as the superuser group
	// and ensure at least one API access group is included
	apiAccessGranted := false

	// Check for required API access group (clab_admins)
	if contains(groupsList, requiredAdminGroup) {
		apiAccessGranted = true
	}

	// Check for configured API group if different from the required one
	if config.AppConfig.APIUserGroup != "" &&
		config.AppConfig.APIUserGroup != requiredAdminGroup &&
		contains(groupsList, config.AppConfig.APIUserGroup) {
		apiAccessGranted = true
	}

	// If no API access group was included, add the required one
	if !apiAccessGranted {
		groupsList = append(groupsList, requiredAdminGroup)
	}

	// Make sure the groups exist
	for _, group := range groupsList {
		ensureGroupExists(group)
	}

	// Set user's groups
	if len(groupsList) > 0 {
		if err := setUserGroups(req.Username, groupsList); err != nil {
			log.Warnf("Error adding user '%s' to groups: %v", req.Username, err)
		}
	}

	return nil
}

// UpdateUser updates the specified user's information
func UpdateUser(username string, req models.UserUpdateRequest) error {
	// Check if user exists
	_, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("user '%s' not found: %w", username, err)
	}

	// Prepare usermod command args
	args := []string{}

	// Update display name if provided
	if req.DisplayName != "" {
		args = append(args, "-c", req.DisplayName)
	}

	// Update shell if provided
	if req.Shell != "" {
		args = append(args, "-s", req.Shell)
	}

	// Execute usermod if we have any arguments to update
	if len(args) > 0 {
		// Add username as the final argument
		args = append(args, username)

		cmd := exec.Command(usermodBin, args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("error updating user '%s': %w - %s", username, err, string(output))
		}
	}

	// Handle groups update separately
	if len(req.Groups) > 0 || req.IsSuperuser {
		groupsList := req.Groups

		// Add the user to superuser group if requested
		if req.IsSuperuser && config.AppConfig.SuperuserGroup != "" {
			if !contains(groupsList, config.AppConfig.SuperuserGroup) {
				groupsList = append(groupsList, config.AppConfig.SuperuserGroup)
			}
		}

		// Ensure at least one API access group is included
		apiAccessGranted := false

		// Check for required API access group (clab_admins)
		if contains(groupsList, requiredAdminGroup) {
			apiAccessGranted = true
		}

		// Check for configured API group if different from the required one
		if config.AppConfig.APIUserGroup != "" &&
			config.AppConfig.APIUserGroup != requiredAdminGroup &&
			contains(groupsList, config.AppConfig.APIUserGroup) {
			apiAccessGranted = true
		}

		// If no API access group was included, add the required one
		if !apiAccessGranted {
			groupsList = append(groupsList, requiredAdminGroup)
		}

		// Make sure the groups exist
		for _, group := range groupsList {
			ensureGroupExists(group)
		}

		// Set user's groups
		if err := setUserGroups(username, groupsList); err != nil {
			return fmt.Errorf("error updating groups for user '%s': %w", username, err)
		}
	}

	return nil
}

// DeleteUser deletes the specified user from the system
func DeleteUser(username string) error {
	// Check if user exists
	_, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("user '%s' not found: %w", username, err)
	}

	// Execute userdel command with -r to remove home directory
	cmd := exec.Command(userdelBin, "-r", username)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error deleting user '%s': %w - %s", username, err, string(output))
	}

	return nil
}

// ChangeUserPassword changes a user's password
func ChangeUserPassword(username, currentPassword, newPassword string, isSuperuser bool) error {
	// Check if user exists
	_, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("user '%s' not found: %w", username, err)
	}

	// If not superuser, verify current password
	if !isSuperuser && currentPassword != "" {
		valid, err := ValidateCredentials(username, currentPassword)
		if err != nil {
			return fmt.Errorf("error validating current password: %w", err)
		}
		if !valid {
			return fmt.Errorf("current password is incorrect")
		}
	}

	// Set new password
	return setUserPassword(username, newPassword)
}

// Helper function to set a user's password using chpasswd
func setUserPassword(username, password string) error {
	input := fmt.Sprintf("%s:%s", username, password)

	cmd := exec.Command(chpasswdBin)
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("chpasswd error: %w - %s", err, string(output))
	}

	return nil
}

// Helper function to get a user's login shell
func getLoginShell(username string) string {
	_, err := user.Lookup(username)
	if err != nil {
		return ""
	}

	// Read /etc/passwd to get shell
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) >= 7 && parts[0] == username {
			return parts[6]
		}
	}

	return "/bin/bash" // Default
}

// Helper function to get user's groups
func getUserGroups(username string) ([]string, error) {
	cmd := exec.Command(groupsBin, username)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error getting groups: %w - %s", err, string(output))
	}

	// Parse the output - typically in the format: "username : group1 group2 group3"
	outputStr := strings.TrimSpace(string(output))
	parts := strings.Split(outputStr, ":")
	if len(parts) < 2 {
		return []string{}, nil
	}

	groupsStr := strings.TrimSpace(parts[1])
	return strings.Fields(groupsStr), nil
}

// Helper function to set a user's groups
func setUserGroups(username string, groups []string) error {
	if len(groups) == 0 {
		return nil
	}

	args := []string{"-G", strings.Join(groups, ",")}

	// Add username as the final argument
	args = append(args, username)

	cmd := exec.Command(usermodBin, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error setting groups: %w - %s", err, string(output))
	}

	return nil
}

// Helper to ensure a group exists
func ensureGroupExists(groupName string) error {
	// Check if group already exists
	_, err := user.LookupGroup(groupName)
	if err == nil {
		return nil // Group exists
	}

	// Create the group
	cmd := exec.Command(groupaddBin, groupName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error creating group '%s': %w - %s", groupName, err, string(output))
	}

	return nil
}

// Helper to extract display name from user info
func extractDisplayName(u *user.User) string {
	// Try to extract from GECOS field (comment)
	// Format is typically: Full Name,Room,Work Phone,Home Phone,Other
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) >= 5 && parts[0] == u.Username {
			gecos := parts[4]
			// Extract just the full name from the GECOS field
			if gecosName := strings.Split(gecos, ","); len(gecosName) > 0 {
				return gecosName[0]
			}
			return gecos
		}
	}

	return ""
}

// Helper to get shell with default fallback
func getShellOrDefault(shell string) string {
	if shell == "" {
		return "/bin/bash"
	}
	return shell
}

// Helper to check if a string slice contains a value
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

// Helper to validate username format
func isValidUsername(username string) bool {
	// Basic validation - alphanumeric and some special chars
	// Usually Linux usernames can be 1-32 chars, starting with a letter or underscore
	if len(username) < 1 || len(username) > 32 {
		return false
	}

	// First character should be a letter or underscore
	if !((username[0] >= 'a' && username[0] <= 'z') ||
		(username[0] >= 'A' && username[0] <= 'Z') ||
		username[0] == '_') {
		return false
	}

	// Rest can include letters, numbers, underscore, hyphen, dot
	for _, c := range username {
		if !((c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '_' || c == '-' || c == '.') {
			return false
		}
	}

	return true
}

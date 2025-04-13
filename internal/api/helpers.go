// internal/api/helpers.go
package api

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/auth"
	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// isValidLabName checks for potentially harmful characters in lab names.
var labNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// isValidContainerName checks container names (often includes lab prefix)
var containerNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]+$`) // Docker's typical naming restrictions

// isValidInterfaceName checks interface names
var interfaceNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// isValidCertName checks certificate/key file base names
var certNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// isValidNodeFilter checks the node filter format (basic check)
func isValidNodeFilter(filter string) bool {
	if filter == "" {
		return true // Empty is valid (no filter)
	}
	// Check for potentially unsafe characters, allow comma, alphanumeric, hyphen, underscore
	return regexp.MustCompile(`^[a-zA-Z0-9_,-]+$`).MatchString(filter)
}

// isValidExportTemplate checks the export template format (basic check)
func isValidExportTemplate(template string) bool {
	if template == "" {
		return true // Empty is valid (use default)
	}
	if template == "__full" {
		return true // Special value
	}
	// Basic check: prevent path traversal, allow alphanumeric, underscore, hyphen, dot
	// This is NOT a foolproof validation for file paths, but a basic sanity check.
	// It assumes the template is relative or just a name.
	if strings.Contains(template, "..") || strings.HasPrefix(template, "/") {
		return false
	}
	return regexp.MustCompile(`^[a-zA-Z0-9_./-]+$`).MatchString(template)
}

func isValidLabName(name string) bool {
	// Allow slightly longer names for generated certs/files, but keep reasonable
	if name == "" || len(name) > 128 {
		return false
	}
	return labNameRegex.MatchString(name) // Re-use labNameRegex for consistency, adjust if needed
}

// isValidContainerName validation
func isValidContainerName(name string) bool {
	if name == "" || len(name) > 128 { // Keep length check reasonable
		return false
	}
	return containerNameRegex.MatchString(name)
}

// isValidInterfaceName validation
func isValidInterfaceName(name string) bool {
	if name == "" || len(name) > 15 { // Linux IFName max length
		return false
	}
	return interfaceNameRegex.MatchString(name)
}

// isValidCertName validation
func isValidCertName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	// Prevent path traversal in the name itself
	if strings.Contains(name, "/") || strings.Contains(name, "\\") || name == "." || name == ".." {
		return false
	}
	return certNameRegex.MatchString(name)
}

// isValidDurationString checks if a string can be parsed as a duration >= 0
func isValidDurationString(durationStr string) bool {
	if durationStr == "" {
		return true // Empty is valid (means 0 or default)
	}
	d, err := time.ParseDuration(durationStr)
	if err != nil {
		return false
	}
	return d >= 0 // Allow 0 duration
}

// isValidPercentage checks if a float is between 0.0 and 100.0
func isValidPercentage(p float64) bool {
	return p >= 0.0 && p <= 100.0
}

// Helper to get the conventional container name
func getNodeContainerName(labName, nodeName string) (string, error) {
	if !isValidLabName(labName) {
		return "", fmt.Errorf("invalid lab name format: %s", labName)
	}
	// Node names within topology can be simple, reuse labNameRegex for basic check
	if !isValidLabName(nodeName) {
		return "", fmt.Errorf("invalid node name format: %s", nodeName)
	}
	// Default containerlab naming convention
	containerName := fmt.Sprintf("clab-%s-%s", labName, nodeName)
	// Validate the generated name just in case
	if !isValidContainerName(containerName) {
		// This should ideally not happen if labName and nodeName are valid
		return "", fmt.Errorf("generated container name is invalid: %s", containerName)
	}
	return containerName, nil
}

// Helper to check if user is superuser
func isSuperuser(username string) bool {
	if config.AppConfig.SuperuserGroup == "" {
		return false // No superuser group configured
	}
	inGroup, err := auth.IsUserInGroup(username, config.AppConfig.SuperuserGroup)
	if err != nil {
		log.Warnf("Error checking superuser status for user '%s': %v", username, err)
		return false // Treat error as not superuser
	}
	return inGroup
}

// Helper to get and ensure the base directory for user certificates IN THE USER'S HOME.
// Attempts to set ownership of the base directory to the user.
func getUserCertBasePath(username string) (string, error) {
	usr, err := user.Lookup(username)
	if err != nil {
		log.Errorf("Cannot get user details for '%s': %v", username, err)
		return "", fmt.Errorf("could not retrieve user details for '%s'", username)
	}

	// --- NEW PATH: Use user's home directory ---
	// Store certs under ~/.clab/certs (consistent with potential user clab usage)
	basePath := filepath.Join(usr.HomeDir, ".clab", "certs")

	// Create directory if it doesn't exist
	// Use 0750: User rwx, Group rx, Other --- (adjust if stricter 0700 is needed)
	if err := os.MkdirAll(basePath, 0750); err != nil {
		log.Errorf("Failed to create cert base directory '%s': %v", basePath, err)
		return "", fmt.Errorf("failed to create certificate base directory")
	}

	// --- Attempt to set ownership to the user ---
	uid, uidErr := strconv.Atoi(usr.Uid)
	gid, gidErr := strconv.Atoi(usr.Gid)

	if uidErr != nil || gidErr != nil {
		log.Warnf("Could not parse UID/GID for user '%s' (%s/%s). Cannot set ownership for cert directory '%s'. Files might be owned by API server user.", username, usr.Uid, usr.Gid, basePath)
		// Continue, but ownership will be wrong if the API user isn't the target user
	} else {
		// Attempt to change ownership of the base directory
		if err := os.Chown(basePath, uid, gid); err != nil {
			// This might fail if the API server user (e.g., root) doesn't have permission
			// to chown files in the target user's home directory, or if filesystem restrictions apply.
			log.Warnf("Failed to set ownership of cert base directory '%s' to user '%s' (uid:%d, gid:%d): %v. Certificate operations might proceed but file ownership may be incorrect.", basePath, username, uid, gid, err)
			// Do not return an error here, allow the operation to proceed but log the warning.
		} else {
			log.Debugf("Successfully set ownership of cert base directory '%s' to user '%s'", basePath, username)
		}
	}

	return basePath, nil
}

// verifyLabOwnership checks if a lab exists and is owned by the user.
// Returns the original topology path (if found) and nil error on success.
// Sends appropriate HTTP error response and returns non-nil error on failure.
func verifyLabOwnership(c *gin.Context, username, labName string) (string, error) {
	log.Debugf("Verifying ownership for user '%s', lab '%s'", username, labName)

	// Check superuser status FIRST - if superuser, bypass inspect check for ownership
	if isSuperuser(username) {
		log.Infof("Ownership check bypass for user '%s' on lab '%s': User is superuser.", username, labName)
		// Still need the topo path for some operations, so run inspect anyway, but ignore owner field
		inspectArgs := []string{"inspect", "--name", labName, "--format", "json"}
		ctx := c.Request.Context()
		inspectStdout, inspectStderr, inspectErr := clab.RunClabCommand(ctx, username, inspectArgs...)

		if inspectErr != nil || strings.Contains(inspectStdout, "no containers found") || strings.Contains(inspectStderr, "Could not find containers for lab") {
			// Lab doesn't exist, even for superuser
			log.Infof("Ownership check (superuser): Lab '%s' not found.", labName)
			err := fmt.Errorf("lab '%s' not found", labName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
			return "", err
		}
		// Lab exists, try to parse to get path
		var inspectResult models.ClabInspectOutput
		if err := json.Unmarshal([]byte(inspectStdout), &inspectResult); err == nil && len(inspectResult.Containers) > 0 {
			originalTopoPath := inspectResult.Containers[0].LabPath
			log.Debugf("Superuser '%s' accessing lab '%s' (Original Path: '%s')", username, labName, originalTopoPath)
			return originalTopoPath, nil // Superuser confirmed, path retrieved
		}
		// Inspect failed to parse or no containers, but didn't error before? Unlikely but handle.
		log.Warnf("Superuser '%s' accessing lab '%s': Lab found but failed to parse inspect output for path.", username, labName)
		return "", nil // Superuser confirmed, but path unknown
	}

	// --- Non-Superuser Path ---
	inspectArgs := []string{"inspect", "--name", labName, "--format", "json"}
	ctx := c.Request.Context()
	inspectStdout, inspectStderr, inspectErr := clab.RunClabCommand(ctx, username, inspectArgs...)

	if inspectStderr != "" {
		log.Warnf("Ownership check (via inspect) stderr for user '%s', lab '%s': %s", username, labName, inspectStderr)
	}
	if inspectErr != nil {
		errMsg := inspectErr.Error()
		// Check various "not found" messages from clab output/error
		if strings.Contains(inspectStdout, "no containers found") ||
			strings.Contains(errMsg, "no containers found") ||
			strings.Contains(errMsg, "no containerlab labs found") ||
			strings.Contains(inspectStderr, "no containers found") ||
			strings.Contains(inspectStderr, "Could not find containers for lab") {
			log.Infof("Ownership check failed for user '%s': Lab '%s' not found.", username, labName)
			err := fmt.Errorf("lab '%s' not found", labName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
			return "", err
		}
		log.Errorf("Ownership check failed for user '%s': Failed to inspect lab '%s': %v", username, labName, inspectErr)
		err := fmt.Errorf("failed to inspect lab '%s' for ownership check: %w", labName, inspectErr)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return "", err
	}

	var inspectResult models.ClabInspectOutput
	if err := json.Unmarshal([]byte(inspectStdout), &inspectResult); err != nil {
		log.Errorf("Ownership check failed for user '%s': Could not parse inspect output for lab '%s'. Output: %s, Error: %v", username, labName, inspectStdout, err)
		err := fmt.Errorf("could not parse inspect output for lab '%s'", labName)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return "", err
	}

	if len(inspectResult.Containers) == 0 {
		log.Warnf("Ownership check failed for user '%s': Inspect for lab '%s' succeeded but returned no containers.", username, labName)
		err := fmt.Errorf("lab '%s' not found (no containers returned)", labName)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
		return "", err
	}

	// Use the owner and path from the *first* container found for the lab
	actualOwner := inspectResult.Containers[0].Owner
	originalTopoPath := inspectResult.Containers[0].LabPath

	if actualOwner != username {
		log.Warnf("Ownership check failed for user '%s': Attempted to access lab '%s' but it is owned by '%s'. Access denied.", username, labName, actualOwner)
		// Use 404 for security (don't reveal existence if not owned)
		err := fmt.Errorf("lab '%s' not found or not owned by user", labName)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()}) // Changed to 404
		return "", err
	}

	log.Debugf("Ownership confirmed for user '%s' on lab '%s' (Owner: '%s', Original Path: '%s').", username, labName, actualOwner, originalTopoPath)
	return originalTopoPath, nil // Success
}

// Helper function to count unique lab names in a list of containers
func countUniqueLabs(containers []models.ClabContainerInfo) int {
	uniqueLabs := make(map[string]struct{})
	for _, c := range containers {
		if c.LabName != "" {
			uniqueLabs[c.LabName] = struct{}{}
		}
	}
	return len(uniqueLabs)
}

// verifyContainerOwnership checks if a specific container exists and is owned by the user.
// Sends appropriate HTTP error response and returns non-nil error on failure.
// Returns the container info on success.
func verifyContainerOwnership(c *gin.Context, username, containerName string) (*models.ClabContainerInfo, error) {
	log.Debugf("Verifying ownership for user '%s', container '%s'", username, containerName)

	// Check superuser status FIRST
	if isSuperuser(username) {
		log.Infof("Ownership check bypass for user '%s' on container '%s': User is superuser.", username, containerName)
	}

	// Use inspect --all and filter client-side
	inspectArgs := []string{"inspect", "--all", "--format", "json"}
	ctx := c.Request.Context()
	inspectStdout, inspectStderr, inspectErr := clab.RunClabCommand(ctx, username, inspectArgs...) // username for logging

	if inspectErr != nil {
		// Don't treat "no labs found" as an error here, just means the container wasn't found either
		if !strings.Contains(inspectErr.Error(), "no containerlab labs found") && !strings.Contains(inspectStdout, "no containers found") {
			log.Errorf("Container ownership check failed for user '%s': Failed to inspect all labs: %v", username, inspectErr)
			err := fmt.Errorf("failed to inspect labs for container ownership check: %w", inspectErr)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
			return nil, err
		}
		// If the error was "no labs found", stdout will be empty or "[]", proceed to parsing
	}
	if inspectStderr != "" {
		log.Warnf("Container ownership check (via inspect --all) stderr for user '%s', container '%s': %s", username, containerName, inspectStderr)
	}

	var inspectResult models.ClabInspectOutput
	if err := json.Unmarshal([]byte(inspectStdout), &inspectResult); err != nil {
		// Handle case where stdout might be empty "[]" which is valid JSON but yields no containers
		if strings.TrimSpace(inspectStdout) == "[]" || strings.TrimSpace(inspectStdout) == "{}" {
			log.Infof("Container ownership check failed for user '%s': Container '%s' not found (no labs running).", username, containerName)
			err := fmt.Errorf("container '%s' not found", containerName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
			return nil, err
		}
		log.Errorf("Container ownership check failed for user '%s': Could not parse inspect output. Output: %s, Error: %v", username, inspectStdout, err)
		err := fmt.Errorf("could not parse inspect output for container check")
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return nil, err
	}

	// Find the specific container
	var foundContainer *models.ClabContainerInfo
	for i := range inspectResult.Containers {
		if inspectResult.Containers[i].Name == containerName || inspectResult.Containers[i].ContainerID == containerName { // Check name or ID
			foundContainer = &inspectResult.Containers[i]
			break
		}
	}

	if foundContainer == nil {
		log.Infof("Container ownership check failed for user '%s': Container '%s' not found.", username, containerName)
		err := fmt.Errorf("container '%s' not found", containerName)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
		return nil, err
	}

	// check ownership if not superuser
	if !isSuperuser(username) && foundContainer.Owner != username {
		log.Warnf("Container ownership check failed for user '%s': Attempted to access container '%s' but it is owned by '%s'. Access denied.", username, containerName, foundContainer.Owner)
		err := fmt.Errorf("container '%s' not found or not owned by user", containerName)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()}) // 404 for security
		return nil, err
	}

	log.Debugf("Ownership confirmed for user '%s' on container '%s' (Owner: '%s').", username, containerName, foundContainer.Owner)
	return foundContainer, nil // Success
}

// isValidVethEndpoint checks the basic format of a veth endpoint string.
// It expects either "name:iface" or "kind:name:iface".
func isValidVethEndpoint(endpoint string) bool {
	if endpoint == "" {
		return false
	}
	parts := strings.Split(endpoint, ":")
	numParts := len(parts)

	if numParts < 2 || numParts > 3 {
		return false // Must have 2 or 3 parts
	}

	// Basic validation on parts (allow alphanumeric, hyphen, underscore)
	// This is not exhaustive but prevents obvious injection issues.
	nameRegex := regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`) // Allow dots for bridge/host names

	for _, part := range parts {
		if part == "" || !nameRegex.MatchString(part) {
			return false
		}
	}

	// Check interface name part specifically (last part)
	if !isValidInterfaceName(parts[numParts-1]) {
		return false
	}

	return true
}

// isValidIPAddress checks if a string is a valid IP address (v4 or v6).
func isValidIPAddress(ipStr string) bool {
	return net.ParseIP(ipStr) != nil
}

// isValidPrefix checks if a string is a plausible interface prefix.
func isValidPrefix(prefix string) bool {
	if prefix == "" {
		return false // Prefix cannot be empty
	}
	// Allow alphanumeric, hyphen, underscore. Should not contain path separators.
	if strings.ContainsAny(prefix, "/\\:") {
		return false
	}
	return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(prefix)
}

// extractZip securely extracts a zip archive to the target directory.
// It protects against Zip Slip and sets ownership of extracted files/dirs.
func extractZip(archiveReader io.ReaderAt, archiveSize int64, targetDir string, uid, gid int) error {
	zipReader, err := zip.NewReader(archiveReader, archiveSize)
	if err != nil {
		return fmt.Errorf("failed to create zip reader: %w", err)
	}

	// Clean the target directory path for reliable prefix checking
	cleanTargetDir := filepath.Clean(targetDir)

	for _, f := range zipReader.File {
		// **Zip Slip Protection**
		// filepath.Join cleans the path, removing potential "../" etc.
		filePath := filepath.Join(cleanTargetDir, f.Name)
		// Double check it's still within the target directory
		if !strings.HasPrefix(filePath, cleanTargetDir+string(os.PathSeparator)) && filePath != cleanTargetDir {
			return fmt.Errorf("illegal path in zip archive: '%s' attempts to escape target directory", f.Name)
		}

		// Create directories or files
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(filePath, 0750); err != nil { // Use 0750 for directories
				return fmt.Errorf("failed to create directory '%s': %w", filePath, err)
			}
			// Attempt to set ownership on the directory
			if err := os.Chown(filePath, uid, gid); err != nil {
				log.Warnf("extractZip: Failed to set ownership on directory '%s': %v", filePath, err)
				// Continue even if chown fails
			}
			continue
		}

		// Create parent directory if it doesn't exist
		parentDir := filepath.Dir(filePath)
		if err := os.MkdirAll(parentDir, 0750); err != nil {
			return fmt.Errorf("failed to create parent directory '%s': %w", parentDir, err)
		}
		// Attempt ownership on parent dir (might be redundant but safe)
		if err := os.Chown(parentDir, uid, gid); err != nil {
			log.Warnf("extractZip: Failed to set ownership on parent directory '%s': %v", parentDir, err)
		}

		// Create and write the file
		// Use file mode from archive, but ensure it's reasonable (e.g., mask out world write)
		// 0640 is a reasonable default if archive mode is weird.
		fileMode := f.Mode() & 0777 // Mask to standard permission bits
		if fileMode == 0 {
			fileMode = 0640
		} // Fallback if mode is zero

		dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
		if err != nil {
			return fmt.Errorf("failed to open destination file '%s': %w", filePath, err)
		}

		srcFile, err := f.Open()
		if err != nil {
			dstFile.Close() // Close dstFile before returning error
			return fmt.Errorf("failed to open source file '%s' in archive: %w", f.Name, err)
		}

		_, copyErr := io.Copy(dstFile, srcFile)

		// Close files regardless of copy error
		closeSrcErr := srcFile.Close()
		closeDstErr := dstFile.Close()

		if copyErr != nil {
			return fmt.Errorf("failed to copy file '%s': %w", f.Name, copyErr)
		}
		if closeSrcErr != nil {
			log.Warnf("extractZip: Error closing source file '%s': %v", f.Name, closeSrcErr)
		}
		if closeDstErr != nil {
			log.Warnf("extractZip: Error closing destination file '%s': %v", filePath, closeDstErr)
		}

		// Attempt to set ownership on the created file
		if err := os.Chown(filePath, uid, gid); err != nil {
			log.Warnf("extractZip: Failed to set ownership on file '%s': %v", filePath, err)
			// Continue even if chown fails
		}
	}
	return nil
}

// extractTarGz securely extracts a .tar.gz archive to the target directory.
// It protects against Tar Slip and sets ownership of extracted files/dirs.
func extractTarGz(archiveReader io.Reader, targetDir string, uid, gid int) error {
	gzReader, err := gzip.NewReader(archiveReader)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	cleanTargetDir := filepath.Clean(targetDir)

	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// **Tar Slip Protection**
		filePath := filepath.Join(cleanTargetDir, header.Name)
		if !strings.HasPrefix(filePath, cleanTargetDir+string(os.PathSeparator)) && filePath != cleanTargetDir {
			return fmt.Errorf("illegal path in tar archive: '%s' attempts to escape target directory", header.Name)
		}

		// Get FileInfo from header for mode/type
		fileInfo := header.FileInfo()

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(filePath, 0750); err != nil { // Use 0750 for directories
				return fmt.Errorf("failed to create directory '%s': %w", filePath, err)
			}
			// Attempt ownership
			if err := os.Chown(filePath, uid, gid); err != nil {
				log.Warnf("extractTarGz: Failed to set ownership on directory '%s': %v", filePath, err)
			}

		case tar.TypeReg:
			// Create parent directory if it doesn't exist
			parentDir := filepath.Dir(filePath)
			if err := os.MkdirAll(parentDir, 0750); err != nil {
				return fmt.Errorf("failed to create parent directory '%s': %w", parentDir, err)
			}
			// Attempt ownership on parent dir
			if err := os.Chown(parentDir, uid, gid); err != nil {
				log.Warnf("extractTarGz: Failed to set ownership on parent directory '%s': %v", parentDir, err)
			}

			// Create and write the file
			// Use file mode from archive, masked
			fileMode := fileInfo.Mode() & 0777
			if fileMode == 0 {
				fileMode = 0640
			} // Fallback

			dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
			if err != nil {
				return fmt.Errorf("failed to open destination file '%s': %w", filePath, err)
			}

			_, copyErr := io.Copy(dstFile, tarReader)
			closeErr := dstFile.Close() // Close file regardless of copy error

			if copyErr != nil {
				return fmt.Errorf("failed to copy file '%s': %w", header.Name, copyErr)
			}
			if closeErr != nil {
				log.Warnf("extractTarGz: Error closing destination file '%s': %v", filePath, closeErr)
			}

			// Attempt ownership
			if err := os.Chown(filePath, uid, gid); err != nil {
				log.Warnf("extractTarGz: Failed to set ownership on file '%s': %v", filePath, err)
			}

		case tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			// Security: Explicitly ignore symlinks and other potentially problematic types for now.
			log.Warnf("extractTarGz: Ignoring unsupported file type '%c' for entry '%s' in archive.", header.Typeflag, header.Name)
			continue // Skip to the next entry

		default:
			log.Warnf("extractTarGz: Ignoring unknown file type '%c' for entry '%s' in archive.", header.Typeflag, header.Name)
		}
	}
	return nil
}

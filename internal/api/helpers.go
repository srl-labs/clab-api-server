// internal/api/helpers.go
package api

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
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
	"unicode"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/auth"
	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
	workspacestore "github.com/srl-labs/clab-api-server/internal/workspace"
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

func isValidRuntimeImageReference(reference string) bool {
	if reference == "" || strings.TrimSpace(reference) != reference || len(reference) > 512 {
		return false
	}
	for _, r := range reference {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
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

// parseExpiryDuration parses an expiry duration string into a time.Duration.
// If the string is empty, a default of 87600h (10 years) is returned.
func parseExpiryDuration(durationStr string) (time.Duration, error) {
	if durationStr == "" {
		return 87600 * time.Hour, nil // Default: 10 years
	}
	d, err := time.ParseDuration(durationStr)
	if err != nil {
		return 0, fmt.Errorf("invalid duration format: %w", err)
	}
	if d < 0 {
		return 0, fmt.Errorf("duration must be non-negative")
	}
	return d, nil
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

// requireSuperuser verifies the user is in the configured superuser group.
// It logs a warning and sends a 403 response if the user lacks privileges.
// The action string is used for contextual logging; it can be empty.
// Returns true if the user is a superuser and the caller may proceed.
func requireSuperuser(c *gin.Context, username, action string) bool {
	if isSuperuser(username) {
		return true
	}
	if action != "" {
		log.Warnf("User '%s' attempted to %s without superuser privileges.", username, action)
	} else {
		log.Warnf("User '%s' attempted a superuser-only action without privileges.", username)
	}
	c.JSON(http.StatusForbidden, models.ErrorResponse{Error: "Superuser privileges required for this operation"})
	return false
}

// Helper to get and ensure the base directory for user certificates IN THE USER'S HOME.
// Attempts to set ownership of the base directory to the user.
func getUserCertBasePath(username string) (string, error) {
	usr, err := user.Lookup(username)
	if err != nil {
		log.Errorf("Cannot get user details for '%s': %v", username, err)
		return "", fmt.Errorf("could not retrieve user details for '%s'", username)
	}

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

func getLabInfo(ctx context.Context, username string, labName string) (info *models.ClabContainerInfo, exists bool, err error) {
	log.Debugf("getLabInfo: Checking existence and owner for lab '%s' as user '%s'", labName, username)

	svc := GetClabService()
	if svc == nil {
		return nil, false, fmt.Errorf("containerlab service not initialized")
	}

	// List containers for the specific lab
	containers, listErr := svc.ListContainers(ctx, clab.ListOptions{
		LabName: labName,
	})

	if listErr != nil {
		// Check for common "not found" scenarios
		errMsg := strings.ToLower(listErr.Error())
		if strings.Contains(errMsg, "no containers found") ||
			strings.Contains(errMsg, "no containerlab labs found") ||
			strings.Contains(errMsg, "not found") {
			log.Debugf("getLabInfo: Lab '%s' not found.", labName)
			return nil, false, nil // Lab does not exist, no error
		}
		log.Errorf("getLabInfo: Failed to list containers for lab '%s': %v", labName, listErr)
		return nil, false, fmt.Errorf("failed to inspect lab '%s': %w", labName, listErr)
	}

	// Filter containers to only those belonging to the specified lab
	var labContainers []models.ClabContainerInfo
	for _, c := range containers {
		containerInfo := clab.ContainerToClabContainerInfo(c)
		if containerInfo.LabName == labName {
			labContainers = append(labContainers, containerInfo)
		}
	}

	if len(labContainers) == 0 {
		log.Debugf("getLabInfo: Lab '%s' not found (no containers).", labName)
		return nil, false, nil // Lab does not exist, no error
	}

	// Lab exists, return info from the first container
	log.Debugf("getLabInfo: Lab '%s' found. Owner: '%s'.", labName, labContainers[0].Owner)
	return &labContainers[0], true, nil // Lab exists
}

// ensureLabOwnerLabels re-applies the desired owner label to all containers in a lab.
// verifyLabOwnership checks if a lab exists and is owned by the user.
// Returns the original topology path (if found) and nil error on success.
// Sends appropriate HTTP error response and returns non-nil error on failure.
func verifyLabOwnership(c *gin.Context, username, labName string) (string, error) {
	log.Debugf("Verifying ownership for user '%s', lab '%s'", username, labName)

	// Use a fresh context with timeout for containerlab operations
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Use getLabInfo to check existence and get owner in one step
	labInfo, exists, err := getLabInfo(ctx, username, labName)

	if err != nil {
		// getLabInfo already logged the error
		errResp := fmt.Errorf("failed to check lab '%s' status: %w", labName, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errResp.Error()})
		return "", errResp
	}

	if !exists {
		log.Infof("Ownership check failed for user '%s': Lab '%s' not found.", username, labName)
		errResp := fmt.Errorf("lab '%s' not found", labName)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: errResp.Error()})
		return "", errResp
	}

	// Lab exists, now check ownership
	actualOwner := labInfo.Owner
	originalTopoPath := labInfo.AbsLabPath // Using AbsLabPath as LabPath (relative) does not delete lab dir on cleanup
	c.Set(verifiedLabOwnerContextKey, actualOwner)

	// Check superuser status or direct ownership
	if isSuperuser(username) {
		log.Infof("Ownership check bypass for user '%s' on lab '%s': User is superuser.", username, labName)
		log.Debugf("Superuser '%s' accessing lab '%s' (Owner: '%s', Original Path: '%s').", username, labName, actualOwner, originalTopoPath)
		return originalTopoPath, nil // Superuser confirmed
	}

	if actualOwner != username {
		log.Warnf("Ownership check failed for user '%s': Attempted to access lab '%s' but it is owned by '%s'. Access denied.", username, labName, actualOwner)
		// Use 404 for security (don't reveal existence if not owned)
		errResp := fmt.Errorf("lab '%s' not found or not owned by user", labName)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: errResp.Error()}) // Changed to 404
		return "", errResp
	}

	log.Debugf("Ownership confirmed for user '%s' on lab '%s' (Owner: '%s', Original Path: '%s').", username, labName, actualOwner, originalTopoPath)
	return originalTopoPath, nil // Success
}

// verifyContainerOwnership checks if a specific container exists and is owned by the user using the library.
// Sends appropriate HTTP error response and returns non-nil error on failure.
// Returns the container info on success.
func verifyContainerOwnership(c *gin.Context, username, containerName string) (*models.ClabContainerInfo, error) {
	log.Debugf("Verifying ownership for user '%s', container '%s'", username, containerName)

	svc := GetClabService()
	if svc == nil {
		err := fmt.Errorf("containerlab service not initialized")
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return nil, err
	}

	// Use a fresh context with timeout for containerlab operations
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// List all containers
	containers, listErr := svc.ListContainers(ctx, clab.ListOptions{})

	if listErr != nil {
		// Don't treat "no labs found" as an error here
		errMsg := strings.ToLower(listErr.Error())
		if strings.Contains(errMsg, "no containerlab labs found") || strings.Contains(errMsg, "no containers found") {
			log.Infof("Container ownership check failed for user '%s': Container '%s' not found (no labs running).", username, containerName)
			err := fmt.Errorf("container '%s' not found", containerName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
			return nil, err
		}
		log.Errorf("Container ownership check failed for user '%s': Failed to list containers: %v", username, listErr)
		err := fmt.Errorf("failed to inspect labs for container ownership check: %w", listErr)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return nil, err
	}

	// Find the specific container by name or ID
	var foundContainer *models.ClabContainerInfo
	for _, c := range containers {
		containerInfo := clab.ContainerToClabContainerInfo(c)
		if containerInfo.Name == containerName || containerInfo.ContainerID == containerName {
			foundContainer = &containerInfo
			break
		}
	}

	if foundContainer == nil {
		log.Infof("Container ownership check failed for user '%s': Container '%s' not found.", username, containerName)
		err := fmt.Errorf("container '%s' not found", containerName)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
		return nil, err
	}

	// Check ownership if not superuser
	if !isSuperuser(username) && foundContainer.Owner != username {
		log.Warnf("Container ownership check failed for user '%s': Attempted to access container '%s' but it is owned by '%s'. Access denied.", username, containerName, foundContainer.Owner)
		err := fmt.Errorf("container '%s' not found or not owned by user", containerName)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()}) // 404 for security
		return nil, err
	}

	// Ownership confirmed (either superuser or direct owner)
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
	if len(zipReader.File) > maxLabArchiveEntries {
		return fmt.Errorf("%w: %d entries exceeds %d", errLabArchiveLimit, len(zipReader.File), maxLabArchiveEntries)
	}

	root, err := openWorkspaceRoot(targetDir)
	if err != nil {
		return err
	}
	defer root.Close()

	var totalBytes int64
	seenPaths := make(map[string]struct{}, len(zipReader.File))
	for _, entry := range zipReader.File {
		relativePath, pathErr := cleanArchiveEntryPath(entry.Name)
		if pathErr != nil {
			return pathErr
		}
		if _, duplicate := seenPaths[relativePath]; duplicate {
			return fmt.Errorf("archive contains duplicate path %q", relativePath)
		}
		seenPaths[relativePath] = struct{}{}
		if entry.FileInfo().IsDir() {
			if relativePath == "." {
				continue
			}
			if err := ensureTopologyRootDirectory(root, relativePath, uid, gid); err != nil {
				return fmt.Errorf("failed to create archive directory %q: %w", entry.Name, err)
			}
			continue
		}
		if entry.Mode()&os.ModeType != 0 {
			return fmt.Errorf("unsupported special or symbolic-link entry %q", entry.Name)
		}
		if entry.UncompressedSize64 > uint64(maxLabArchiveUncompressedBytes-totalBytes) {
			return fmt.Errorf("%w: uncompressed content exceeds %d bytes", errLabArchiveLimit, maxLabArchiveUncompressedBytes)
		}
		totalBytes += int64(entry.UncompressedSize64)

		source, openErr := entry.Open()
		if openErr != nil {
			return fmt.Errorf("failed to open archive entry %q: %w", entry.Name, openErr)
		}
		writeErr := writeArchiveFile(root, relativePath, source, int64(entry.UncompressedSize64), entry.Mode(), uid, gid)
		closeErr := source.Close()
		if writeErr != nil {
			return fmt.Errorf("failed to extract archive entry %q: %w", entry.Name, writeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("failed to close archive entry %q: %w", entry.Name, closeErr)
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
	root, err := openWorkspaceRoot(targetDir)
	if err != nil {
		return err
	}
	defer root.Close()

	entryCount := 0
	var totalBytes int64
	seenPaths := make(map[string]struct{})
	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		entryCount++
		if entryCount > maxLabArchiveEntries {
			return fmt.Errorf("%w: more than %d entries", errLabArchiveLimit, maxLabArchiveEntries)
		}
		relativePath, pathErr := cleanArchiveEntryPath(header.Name)
		if pathErr != nil {
			return pathErr
		}
		if _, duplicate := seenPaths[relativePath]; duplicate {
			return fmt.Errorf("archive contains duplicate path %q", relativePath)
		}
		seenPaths[relativePath] = struct{}{}

		switch header.Typeflag {
		case tar.TypeDir:
			if relativePath == "." {
				continue
			}
			if err := ensureTopologyRootDirectory(root, relativePath, uid, gid); err != nil {
				return fmt.Errorf("failed to create archive directory %q: %w", header.Name, err)
			}

		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > maxLabArchiveUncompressedBytes-totalBytes {
				return fmt.Errorf("%w: uncompressed content exceeds %d bytes", errLabArchiveLimit, maxLabArchiveUncompressedBytes)
			}
			totalBytes += header.Size
			if err := writeArchiveFile(root, relativePath, tarReader, header.Size, header.FileInfo().Mode(), uid, gid); err != nil {
				return fmt.Errorf("failed to extract archive entry %q: %w", header.Name, err)
			}

		default:
			return fmt.Errorf("unsupported special or symbolic-link entry %q", header.Name)
		}
	}
	return nil
}

const (
	maxLabArchiveEntries           = 10_000
	maxLabArchiveCompressedBytes   = int64(256 << 20)
	maxLabArchiveUncompressedBytes = int64(256 << 20)
	maxLabArchiveRequestBytes      = maxLabArchiveCompressedBytes + int64(1<<20)
)

var errLabArchiveLimit = errors.New("lab archive exceeds configured limit")

func cleanArchiveEntryPath(name string) (string, error) {
	normalized := filepath.FromSlash(strings.ReplaceAll(strings.TrimSpace(name), `\`, "/"))
	cleanPath := filepath.Clean(normalized)
	if cleanPath == "" || cleanPath == "." {
		return ".", nil
	}
	if filepath.IsAbs(cleanPath) || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("illegal path in archive: %q attempts to escape target directory", name)
	}
	return cleanPath, nil
}

func writeArchiveFile(root *os.Root, relativePath string, source io.Reader, expectedSize int64, mode os.FileMode, uid, gid int) error {
	if relativePath == "." {
		return fmt.Errorf("archive file entry has an empty path")
	}
	parentPath := filepath.Dir(relativePath)
	if parentPath != "." {
		if err := ensureTopologyRootDirectory(root, parentPath, uid, gid); err != nil {
			return err
		}
	}

	fileMode := os.FileMode(0o640)
	if mode.Perm()&0o111 != 0 {
		fileMode = 0o750
	}
	destination, err := root.OpenFile(relativePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return err
	}
	if err := destination.Chown(uid, gid); err != nil {
		_ = destination.Close()
		return err
	}
	limitedSource := &io.LimitedReader{R: source, N: expectedSize + 1}
	written, copyErr := io.Copy(destination, limitedSource)
	closeErr := destination.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written != expectedSize {
		return fmt.Errorf("archive entry size mismatch: wrote %d bytes, expected %d", written, expectedSize)
	}
	return nil
}

func getUserLabsBaseDirectoryInfo(username string) (baseDir string, uid, gid int, err error) {
	storage, err := workspacestore.ResolveUserStorage(username)
	if err != nil {
		return "", -1, -1, err
	}
	return storage.BaseDir, storage.UID, storage.GID, nil
}

// getLabDirectoryInfo returns the appropriate directory path for a lab,
// along with the user's UID/GID for ownership operations.
// If CLAB_LABS_ROOT is set, it returns $CLAB_LABS_ROOT/$username/$labName.
// Otherwise, it returns $HOME/.clab/$labName.
func getLabDirectoryInfo(username, labName string) (targetDir string, uid, gid int, err error) {
	targetDir, storage, err := workspacestore.ResolveLabDirectory(username, labName)
	if err != nil {
		return "", -1, -1, err
	}
	return targetDir, storage.UID, storage.GID, nil
}

func ensureUserLabsBaseDirectory(baseDir string, uid, gid int) error {
	return workspacestore.EnsureUserBaseDirectory(baseDir, uid, gid)
}

func ensureLabDirectory(labDir string, uid, gid int) error {
	baseDir := filepath.Clean(filepath.Dir(labDir))
	cleanLabDir := filepath.Clean(labDir)
	if cleanLabDir == baseDir || !pathIsInsideRoot(baseDir, cleanLabDir) {
		return fmt.Errorf("lab directory escapes user workspace")
	}
	if err := ensureUserLabsBaseDirectory(baseDir, uid, gid); err != nil {
		return err
	}

	root, err := openWorkspaceRoot(baseDir)
	if err != nil {
		return err
	}
	defer root.Close()
	relativePath, err := filepath.Rel(baseDir, cleanLabDir)
	if err != nil || relativePath == "." || filepath.Dir(relativePath) != "." {
		return fmt.Errorf("invalid lab directory")
	}
	return ensureTopologyRootDirectory(root, relativePath, uid, gid)
}

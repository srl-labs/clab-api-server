// internal/api/tools_handlers.go
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/user" // <-- Ensure os/user is imported
	"path/filepath"
	"strconv" // <-- Ensure strconv is imported
	"strings"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/FloSch62/clab-api/internal/clab"
	"github.com/FloSch62/clab-api/internal/models"
	// "github.com/FloSch62/clab-api/internal/auth" // Already imported via helpers
	// "github.com/FloSch62/clab-api/internal/config" // Already imported via helpers
)

// --- TX Offload Handler ---

// @Summary Disable TX Checksum Offload
// @Description Disables TX checksum offload for the eth0 interface of a specific container. Requires SUPERUSER privileges.
// @Tags Tools
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param tx_request body models.DisableTxOffloadRequest true "Container Name"
// @Success 200 {object} models.GenericSuccessResponse "Offload disabled successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized (JWT)"
// @Failure 403 {object} models.ErrorResponse "Forbidden (User is not a superuser)"
// @Failure 404 {object} models.ErrorResponse "Container not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/tools/disable-tx-offload [post]
func DisableTxOffloadHandler(c *gin.Context) {
	username := c.GetString("username")

	// --- Authorization: Superuser Only ---
	if !isSuperuser(username) {
		log.Warnf("User '%s' attempted to use disable-tx-offload without superuser privileges.", username)
		c.JSON(http.StatusForbidden, models.ErrorResponse{Error: "Superuser privileges required for this operation."})
		return
	}

	var req models.DisableTxOffloadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("DisableTxOffload failed for superuser '%s': Invalid request body: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	if !isValidContainerName(req.ContainerName) {
		log.Warnf("DisableTxOffload failed for superuser '%s': Invalid container name format '%s'", username, req.ContainerName)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid container name format."})
		return
	}

	// Optional: Verify container exists (using the less efficient inspect --all method for now)
	// If performance is critical, direct runtime calls might be better.
	_, err := verifyContainerOwnership(c, username, req.ContainerName) // We check ownership even for superuser to ensure container exists
	if err != nil {
		// verifyContainerOwnership already sent the response (404 or 500)
		return
	}

	// --- Execute clab command ---
	args := []string{"tools", "disable-tx-offload", "-c", req.ContainerName}
	log.Infof("Superuser '%s' executing disable-tx-offload for container '%s'", username, req.ContainerName)

	_, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	if stderr != "" {
		log.Warnf("DisableTxOffload stderr for container '%s' (user '%s'): %s", req.ContainerName, username, stderr)
	}
	if err != nil {
		log.Errorf("DisableTxOffload failed for container '%s' (user '%s'): %v", req.ContainerName, username, err)
		errMsg := fmt.Sprintf("Failed to disable TX offload for container '%s': %s", req.ContainerName, err.Error())
		if stderr != "" {
			errMsg += "\nstderr: " + stderr
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	log.Infof("Successfully disabled TX offload for container '%s' (triggered by superuser '%s')", req.ContainerName, username)
	c.JSON(http.StatusOK, models.GenericSuccessResponse{Message: fmt.Sprintf("TX checksum offload disabled successfully for eth0 on container '%s'", req.ContainerName)})
}

// --- Certificate Handlers ---

// @Summary Create Certificate Authority (CA)
// @Description Creates a CA certificate and private key. Requires SUPERUSER privileges. Files are stored in the user's ~/.clab/certs/<ca_name>/ directory on the server.
// @Tags Tools - Certificates
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param ca_request body models.CACreateRequest true "CA Generation Parameters"
// @Success 200 {object} models.CertResponse "CA created successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid input parameters"
// @Failure 401 {object} models.ErrorResponse "Unauthorized (JWT)"
// @Failure 403 {object} models.ErrorResponse "Forbidden (User is not a superuser)"
// @Failure 500 {object} models.ErrorResponse "Internal server error (filesystem, clab execution)"
// @Router /api/v1/tools/certs/ca [post]
func CreateCAHandler(c *gin.Context) {
	username := c.GetString("username")

	// --- Authorization: Superuser Only ---
	if !isSuperuser(username) {
		log.Warnf("User '%s' attempted to use cert ca create without superuser privileges.", username)
		c.JSON(http.StatusForbidden, models.ErrorResponse{Error: "Superuser privileges required for this operation."})
		return
	}

	var req models.CACreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("CreateCA failed for superuser '%s': Invalid request body: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	// --- Validate and Set Defaults ---
	caName := strings.TrimSpace(req.Name)
	if caName == "" {
		caName = "ca" // Default name
	}
	if !isValidCertName(caName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid CA name format."})
		return
	}

	expiry := strings.TrimSpace(req.Expiry)
	if expiry == "" {
		expiry = "87600h" // Default expiry (10 years)
	}
	if !isValidDurationString(expiry) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid expiry duration format."})
		return
	}

	// Other fields use clab defaults if empty

	// --- Path Handling & Ownership Setup ---
	basePath, err := getUserCertBasePath(username) // Get ~/.clab/certs path
	if err != nil {
		// Error already logged in helper
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	// Get user UID/GID again for Chown operations below
	usr, lookupErr := user.Lookup(username)
	uid, uidErr := -1, fmt.Errorf("user lookup failed") // Initialize with error state
	gid, gidErr := -1, fmt.Errorf("user lookup failed")
	if lookupErr == nil {
		uid, uidErr = strconv.Atoi(usr.Uid)
		gid, gidErr = strconv.Atoi(usr.Gid)
	}
	canChown := lookupErr == nil && uidErr == nil && gidErr == nil
	if !canChown {
		log.Warnf("CreateCA: Cannot reliably get UID/GID for user '%s'. Ownership of generated files might be incorrect.", username)
	}

	// Create the specific subdirectory for this CA within the user's cert base path
	caDir := filepath.Join(basePath, caName)
	// Use 0750 or 0700 permissions for the CA directory itself
	if err := os.MkdirAll(caDir, 0750); err != nil {
		log.Errorf("Failed to create CA subdirectory '%s': %v", caDir, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to create CA directory"})
		return
	}

	// Attempt to set ownership of the specific CA directory
	if canChown {
		if err := os.Chown(caDir, uid, gid); err != nil {
			log.Warnf("Failed to set ownership of CA directory '%s' to user '%s': %v. Continuing...", caDir, username, err)
		} else {
			log.Debugf("Set ownership of CA directory '%s' to user '%s'", caDir, username)
		}
	}

	// --- Build clab args ---
	args := []string{"tools", "cert", "ca", "create"}
	args = append(args, "--path", caDir) // Use the specific CA directory path
	args = append(args, "--name", caName)
	args = append(args, "--expiry", expiry) // Use the validated expiry

	if req.CommonName != "" {
		args = append(args, "--cn", req.CommonName)
	}
	if req.Country != "" {
		args = append(args, "--country", req.Country)
	}
	if req.Locality != "" {
		args = append(args, "--locality", req.Locality)
	}
	if req.Organization != "" {
		args = append(args, "--organization", req.Organization)
	}
	if req.OrgUnit != "" {
		args = append(args, "--ou", req.OrgUnit)
	}

	log.Infof("Superuser '%s' creating CA '%s' in user's path '%s'", username, caName, caDir)

	// --- Execute clab command ---
	_, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	if stderr != "" {
		log.Warnf("CreateCA stderr for CA '%s' (user '%s'): %s", caName, username, stderr)
	}
	if err != nil {
		log.Errorf("CreateCA failed for CA '%s' (user '%s'): %v", caName, username, err)
		errMsg := fmt.Sprintf("Failed to create CA '%s': %s", caName, err.Error())
		if stderr != "" {
			errMsg += "\nstderr: " + stderr
		}
		// Attempt cleanup of directory? Maybe not, could contain partial results.
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	// --- Attempt to set ownership of generated files ---
	if canChown {
		certFilePath := filepath.Join(caDir, caName+".pem")
		keyFilePath := filepath.Join(caDir, caName+".key")
		csrFilePath := filepath.Join(caDir, caName+".csr") // clab creates this too

		for _, fPath := range []string{certFilePath, keyFilePath, csrFilePath} {
			if _, statErr := os.Stat(fPath); statErr == nil { // Check if file exists before chown
				if chownErr := os.Chown(fPath, uid, gid); chownErr != nil {
					log.Warnf("Failed to set ownership of generated file '%s' to user '%s': %v", fPath, username, chownErr)
				} else {
					log.Debugf("Set ownership of generated file '%s' to user '%s'", fPath, username)
				}
			} else if !os.IsNotExist(statErr) {
				log.Warnf("Error checking status of generated file '%s' before chown: %v", fPath, statErr)
			}
		}
	}

	log.Infof("Successfully created CA '%s' for superuser '%s' in user directory", caName, username)

	// Construct relative paths for response (relative to the user's cert base dir)
	certRelPath := filepath.Join(caName, caName+".pem")
	keyRelPath := filepath.Join(caName, caName+".key")
	csrRelPath := filepath.Join(caName, caName+".csr")

	c.JSON(http.StatusOK, models.CertResponse{
		Message:  fmt.Sprintf("CA '%s' created successfully in user's cert directory.", caName),
		CertPath: certRelPath, // These relative paths are correct
		KeyPath:  keyRelPath,
		CSRPath:  csrRelPath,
	})
}

// @Summary Sign Certificate
// @Description Creates a certificate/key and signs it with a previously generated CA. Requires SUPERUSER privileges. Files are stored in the user's ~/.clab/certs/<ca_name>/ directory.
// @Tags Tools - Certificates
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param sign_request body models.CertSignRequest true "Certificate Signing Parameters"
// @Success 200 {object} models.CertResponse "Certificate signed successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid input parameters (name, hosts, CA name, etc.)"
// @Failure 401 {object} models.ErrorResponse "Unauthorized (JWT)"
// @Failure 403 {object} models.ErrorResponse "Forbidden (User is not a superuser)"
// @Failure 404 {object} models.ErrorResponse "Specified CA not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error (filesystem, clab execution)"
// @Router /api/v1/tools/certs/sign [post]
func SignCertHandler(c *gin.Context) {
	username := c.GetString("username")

	// --- Authorization: Superuser Only ---
	if !isSuperuser(username) {
		log.Warnf("User '%s' attempted to use cert sign without superuser privileges.", username)
		c.JSON(http.StatusForbidden, models.ErrorResponse{Error: "Superuser privileges required for this operation."})
		return
	}

	var req models.CertSignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("SignCert failed for superuser '%s': Invalid request body: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	// --- Validate Inputs ---
	certName := strings.TrimSpace(req.Name)
	if !isValidCertName(certName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid certificate name format."})
		return
	}
	caName := strings.TrimSpace(req.CaName)
	if !isValidCertName(caName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid CA name format."})
		return
	}
	if len(req.Hosts) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "At least one host (SAN) is required."})
		return // Added return
	}
	// Basic validation for hosts - prevent obvious issues
	for _, h := range req.Hosts {
		if strings.ContainsAny(h, " ,;\"'()") { // Avoid spaces, commas, quotes etc. within a host entry
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("Invalid character in host entry: '%s'", h)})
			return
		}
	}
	hostsStr := strings.Join(req.Hosts, ",") // Join for clab command

	keySize := req.KeySize
	if keySize == 0 {
		keySize = 2048 // Default key size
	} else if keySize < 2048 { // Enforce minimum reasonable size
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Key size must be 2048 or greater."})
		return
	}

	commonName := strings.TrimSpace(req.CommonName)
	if commonName == "" {
		commonName = certName // Default CN to cert name
	}

	// --- Path Handling & Ownership Info ---
	basePath, err := getUserCertBasePath(username) // Get ~/.clab/certs path
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	usr, lookupErr := user.Lookup(username)
	uid, uidErr := -1, fmt.Errorf("user lookup failed") // Initialize with error state
	gid, gidErr := -1, fmt.Errorf("user lookup failed")
	if lookupErr == nil {
		uid, uidErr = strconv.Atoi(usr.Uid)
		gid, gidErr = strconv.Atoi(usr.Gid)
	}
	canChown := lookupErr == nil && uidErr == nil && gidErr == nil
	if !canChown {
		log.Warnf("SignCert: Cannot reliably get UID/GID for user '%s'. Ownership of generated files might be incorrect.", username)
	}

	// Certs are stored *within* the specified CA's subdirectory in the user's home
	caDir := filepath.Join(basePath, caName)
	caCertPath := filepath.Join(caDir, caName+".pem")
	caKeyPath := filepath.Join(caDir, caName+".key")

	// Check if CA files exist before proceeding
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		log.Warnf("SignCert failed for user '%s': CA certificate not found at '%s'", username, caCertPath)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("CA '%s' certificate not found in user's cert directory.", caName)})
		return
	}
	if _, err := os.Stat(caKeyPath); os.IsNotExist(err) {
		log.Warnf("SignCert failed for user '%s': CA key not found at '%s'", username, caKeyPath)
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("CA '%s' key not found in user's cert directory.", caName)})
		return
	}

	// Output path for the new cert/key is the CA directory
	outputPath := caDir // clab will write the new cert/key/csr into this directory

	// --- Build clab args ---
	args := []string{"tools", "cert", "sign"}
	args = append(args, "--path", outputPath)    // Directory where new cert/key/csr are created
	args = append(args, "--name", certName)      // Base name for new files
	args = append(args, "--ca-cert", caCertPath) // Path to existing CA cert
	args = append(args, "--ca-key", caKeyPath)   // Path to existing CA key
	args = append(args, "--hosts", hostsStr)
	args = append(args, "--cn", commonName)
	args = append(args, "--key-size", strconv.Itoa(keySize))

	if req.Country != "" {
		args = append(args, "--country", req.Country)
	}
	if req.Locality != "" {
		args = append(args, "--locality", req.Locality)
	}
	if req.Organization != "" {
		args = append(args, "--organization", req.Organization)
	}
	if req.OrgUnit != "" {
		args = append(args, "--ou", req.OrgUnit)
	}

	log.Infof("Superuser '%s' signing certificate '%s' using CA '%s' in user's path '%s'", username, certName, caName, outputPath)

	// --- Execute clab command ---
	_, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	if stderr != "" {
		log.Warnf("SignCert stderr for cert '%s' using CA '%s' (user '%s'): %s", certName, caName, username, stderr)
	}
	if err != nil {
		log.Errorf("SignCert failed for cert '%s' using CA '%s' (user '%s'): %v", certName, caName, username, err)
		errMsg := fmt.Sprintf("Failed to sign certificate '%s' using CA '%s': %s", certName, caName, err.Error())
		if stderr != "" {
			errMsg += "\nstderr: " + stderr
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	// --- Attempt to set ownership of newly generated files ---
	if canChown {
		certFilePath := filepath.Join(outputPath, certName+".pem")
		keyFilePath := filepath.Join(outputPath, certName+".key")
		csrFilePath := filepath.Join(outputPath, certName+".csr")

		for _, fPath := range []string{certFilePath, keyFilePath, csrFilePath} {
			if _, statErr := os.Stat(fPath); statErr == nil { // Check if file exists
				if chownErr := os.Chown(fPath, uid, gid); chownErr != nil {
					log.Warnf("Failed to set ownership of generated file '%s' to user '%s': %v", fPath, username, chownErr)
				} else {
					log.Debugf("Set ownership of generated file '%s' to user '%s'", fPath, username)
				}
			} else if !os.IsNotExist(statErr) {
				log.Warnf("Error checking status of generated file '%s' before chown: %v", fPath, statErr)
			}
		}
	}

	log.Infof("Successfully signed certificate '%s' using CA '%s' for superuser '%s' in user directory", certName, caName, username)

	// Construct relative paths for response (relative to user's cert base dir)
	certRelPath := filepath.Join(caName, certName+".pem")
	keyRelPath := filepath.Join(caName, certName+".key")
	csrRelPath := filepath.Join(caName, certName+".csr")

	c.JSON(http.StatusOK, models.CertResponse{
		Message:  fmt.Sprintf("Certificate '%s' signed successfully by CA '%s' in user's cert directory.", certName, caName),
		CertPath: certRelPath, // These relative paths are correct
		KeyPath:  keyRelPath,
		CSRPath:  csrRelPath,
	})
}

// --- Netem Handlers ---

// @Summary Set Network Emulation
// @Description Sets network impairments (delay, jitter, loss, rate, corruption) on a specific interface of a node within a lab. Checks lab ownership.
// @Tags Tools - Netem
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param labName path string true "Name of the lab" example="my-lab"
// @Param nodeName path string true "Logical name of the node in the topology" example="srl1"
// @Param interfaceName path string true "Name of the interface within the container" example="eth1"
// @Param netem_params body models.NetemSetRequest true "Network Emulation Parameters"
// @Success 200 {object} models.GenericSuccessResponse "Impairments set successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid input (lab/node/interface name, netem params)"
// @Failure 401 {object} models.ErrorResponse "Unauthorized (JWT)"
// @Failure 404 {object} models.ErrorResponse "Lab, node, or interface not found / not owned"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/labs/{labName}/nodes/{nodeName}/interfaces/{interfaceName}/netem [put]
func SetNetemHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	nodeName := c.Param("nodeName")
	interfaceName := c.Param("interfaceName")

	// --- Validate Path Params ---
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name format."})
		return
	}
	if !isValidLabName(nodeName) { // Using labName regex for node name simplicity
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid node name format."})
		return
	}
	if !isValidInterfaceName(interfaceName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid interface name format."})
		return
	}

	// --- Bind and Validate Body ---
	var req models.NetemSetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("SetNetem failed for user '%s', lab '%s', node '%s': Invalid request body: %v", username, labName, nodeName, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	// Validate netem parameters
	if !isValidDurationString(req.Delay) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid delay format."})
		return
	}
	if req.Jitter != "" && !isValidDurationString(req.Jitter) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid jitter format."})
		return
	}
	if req.Jitter != "" && req.Delay == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Jitter requires Delay to be set."})
		return
	}
	if !isValidPercentage(req.Loss) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Loss must be between 0.0 and 100.0."})
		return
	}
	if !isValidPercentage(req.Corruption) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Corruption must be between 0.0 and 100.0."})
		return
	}
	// Rate (uint) is implicitly non-negative

	// --- Verify Ownership & Get Container Name ---
	_, ownerCheckErr := verifyLabOwnership(c, username, labName)
	if ownerCheckErr != nil {
		return // verifyLabOwnership sent response
	}
	containerName, nameErr := getNodeContainerName(labName, nodeName)
	if nameErr != nil {
		// Should not happen if path params are valid, but check anyway
		log.Errorf("Internal error generating container name for lab '%s', node '%s': %v", labName, nodeName, nameErr)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Internal error generating container name."})
		return
	}

	// --- Build clab args ---
	args := []string{"tools", "netem", "set", "-n", containerName, "-i", interfaceName}
	if req.Delay != "" {
		args = append(args, "--delay", req.Delay)
		if req.Jitter != "" {
			args = append(args, "--jitter", req.Jitter)
		}
	}
	if req.Loss > 0 {
		// Format float precisely for the command line if needed, though clab might handle it
		args = append(args, "--loss", strconv.FormatFloat(req.Loss, 'f', -1, 64))
	}
	if req.Rate > 0 {
		args = append(args, "--rate", strconv.FormatUint(uint64(req.Rate), 10))
	}
	if req.Corruption > 0 {
		args = append(args, "--corruption", strconv.FormatFloat(req.Corruption, 'f', -1, 64))
	}

	log.Infof("User '%s' setting netem on lab '%s', node '%s' (container '%s'), interface '%s'", username, labName, nodeName, containerName, interfaceName)

	// --- Execute clab command ---
	_, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	if stderr != "" {
		// Netem commands often print status to stderr on success
		log.Infof("SetNetem stderr for lab '%s', container '%s', interface '%s' (user '%s'): %s", labName, containerName, interfaceName, username, stderr)
	}
	if err != nil {
		// Check if the error indicates the interface doesn't exist
		if strings.Contains(stderr, "Cannot find device") || strings.Contains(err.Error(), "Cannot find device") {
			log.Warnf("SetNetem failed for user '%s': Interface '%s' not found on container '%s'", username, interfaceName, containerName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Interface '%s' not found on node '%s'", interfaceName, nodeName)})
			return
		}
		log.Errorf("SetNetem failed for lab '%s', container '%s', interface '%s' (user '%s'): %v", labName, containerName, interfaceName, username, err)
		errMsg := fmt.Sprintf("Failed to set netem on node '%s', interface '%s': %s", nodeName, interfaceName, err.Error())
		if stderr != "" {
			errMsg += "\nstderr: " + stderr
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	log.Infof("Successfully set netem for lab '%s', node '%s', interface '%s' (user '%s')", labName, nodeName, interfaceName, username)
	c.JSON(http.StatusOK, models.GenericSuccessResponse{Message: fmt.Sprintf("Network emulation parameters set for node '%s', interface '%s'", nodeName, interfaceName)})
}

// @Summary Reset Network Emulation
// @Description Removes all network impairments from a specific interface of a node within a lab. Checks lab ownership.
// @Tags Tools - Netem
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Name of the lab" example="my-lab"
// @Param nodeName path string true "Logical name of the node in the topology" example="srl1"
// @Param interfaceName path string true "Name of the interface within the container" example="eth1"
// @Success 200 {object} models.GenericSuccessResponse "Impairments reset successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid input (lab/node/interface name)"
// @Failure 401 {object} models.ErrorResponse "Unauthorized (JWT)"
// @Failure 404 {object} models.ErrorResponse "Lab, node, or interface not found / not owned"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/labs/{labName}/nodes/{nodeName}/interfaces/{interfaceName}/netem [delete]
func ResetNetemHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	nodeName := c.Param("nodeName")
	interfaceName := c.Param("interfaceName")

	// --- Validate Path Params ---
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name format."})
		return
	}
	if !isValidLabName(nodeName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid node name format."})
		return
	}
	if !isValidInterfaceName(interfaceName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid interface name format."})
		return
	}

	// --- Verify Ownership & Get Container Name ---
	_, ownerCheckErr := verifyLabOwnership(c, username, labName)
	if ownerCheckErr != nil {
		return // verifyLabOwnership sent response
	}
	containerName, nameErr := getNodeContainerName(labName, nodeName)
	if nameErr != nil {
		log.Errorf("Internal error generating container name for lab '%s', node '%s': %v", labName, nodeName, nameErr)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Internal error generating container name."})
		return
	}

	// --- Build clab args ---
	args := []string{"tools", "netem", "reset", "-n", containerName, "-i", interfaceName}

	log.Infof("User '%s' resetting netem on lab '%s', node '%s' (container '%s'), interface '%s'", username, labName, nodeName, containerName, interfaceName)

	// --- Execute clab command ---
	_, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	if stderr != "" {
		// Reset command also prints status to stderr
		log.Infof("ResetNetem stderr for lab '%s', container '%s', interface '%s' (user '%s'): %s", labName, containerName, interfaceName, username, stderr)
	}
	if err != nil {
		// Check if the error indicates the interface doesn't exist (less likely for reset, but possible)
		if strings.Contains(stderr, "Cannot find device") || strings.Contains(err.Error(), "Cannot find device") {
			log.Warnf("ResetNetem failed for user '%s': Interface '%s' not found on container '%s'", username, interfaceName, containerName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Interface '%s' not found on node '%s'", interfaceName, nodeName)})
			return
		}
		log.Errorf("ResetNetem failed for lab '%s', container '%s', interface '%s' (user '%s'): %v", labName, containerName, interfaceName, username, err)
		errMsg := fmt.Sprintf("Failed to reset netem on node '%s', interface '%s': %s", nodeName, interfaceName, err.Error())
		if stderr != "" {
			errMsg += "\nstderr: " + stderr
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	log.Infof("Successfully reset netem for lab '%s', node '%s', interface '%s' (user '%s')", labName, nodeName, interfaceName, username)
	c.JSON(http.StatusOK, models.GenericSuccessResponse{Message: fmt.Sprintf("Network emulation parameters reset for node '%s', interface '%s'", nodeName, interfaceName)})
}

// @Summary Show Network Emulation
// @Description Shows network impairments for all interfaces on a specific node within a lab. Checks lab ownership.
// @Tags Tools - Netem
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Name of the lab" example="my-lab"
// @Param nodeName path string true "Logical name of the node in the topology" example="srl1"
// @Success 200 {object} models.NetemShowResponse "Current network emulation parameters"
// @Failure 400 {object} models.ErrorResponse "Invalid input (lab/node name)"
// @Failure 401 {object} models.ErrorResponse "Unauthorized (JWT)"
// @Failure 404 {object} models.ErrorResponse "Lab or node not found / not owned"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/labs/{labName}/nodes/{nodeName}/netem [get]
func ShowNetemHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	nodeName := c.Param("nodeName")

	// --- Validate Path Params ---
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name format."})
		return
	}
	if !isValidLabName(nodeName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid node name format."})
		return
	}

	// --- Verify Ownership & Get Container Name ---
	_, ownerCheckErr := verifyLabOwnership(c, username, labName)
	if ownerCheckErr != nil {
		return // verifyLabOwnership sent response
	}
	containerName, nameErr := getNodeContainerName(labName, nodeName)
	if nameErr != nil {
		log.Errorf("Internal error generating container name for lab '%s', node '%s': %v", labName, nodeName, nameErr)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Internal error generating container name."})
		return
	}

	// --- Build clab args ---
	// Use --format json
	args := []string{"tools", "netem", "show", "-n", containerName, "--format", "json"}

	log.Infof("User '%s' showing netem on lab '%s', node '%s' (container '%s')", username, labName, nodeName, containerName)

	// --- Execute clab command ---
	stdout, stderr, err := clab.RunClabCommand(c.Request.Context(), username, args...)

	if stderr != "" {
		// Show command shouldn't produce stderr on success with JSON format
		log.Warnf("ShowNetem stderr for lab '%s', container '%s' (user '%s'): %s", labName, containerName, username, stderr)
	}
	if err != nil {
		// Check if node (container) wasn't found
		if strings.Contains(stderr, "container not found") || strings.Contains(err.Error(), "container not found") {
			log.Warnf("ShowNetem failed for user '%s': Node '%s' (container '%s') not found in lab '%s'", username, nodeName, containerName, labName)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("Node '%s' not found in lab '%s'", nodeName, labName)})
			return
		}
		log.Errorf("ShowNetem failed for lab '%s', container '%s' (user '%s'): %v", labName, containerName, username, err)
		errMsg := fmt.Sprintf("Failed to show netem for node '%s': %s", nodeName, err.Error())
		if stderr != "" {
			errMsg += "\nstderr: " + stderr
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	// --- Parse JSON Output ---
	var result models.NetemShowResponse
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		log.Errorf("ShowNetem failed for user '%s': Failed to parse JSON output for node '%s': %v. Output: %s", username, nodeName, err, stdout)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to parse command output."})
		return
	}

	log.Infof("Successfully retrieved netem info for lab '%s', node '%s' (user '%s')", labName, nodeName, username)
	c.JSON(http.StatusOK, result)
}

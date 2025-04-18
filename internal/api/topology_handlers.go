// internal/api/topology_handlers.go
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// @Summary Generate Topology
// @Description Generates a containerlab topology file based on CLOS definitions. Optionally deploys it, setting the owner to the authenticated user.
// @Description Deployment is DENIED if a lab with the target name already exists.
// @Description The 'images' and 'licenses' fields expect a map where the key is the node 'kind' and the value is the corresponding image or license path (e.g., {"nokia_srlinux": "ghcr.io/..."}).
// @Description If Deploy=true, the topology is saved to the user's ~/.clab/<labName>/ directory before deployment, and the 'outputFile' field is ignored.
// @Description If Deploy=false and 'outputFile' is empty, YAML is returned directly.
// @Description If Deploy=false and 'outputFile' is set, the file is saved to that path on the server (requires API server write permissions).
// @Tags Topology Generation
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param generate_request body models.GenerateRequest true "Topology generation parameters. Note: 'images'/'licenses' format is { \"kind\": \"path\" }." example({ "defaultKind": "nokia_srlinux", "deploy": true, "groupPrefix": "clos-tier", "images": { "nokia_srlinux": "ghcr.io/nokia/srlinux:latest" }, "ipv4Subnet": "172.50.20.0/24", "licenses": {}, "ipv6Subnet": "2001:172:20:20::/64", "managementNetwork": "clos-mgmt", "maxWorkers": 0, "name": "3-tier-clos", "nodePrefix": "clos-node", "outputFile": "", "tiers": [ { "count": 4, "kind": "nokia_srlinux", "type": "ixrd3" } ] }) // Example structure
// @Success 200 {object} models.GenerateResponse "Generation successful (YAML or deploy output)"
// @Failure 400 {object} models.ErrorResponse "Invalid input parameters"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 409 {object} models.ErrorResponse "Conflict (Lab already exists and Deploy=true)"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/generate [post]
func GenerateTopologyHandler(c *gin.Context) {
	username := c.GetString("username") // Needed for potential deploy logging/context
	ctx := c.Request.Context()

	var req models.GenerateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("GenerateTopology failed for user '%s': Invalid request body: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	// --- Basic Input Validation ---
	if !isValidLabName(req.Name) { // Validate the lab name itself
		log.Warnf("GenerateTopology failed for user '%s': Invalid characters in lab name '%s'", username, req.Name)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}
	if len(req.Tiers) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "At least one tier must be defined in 'tiers'."})
		return
	}
	if len(req.Images) == 0 { // Already checked by binding:"required", but double-check
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "'images' field is required."})
		return
	}

	log.Debugf("GenerateTopology user '%s': Generating topology '%s' (deploy=%t)", username, req.Name, req.Deploy)

	// --- Pre-Deployment Check (if Deploy=true) ---
	if req.Deploy {
		labInfo, exists, checkErr := getLabInfo(ctx, req.Name) // Use req.Name as the lab name
		if checkErr != nil {
			log.Errorf("GenerateTopology failed for user '%s': Error checking lab '%s' existence: %v", username, req.Name, checkErr)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Error checking lab '%s' status: %s", req.Name, checkErr.Error())})
			return
		}
		if exists {
			log.Warnf("GenerateTopology failed for user '%s': Lab '%s' already exists (owner: '%s'). Deployment with generate is not allowed if lab exists.", username, req.Name, labInfo.Owner)
			c.JSON(http.StatusConflict, models.ErrorResponse{Error: fmt.Sprintf("Lab '%s' already exists. Cannot generate and deploy.", req.Name)})
			return
		}
		log.Infof("GenerateTopology user '%s': Lab '%s' does not exist. Proceeding with generation and deployment.", username, req.Name)
	}
	// --- End Pre-Deployment Check ---

	// --- Construct clab generate arguments ---
	args := []string{"generate", "--name", req.Name}

	// Build --nodes flag string(s)
	for i, tier := range req.Tiers {
		if tier.Count <= 0 {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("Tier %d has invalid count: %d", i+1, tier.Count)})
			return
		}
		nodeStr := strconv.Itoa(tier.Count)
		if tier.Kind != "" {
			nodeStr += ":" + tier.Kind
			if tier.Type != "" {
				nodeStr += ":" + tier.Type
			}
		} else if tier.Type != "" {
			defaultKind := req.DefaultKind
			if defaultKind == "" {
				defaultKind = "srl" // clab's default
			}
			nodeStr += ":" + defaultKind + ":" + tier.Type
		}
		args = append(args, "--nodes", nodeStr)
	}

	if req.DefaultKind != "" {
		args = append(args, "--kind", req.DefaultKind)
	}
	if len(req.Images) > 0 { // Already checked mandatory, but keep structure
		var imgArgs []string
		for kind, img := range req.Images {
			imgArgs = append(imgArgs, fmt.Sprintf("%s=%s", kind, img))
		}
		args = append(args, "--image", strings.Join(imgArgs, ","))
	}
	if len(req.Licenses) > 0 {
		var licArgs []string
		for kind, lic := range req.Licenses {
			cleanLic, licErr := clab.SanitizePath(lic) // Apply basic sanitization
			if licErr != nil {
				log.Warnf("GenerateTopology failed for user '%s': Invalid license path '%s': %v", username, lic, licErr)
				c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("Invalid license path for kind '%s': %s", kind, licErr.Error())})
				return
			}
			licArgs = append(licArgs, fmt.Sprintf("%s=%s", kind, cleanLic))
		}
		args = append(args, "--license", strings.Join(licArgs, ","))
	}
	if req.NodePrefix != "" {
		args = append(args, "--node-prefix", req.NodePrefix)
	}
	if req.GroupPrefix != "" {
		args = append(args, "--group-prefix", req.GroupPrefix)
	}
	if req.ManagementNetwork != "" {
		args = append(args, "--network", req.ManagementNetwork)
	}
	if req.IPv4Subnet != "" {
		args = append(args, "--ipv4-subnet", req.IPv4Subnet)
	}
	if req.IPv6Subnet != "" {
		args = append(args, "--ipv6-subnet", req.IPv6Subnet)
	}

	// --- Determine Output/Action and Target File Path ---
	var targetFilePath string // Path used by clab generate --file and clab deploy -t
	var err error
	var usr *user.User
	var uid, gid int

	if req.Deploy {
		// --- Deploy=true: Save to user's ~/.clab/<labName>/ directory ---
		if req.OutputFile != "" {
			log.Warnf("GenerateTopology user '%s': 'outputFile' field provided but Deploy=true. Ignoring 'outputFile' and saving to user's ~/.clab directory.", username)
		}

		// Get User Home Directory, UID/GID
		usr, err = user.Lookup(username)
		if err != nil {
			log.Errorf("GenerateTopology failed for user '%s': Could not determine user details: %v", username, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Could not determine user details."})
			return
		}
		homeDir := usr.HomeDir
		uid, err = strconv.Atoi(usr.Uid)
		if err != nil {
			log.Errorf("GenerateTopology failed for user '%s': Could not process user UID: %v", username, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Could not process user UID."})
			return
		}
		gid, err = strconv.Atoi(usr.Gid)
		if err != nil {
			log.Errorf("GenerateTopology failed for user '%s': Could not process user GID: %v", username, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Could not process user GID."})
			return
		}

		// Construct Paths, Create Dir, Set Ownership
		clabUserDir := filepath.Join(homeDir, ".clab")
		targetDir := filepath.Join(clabUserDir, req.Name)               // Use req.Name for the directory
		targetFilePath = filepath.Join(targetDir, req.Name+".clab.yml") // Use req.Name for the filename

		err = os.MkdirAll(targetDir, 0750) // Create user's lab dir
		if err != nil {
			log.Errorf("GenerateTopology failed for user '%s': Failed to create lab directory '%s': %v", username, targetDir, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to create lab directory: %s.", err.Error())})
			return
		}
		err = os.Chown(targetDir, uid, gid) // Set ownership of the directory
		if err != nil {
			// Log error but continue, maybe file write will succeed anyway if API user has perms
			log.Warnf("GenerateTopology user '%s': Failed to set ownership on lab directory '%s': %v. Continuing...", username, targetDir, err)
		}
		log.Infof("GenerateTopology user '%s': Ensured directory '%s' exists and attempted ownership set.", username, targetDir)

		args = append(args, "--file", targetFilePath) // Tell clab generate where to save

	} else {
		// --- Deploy=false: Save to OutputFile (server path) or return YAML ---
		if req.OutputFile != "" {
			// User specified output file on the server. Sanitize the path.
			targetFilePath, err = clab.SanitizePath(req.OutputFile)
			if err != nil {
				log.Warnf("GenerateTopology failed for user '%s': Invalid OutputFile path '%s': %v", username, req.OutputFile, err)
				c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid OutputFile path: " + err.Error()})
				return
			}
			// Ensure directory exists? Let's check.
			dir := filepath.Dir(targetFilePath)
			if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
				// Attempt to create the directory (API server user needs permission)
				if mkdirErr := os.MkdirAll(dir, 0750); mkdirErr != nil {
					log.Warnf("GenerateTopology failed for user '%s': OutputFile directory does not exist and could not be created: %s. Error: %v", username, dir, mkdirErr)
					c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("OutputFile directory does not exist and could not be created: %s", dir)})
					return
				}
				log.Infof("GenerateTopology user '%s': Created OutputFile directory: %s", username, dir)
			} else if statErr != nil {
				log.Warnf("GenerateTopology failed for user '%s': Error checking OutputFile directory '%s': %v", username, dir, statErr)
				c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Error checking OutputFile directory: %s", dir)})
				return
			}
			log.Infof("GenerateTopology user '%s': Will save generated topology to server file: %s", username, targetFilePath)
			args = append(args, "--file", targetFilePath)
		} else {
			// Return YAML directly via stdout
			targetFilePath = "-" // Special value for clab
			args = append(args, "--file", targetFilePath)
			log.Infof("GenerateTopology user '%s': Will output generated topology YAML to stdout.", username)
		}
	}

	// --- Execute clab generate ---
	log.Infof("GenerateTopology user '%s': Executing clab generate...", username)
	genStdout, genStderr, genErr := clab.RunClabCommand(ctx, username, args...)

	if genStderr != "" {
		log.Warnf("GenerateTopology user '%s': clab generate stderr: %s", username, genStderr)
	}
	if genErr != nil {
		// Don't need temp file cleanup anymore
		log.Errorf("GenerateTopology failed for user '%s': clab generate command error: %v", username, genErr)
		errMsg := fmt.Sprintf("Failed to generate topology '%s': %s", req.Name, genErr.Error())
		if genStderr != "" && (strings.Contains(genStderr, "level=error") || strings.Contains(genStderr, "failed")) {
			errMsg += "\nstderr: " + genStderr
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	log.Infof("GenerateTopology user '%s': clab generate successful.", username)

	// --- Set File Ownership (only if Deploy=true and file was created) ---
	if req.Deploy {
		err = os.Chown(targetFilePath, uid, gid)
		if err != nil {
			log.Warnf("GenerateTopology user '%s': Failed to set ownership on generated topology file '%s': %v. Deployment might fail if permissions are incorrect.", username, targetFilePath, err)
			// Don't fail the whole operation here, let deploy try
		} else {
			log.Infof("GenerateTopology user '%s': Set ownership on generated file '%s'", username, targetFilePath)
		}
	}

	// --- Handle Response based on Action ---
	response := models.GenerateResponse{
		Message: fmt.Sprintf("Topology '%s' generated successfully.", req.Name),
		// Set SavedFilePath based on whether we saved to a real file
		SavedFilePath: "",
	}
	if targetFilePath != "-" {
		response.SavedFilePath = targetFilePath
	}

	if req.Deploy {
		// --- Execute clab deploy ---
		// No temp file cleanup needed

		// Use --reconfigure because generate+deploy implies starting fresh for this specific generated topology
		deployArgs := []string{"deploy", "--owner", username, "-t", targetFilePath, "--reconfigure", "--format", "json"}
		if req.MaxWorkers > 0 {
			deployArgs = append(deployArgs, "--max-workers", strconv.Itoa(req.MaxWorkers))
		}

		log.Infof("GenerateTopology user '%s': Deploying generated topology '%s' from '%s'...", username, req.Name, targetFilePath)
		deployStdout, deployStderr, deployErr := clab.RunClabCommand(ctx, username, deployArgs...)

		if deployStderr != "" {
			log.Warnf("GenerateTopology (deploy step) user '%s': clab deploy stderr: %s", username, deployStderr)
		}
		if deployErr != nil {
			// Deploy failed, but generation succeeded. Return failure but include context.
			log.Errorf("GenerateTopology (deploy step) failed for user '%s': clab deploy command error: %v", username, deployErr)
			errMsg := fmt.Sprintf("Topology '%s' generated to '%s', but deployment failed: %s", req.Name, targetFilePath, deployErr.Error())
			if deployStderr != "" && (strings.Contains(deployStderr, "level=error") || strings.Contains(deployStderr, "failed")) {
				errMsg += "\nstderr: " + deployStderr
			}
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
			return
		}

		log.Infof("GenerateTopology user '%s': Deployment of generated topology '%s' successful.", username, req.Name)
		response.Message = fmt.Sprintf("Topology '%s' generated and deployed successfully.", req.Name)
		// SavedFilePath is already set correctly

		// Attempt to capture deploy output (try JSON first)
		var deployResult json.RawMessage
		if err := json.Unmarshal([]byte(deployStdout), &deployResult); err == nil {
			response.DeployOutput = deployResult
		} else {
			// If not JSON, store as plain text within the RawMessage (needs quoting and escaping)
			response.DeployOutput = json.RawMessage(strconv.Quote(deployStdout))
			log.Warnf("GenerateTopology user '%s': Deploy output was not valid JSON, returning as escaped string.", username)
		}
		c.JSON(http.StatusOK, response)

	} else {
		// Not deploying
		if targetFilePath == "-" {
			// Returned YAML via stdout
			response.TopologyYAML = genStdout
			response.SavedFilePath = "" // Explicitly clear path
		}
		// If OutputFile was set, SavedFilePath is already populated.
		c.JSON(http.StatusOK, response)
	}
}

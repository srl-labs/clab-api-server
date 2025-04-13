// internal/api/topology_handlers.go
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/FloSch62/clab-api/internal/clab"
	"github.com/FloSch62/clab-api/internal/models"
)

// @Summary Generate Topology
// @Description Generates a containerlab topology file based on CLOS definitions. Optionally deploys it.
// @Tags Topology Generation
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param generate_request body models.GenerateRequest true "Topology generation parameters"
// @Success 200 {object} models.GenerateResponse "Generation successful (YAML or deploy output)"
// @Failure 400 {object} models.ErrorResponse "Invalid input parameters"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/generate [post]
func GenerateTopologyHandler(c *gin.Context) {
	username := c.GetString("username") // Needed for potential deploy logging/context

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
	// Add more validation for tier contents, image/license formats if needed

	log.Debugf("GenerateTopology user '%s': Generating topology '%s' (deploy=%t)", username, req.Name, req.Deploy)

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
			// If kind is empty but type is not, clab might need kind explicitly. Assume default.
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
	if len(req.Images) > 0 {
		var imgArgs []string
		for kind, img := range req.Images {
			imgArgs = append(imgArgs, fmt.Sprintf("%s=%s", kind, img))
		}
		args = append(args, "--image", strings.Join(imgArgs, ","))
	}
	if len(req.Licenses) > 0 {
		var licArgs []string
		for kind, lic := range req.Licenses {
			// Security: Ensure license path is somewhat sane? Difficult without knowing server layout.
			// Rely on clab's own handling for now. Basic sanitization might be good.
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
	// MaxWorkers is handled during deploy step if needed
	// Deploy and OutputFile flags are handled specially below

	// --- Determine Output/Action ---
	var generatedFilePath string
	var err error
	cleanupTempFile := false

	if req.Deploy {
		// Need to save to a file first. Use temp file if OutputFile not specified.
		if req.OutputFile != "" {
			// User specified output file. Sanitize the path.
			generatedFilePath, err = clab.SanitizePath(req.OutputFile)
			if err != nil {
				log.Warnf("GenerateTopology failed for user '%s': Invalid OutputFile path '%s': %v", username, req.OutputFile, err)
				c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid OutputFile path: " + err.Error()})
				return
			}
			// Ensure directory exists? Let's check.
			dir := filepath.Dir(generatedFilePath)
			if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
				log.Warnf("GenerateTopology failed for user '%s': OutputFile directory does not exist: %s", username, dir)
				c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("OutputFile directory does not exist: %s", dir)})
				return
			}
			log.Infof("GenerateTopology user '%s': Will save generated topology to specified file: %s", username, generatedFilePath)

		} else {
			// Create temp file
			tmpFile, err := os.CreateTemp("", fmt.Sprintf("clab-gen-%s-*.yml", req.Name))
			if err != nil {
				log.Errorf("GenerateTopology failed for user '%s': Cannot create temp file: %v", username, err)
				c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to create temporary file for deployment."})
				return
			}
			generatedFilePath = tmpFile.Name()
			tmpFile.Close() // Close immediately, clab will write to it
			cleanupTempFile = true
			log.Debugf("GenerateTopology user '%s': Using temp file for deployment: %s", username, generatedFilePath)
		}
		args = append(args, "--file", generatedFilePath)

	} else {
		// Not deploying. Check if saving to file or returning YAML.
		if req.OutputFile != "" {
			generatedFilePath, err = clab.SanitizePath(req.OutputFile)
			if err != nil {
				log.Warnf("GenerateTopology failed for user '%s': Invalid OutputFile path '%s': %v", username, req.OutputFile, err)
				c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid OutputFile path: " + err.Error()})
				return
			}
			dir := filepath.Dir(generatedFilePath)
			if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
				log.Warnf("GenerateTopology failed for user '%s': OutputFile directory does not exist: %s", username, dir)
				c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("OutputFile directory does not exist: %s", dir)})
				return
			}
			args = append(args, "--file", generatedFilePath)
			log.Infof("GenerateTopology user '%s': Will save generated topology to specified file: %s", username, generatedFilePath)
		} else {
			// Return YAML directly via stdout
			args = append(args, "--file", "-")
			log.Infof("GenerateTopology user '%s': Will output generated topology YAML to stdout.", username)
		}
	}

	// --- Execute clab generate ---
	log.Infof("GenerateTopology user '%s': Executing clab generate...", username)
	genStdout, genStderr, genErr := clab.RunClabCommand(c.Request.Context(), username, args...)

	if genStderr != "" {
		log.Warnf("GenerateTopology user '%s': clab generate stderr: %s", username, genStderr)
	}
	if genErr != nil {
		if cleanupTempFile {
			os.Remove(generatedFilePath) // Clean up temp file on error
		}
		log.Errorf("GenerateTopology failed for user '%s': clab generate command error: %v", username, genErr)
		errMsg := fmt.Sprintf("Failed to generate topology '%s': %s", req.Name, genErr.Error())
		if genStderr != "" && (strings.Contains(genStderr, "level=error") || strings.Contains(genStderr, "failed")) {
			errMsg += "\nstderr: " + genStderr
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
		return
	}

	log.Infof("GenerateTopology user '%s': clab generate successful.", username)

	// --- Handle Response based on Action ---
	response := models.GenerateResponse{
		Message:       fmt.Sprintf("Topology '%s' generated successfully.", req.Name),
		SavedFilePath: "", // Default to empty
	}
	if generatedFilePath != "" && req.OutputFile != "" {
		response.SavedFilePath = generatedFilePath // Only set if OutputFile was specified
	}

	if req.Deploy {
		// --- Execute clab deploy ---
		if cleanupTempFile {
			defer os.Remove(generatedFilePath) // Ensure temp file cleanup even if deploy fails
		}

		deployArgs := []string{"deploy", "-t", generatedFilePath, "--reconfigure"}
		if req.MaxWorkers > 0 {
			deployArgs = append(deployArgs, "--max-workers", strconv.Itoa(req.MaxWorkers))
		}
		deployArgs = append(deployArgs, "--format", "json") // Request JSON output from deploy

		log.Infof("GenerateTopology user '%s': Deploying generated topology '%s' from '%s'...", username, req.Name, generatedFilePath)
		deployStdout, deployStderr, deployErr := clab.RunClabCommand(c.Request.Context(), username, deployArgs...)

		if deployStderr != "" {
			log.Warnf("GenerateTopology (deploy step) user '%s': clab deploy stderr: %s", username, deployStderr)
		}
		if deployErr != nil {
			// Deploy failed, but generation succeeded. Return failure but include context.
			log.Errorf("GenerateTopology (deploy step) failed for user '%s': clab deploy command error: %v", username, deployErr)
			errMsg := fmt.Sprintf("Topology '%s' generated, but deployment failed: %s", req.Name, deployErr.Error())
			// Include path only if it was explicitly set or temp file used
			if req.OutputFile != "" || cleanupTempFile {
				errMsg = fmt.Sprintf("Topology '%s' generated to '%s', but deployment failed: %s", req.Name, generatedFilePath, deployErr.Error())
			}
			if deployStderr != "" && (strings.Contains(deployStderr, "level=error") || strings.Contains(deployStderr, "failed")) {
				errMsg += "\nstderr: " + deployStderr
			}
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: errMsg})
			return
		}

		log.Infof("GenerateTopology user '%s': Deployment of generated topology '%s' successful.", username, req.Name)
		response.Message = fmt.Sprintf("Topology '%s' generated and deployed successfully.", req.Name)
		if req.OutputFile != "" { // Ensure path is included if file was saved explicitly
			response.SavedFilePath = generatedFilePath
		} else if cleanupTempFile {
			response.SavedFilePath = generatedFilePath // Include temp path for reference if deploy succeeded
		}

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
		if req.OutputFile == "" {
			// Returned YAML via stdout
			response.TopologyYAML = genStdout
			response.SavedFilePath = "" // Explicitly clear path
		}
		// If OutputFile was set, SavedFilePath is already populated.
		c.JSON(http.StatusOK, response)
	}
}

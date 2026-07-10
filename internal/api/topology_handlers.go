// internal/api/topology_handlers.go
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// @Summary Generate containerlab topology
// @Description Generates a containerlab topology from CLOS definitions and can optionally deploy it for the authenticated user.
// @Description
// @Description **Notes**
// @Description - Deployment is denied if a lab with the target name already exists.
// @Description - The `images` and `licenses` fields map node kind to image or license path (e.g., {"nokia_srlinux":"ghcr.io/..."}).
// @Description - When `deploy=true`, the topology is saved to the user's managed lab directory and `outputFile` is ignored.
// @Description - When `deploy=false` and `outputFile` is empty, YAML is returned in the response.
// @Description - When `deploy=false` and `outputFile` is set, the relative file path is saved inside the authenticated user's managed workspace.
// @Tags Topology Generation
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param generate_request body models.GenerateRequest true "Topology generation parameters. The 'images' field maps kind to image path." example(`{"name": "3-tier-clos", "tiers": [{"count": 4, "kind": "nokia_srlinux", "type": "ixrd3"}, {"count": 2, "kind": "arista_ceos"}], "defaultKind": "nokia_srlinux", "images": {"nokia_srlinux": "ghcr.io/nokia/srlinux:latest", "arista_ceos": "ceos:4.28.0F", "cisco_xr": "cisco/xrd:7.8.2"}, "licenses": {"nokia_srlinux": "/path/to/license.key"}, "nodePrefix": "clos-node", "groupPrefix": "clos-tier", "managementNetwork": "clos-mgmt", "ipv4Subnet": "172.50.20.0/24", "ipv6Subnet": "2001:172:20:20::/64", "deploy": true, "maxWorkers": 0, "outputFile": ""}`)
// @Success 200 {object} models.GenerateResponse "Generation successful (YAML or deploy output)"
// @Failure 400 {object} models.ErrorResponse "Invalid input parameters"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 409 {object} models.ErrorResponse "Conflict (Lab already exists and Deploy=true)"
// @Failure 500 {object} models.ErrorResponse "Internal server error or clab execution failed"
// @Router /api/v1/generate [post]
func GenerateTopologyHandler(c *gin.Context) {
	username := c.GetString("username")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var req models.GenerateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("GenerateTopology failed for user '%s': Invalid request body: %v", username, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	// --- Basic Input Validation ---
	if !isValidLabName(req.Name) {
		log.Warnf("GenerateTopology failed for user '%s': Invalid characters in lab name '%s'", username, req.Name)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid characters in lab name."})
		return
	}
	if len(req.Tiers) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "At least one tier must be defined in 'tiers'."})
		return
	}
	if len(req.Images) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "'images' field is required."})
		return
	}

	log.Debugf("GenerateTopology user '%s': Generating topology '%s' (deploy=%t)", username, req.Name, req.Deploy)

	// --- Pre-Deployment Check (if Deploy=true) ---
	if req.Deploy {
		releaseLabOperation, ok := beginLabOperationOrConflict(c, req.Name, "deploy")
		if !ok {
			return
		}
		defer releaseLabOperation()

		labInfo, exists, checkErr := getLabInfo(ctx, username, req.Name)
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

	// --- Convert tiers to service format ---
	tiers := make([]clab.TierDefinition, len(req.Tiers))
	for i, tier := range req.Tiers {
		if tier.Count <= 0 {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("Tier %d has invalid count: %d", i+1, tier.Count)})
			return
		}
		tiers[i] = clab.TierDefinition{
			Count: tier.Count,
			Kind:  tier.Kind,
			Type:  tier.Type,
		}
	}

	// --- Validate license paths ---
	cleanLicenses := make(map[string]string)
	for kind, lic := range req.Licenses {
		cleanLic, licErr := clab.SanitizePath(lic)
		if licErr != nil {
			log.Warnf("GenerateTopology failed for user '%s': Invalid license path '%s': %v", username, lic, licErr)
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: fmt.Sprintf("Invalid license path for kind '%s': %s", kind, licErr.Error())})
			return
		}
		cleanLicenses[kind] = cleanLic
	}

	// --- Generate topology using service ---
	svc := GetClabService()
	log.Infof("GenerateTopology user '%s': Generating topology '%s'...", username, req.Name)

	topoYAML, err := svc.GenerateTopology(ctx, clab.GenerateTopologyOptions{
		Name:              req.Name,
		Tiers:             tiers,
		DefaultKind:       req.DefaultKind,
		Images:            req.Images,
		Licenses:          cleanLicenses,
		NodePrefix:        req.NodePrefix,
		GroupPrefix:       req.GroupPrefix,
		ManagementNetwork: req.ManagementNetwork,
		IPv4Subnet:        req.IPv4Subnet,
		IPv6Subnet:        req.IPv6Subnet,
	})

	if err != nil {
		log.Errorf("GenerateTopology failed for user '%s': %v", username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to generate topology '%s': %s", req.Name, err.Error())})
		return
	}

	log.Infof("GenerateTopology user '%s': Topology '%s' generated successfully.", username, req.Name)

	// --- Determine Output/Action and Target File Path ---
	var targetFilePath string
	var uid, gid int

	if req.Deploy {
		// --- Deploy=true: Save to the user's managed lab directory ---
		if req.OutputFile != "" {
			log.Warnf("GenerateTopology user '%s': 'outputFile' field provided but Deploy=true. Ignoring 'outputFile' and saving to appropriate lab directory.", username)
		}

		// Get Lab Directory and User UID/GID
		targetDir, uidVal, gidVal, dirErr := getLabDirectoryInfo(username, req.Name)
		if dirErr != nil {
			log.Errorf("GenerateTopology failed for user '%s': %v", username, dirErr)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: dirErr.Error()})
			return
		}
		uid, gid = uidVal, gidVal

		targetFilePath = filepath.Join(targetDir, req.Name+".clab.yml")

		if err := ensureLabDirectory(targetDir, uid, gid); err != nil {
			log.Errorf("GenerateTopology failed for user '%s': Failed to create lab directory '%s': %v", username, targetDir, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to create lab directory: %s.", err.Error())})
			return
		}
		log.Infof("GenerateTopology user '%s': Ensured directory '%s' exists and attempted ownership set.", username, targetDir)

		rootedTarget, resolveErr := resolveUserRootedFilePath(username, targetFilePath)
		if resolveErr != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: resolveErr.Error()})
			return
		}
		if err := writeRootedFile(rootedTarget, topoYAML, false); err != nil {
			log.Errorf("GenerateTopology failed for user '%s': Failed to write topology file '%s': %v", username, targetFilePath, err)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to write topology file: %s", err.Error())})
			return
		}

	} else {
		// --- Deploy=false: Save inside the user's workspace or return YAML ---
		if req.OutputFile != "" {
			absolutePath, rootPath, relativePath, outputUID, outputGID, resolveErr := resolveWorkspacePath(username, req.OutputFile, false)
			if resolveErr != nil {
				log.Warnf("GenerateTopology failed for user '%s': Invalid OutputFile path '%s': %v", username, req.OutputFile, resolveErr)
				c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid OutputFile path: " + resolveErr.Error()})
				return
			}
			targetFilePath = absolutePath
			if err := writeRootedFile(rootedFilePath{
				rootPath:     rootPath,
				relativePath: relativePath,
				uid:          outputUID,
				gid:          outputGID,
			}, topoYAML, true); err != nil {
				log.Errorf("GenerateTopology failed for user '%s': Failed to write topology file '%s': %v", username, targetFilePath, err)
				c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: fmt.Sprintf("Failed to write topology file: %s", err.Error())})
				return
			}

			log.Infof("GenerateTopology user '%s': Saved generated topology to server file: %s", username, targetFilePath)
		}
	}

	// --- Handle Response based on Action ---
	response := models.GenerateResponse{
		Message:       fmt.Sprintf("Topology '%s' generated successfully.", req.Name),
		SavedFilePath: "",
	}
	if targetFilePath != "" {
		response.SavedFilePath = targetFilePath
	}

	if req.Deploy {
		// --- Execute deployment ---
		log.Infof("GenerateTopology user '%s': Deploying generated topology '%s' from '%s'...", username, req.Name, targetFilePath)

		containers, deployErr := svc.Deploy(ctx, clab.DeployOptions{
			TopoPath:    targetFilePath,
			Username:    username,
			Reconfigure: true,
			MaxWorkers:  uint(req.MaxWorkers),
		})

		if deployErr != nil {
			log.Errorf("GenerateTopology (deploy step) failed for user '%s': %v", username, deployErr)
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{
				Error: fmt.Sprintf("Topology '%s' generated to '%s', but deployment failed: %s", req.Name, targetFilePath, deployErr.Error()),
			})
			return
		}

		log.Infof("GenerateTopology user '%s': Deployment of generated topology '%s' successful.", username, req.Name)
		response.Message = fmt.Sprintf("Topology '%s' generated and deployed successfully.", req.Name)

		// Convert containers to response format (map by lab name for consistency)
		deployResult := make(map[string][]models.ClabContainerInfo)
		for _, container := range containers {
			containerInfo := clab.ContainerToClabContainerInfo(container)
			deployResult[containerInfo.LabName] = append(deployResult[containerInfo.LabName], containerInfo)
		}

		// Marshal the result to JSON
		deployJSON, err := json.Marshal(deployResult)
		if err != nil {
			log.Warnf("GenerateTopology user '%s': Failed to marshal deploy result: %v", username, err)
			deployJSON = []byte("{}")
		}
		response.DeployOutput = json.RawMessage(deployJSON)

		c.JSON(http.StatusOK, response)

	} else {
		// Not deploying
		if targetFilePath == "" {
			// Return YAML directly
			response.TopologyYAML = string(topoYAML)
		}
		c.JSON(http.StatusOK, response)
	}
}

// extractJSONFromClabOutput attempts to isolate the JSON block from clab CLI output
// that may include banners, warnings, or ANSI art before/after the JSON payload.
func extractJSONFromClabOutput(output string) string {
	start := -1
	end := -1
	for i := 0; i < len(output); i++ {
		if output[i] == '{' {
			start = i
			break
		}
	}
	for i := len(output) - 1; i >= 0; i-- {
		if output[i] == '}' {
			end = i
			break
		}
	}
	if start == -1 || end == -1 || end <= start {
		return ""
	}
	candidate := output[start : end+1]
	if json.Valid([]byte(candidate)) {
		return candidate
	}
	return ""
}

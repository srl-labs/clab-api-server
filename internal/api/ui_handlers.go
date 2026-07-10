package api

import (
	"encoding/base64"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/models"
)

// @Summary List custom node templates
// @Description Returns the authenticated user's persisted TopoViewer custom node templates. If none have been saved yet, seeded defaults matching VS Code are returned.
// @Tags UI
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.CustomNodesResponse "Custom node templates"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/ui/custom-nodes [get]
func GetCustomNodesHandler(c *gin.Context) {
	username := c.GetString("username")

	nodes, err := loadCustomNodes(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, customNodesResponse(nodes))
}

// @Summary Replace custom node templates
// @Description Replaces the authenticated user's full TopoViewer custom node template collection.
// @Tags UI
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.CustomNodesReplaceRequest true "Replacement custom node template collection"
// @Success 200 {object} models.CustomNodesResponse "Updated custom node templates"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/ui/custom-nodes [put]
func PutCustomNodesHandler(c *gin.Context) {
	username := c.GetString("username")

	var req models.CustomNodesReplaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}
	for _, node := range req.CustomNodes {
		if err := validateCustomNodeTemplate(node); err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
			return
		}
	}

	if err := saveCustomNodes(username, req.CustomNodes); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, customNodesResponse(req.CustomNodes))
}

// @Summary Save custom node template
// @Description Creates or updates a single TopoViewer custom node template for the authenticated user.
// @Tags UI
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.CustomNodeTemplate true "Custom node template payload"
// @Success 200 {object} models.CustomNodesResponse "Updated custom node templates"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/ui/custom-nodes [post]
func SaveCustomNodeHandler(c *gin.Context) {
	username := c.GetString("username")

	var req models.CustomNodeTemplate
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}
	if len(req) == 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: custom node payload is required"})
		return
	}
	if err := validateCustomNodeTemplate(req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: err.Error()})
		return
	}

	nodes, err := loadCustomNodes(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	oldName := customNodeString(req, "oldName")
	delete(req, "oldName")

	if customNodeBool(req, "setDefault") {
		for _, node := range nodes {
			node["setDefault"] = false
		}
	}

	replacement := cloneCustomNodeTemplate(req)
	replacementName := customNodeString(replacement, "name")
	targetIndex := -1
	if oldName != "" {
		targetIndex = findCustomNodeIndexByName(nodes, oldName)
	}
	if targetIndex < 0 {
		targetIndex = findCustomNodeIndexByName(nodes, replacementName)
	}

	if targetIndex >= 0 {
		nodes[targetIndex] = replacement
	} else {
		nodes = append(nodes, replacement)
	}

	if err := saveCustomNodes(username, nodes); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, customNodesResponse(nodes))
}

// @Summary Delete custom node template
// @Description Deletes a single TopoViewer custom node template for the authenticated user.
// @Tags UI
// @Security BearerAuth
// @Produce json
// @Param name path string true "Custom node name"
// @Success 200 {object} models.CustomNodesResponse "Updated custom node templates"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/ui/custom-nodes/{name} [delete]
func DeleteCustomNodeHandler(c *gin.Context) {
	username := c.GetString("username")
	name := strings.TrimSpace(c.Param("name"))
	if name == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Custom node name is required"})
		return
	}

	nodes, err := loadCustomNodes(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	filtered := make([]models.CustomNodeTemplate, 0, len(nodes))
	for _, node := range nodes {
		if customNodeString(node, "name") == name {
			continue
		}
		filtered = append(filtered, cloneCustomNodeTemplate(node))
	}

	if err := saveCustomNodes(username, filtered); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, customNodesResponse(filtered))
}

// @Summary Set default custom node template
// @Description Sets the default TopoViewer custom node template for the authenticated user.
// @Tags UI
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.CustomNodeDefaultRequest true "Default custom node selection"
// @Success 200 {object} models.CustomNodesResponse "Updated custom node templates"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Custom node not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/ui/custom-nodes/default [post]
func SetDefaultCustomNodeHandler(c *gin.Context) {
	username := c.GetString("username")

	var req models.CustomNodeDefaultRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	nodes, err := loadCustomNodes(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	targetIndex := findCustomNodeIndexByName(nodes, req.Name)
	if targetIndex < 0 {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: "Custom node not found"})
		return
	}

	for idx, node := range nodes {
		node["setDefault"] = idx == targetIndex
	}

	if err := saveCustomNodes(username, nodes); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, customNodesResponse(nodes))
}

// @Summary List global custom icons
// @Description Returns the authenticated user's global custom TopoViewer icon library from ~/.clab/icons.
// @Tags UI
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.IconListResponse "Global custom icons"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/ui/icons [get]
func ListGlobalIconsHandler(c *gin.Context) {
	username := c.GetString("username")

	globalDir, _, _, err := getGlobalIconsDir(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	icons, listErr := listIconsFromDir(username, globalDir, "global")
	if listErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to list icons: " + listErr.Error()})
		return
	}

	c.JSON(http.StatusOK, models.IconListResponse{Icons: icons})
}

// @Summary Upload global custom icon
// @Description Uploads a new global custom TopoViewer icon into ~/.clab/icons for the authenticated user.
// @Tags UI
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.IconUploadRequest true "Custom icon upload payload"
// @Success 200 {object} models.IconUploadResponse "Upload success"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 409 {object} models.ErrorResponse "Rejected due to built-in icon name conflict"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/ui/icons [post]
func UploadGlobalIconHandler(c *gin.Context) {
	username := c.GetString("username")

	var req models.IconUploadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	ext := strings.ToLower(filepath.Ext(req.FileName))
	if !isSupportedIconExtension(ext) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Only SVG and PNG icon uploads are supported"})
		return
	}

	baseName := sanitizeIconName(req.FileName)
	if baseName == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Icon file name is invalid after sanitization"})
		return
	}
	if isBuiltInIconName(baseName) {
		c.JSON(http.StatusConflict, models.ErrorResponse{Error: "Icon name conflicts with a built-in icon"})
		return
	}

	body, err := base64.StdEncoding.DecodeString(req.DataBase64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Icon payload is not valid base64"})
		return
	}

	globalDir, uid, gid, dirErr := getGlobalIconsDir(username)
	if dirErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: dirErr.Error()})
		return
	}
	if err := ensureOwnedDir(username, globalDir, uid, gid); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to ensure global icons directory: " + err.Error()})
		return
	}

	iconName := uniqueIconName(username, globalDir, baseName)
	if err := writeOwnedFile(username, filepath.Join(globalDir, iconName+ext), body, uid, gid); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to store icon: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.IconUploadResponse{
		Success:  true,
		IconName: iconName,
	})
}

// @Summary Delete global custom icon
// @Description Deletes a global custom TopoViewer icon from ~/.clab/icons for the authenticated user.
// @Tags UI
// @Security BearerAuth
// @Produce json
// @Param iconName path string true "Custom icon name"
// @Success 200 {object} models.SimpleSuccessResponse "Delete success"
// @Failure 400 {object} models.ErrorResponse "Invalid icon name"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 404 {object} models.ErrorResponse "Icon not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/ui/icons/{iconName} [delete]
func DeleteGlobalIconHandler(c *gin.Context) {
	username := c.GetString("username")
	iconName := strings.TrimSpace(c.Param("iconName"))
	if !isValidIconName(iconName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid icon name"})
		return
	}

	globalDir, _, _, err := getGlobalIconsDir(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: err.Error()})
		return
	}

	deleted, deleteErr := deleteIconByName(username, globalDir, iconName)
	if deleteErr != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to delete icon: " + deleteErr.Error()})
		return
	}
	if !deleted {
		c.JSON(http.StatusNotFound, models.ErrorResponse{Error: "Icon not found"})
		return
	}

	c.JSON(http.StatusOK, models.SimpleSuccessResponse{Success: true})
}

// @Summary List lab custom icons
// @Description Returns the custom TopoViewer icons available for a lab, merging lab-local .clab-icons with the global ~/.clab/icons library. Lab-local icons take precedence.
// @Tags UI
// @Security BearerAuth
// @Produce json
// @Param labName path string true "Lab name"
// @Success 200 {object} models.IconListResponse "Merged lab icon list"
// @Failure 400 {object} models.ErrorResponse "Invalid lab name"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/ui/icons [get]
func ListLabIconsHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name"})
		return
	}

	icons, err := loadMergedLabIcons(username, labName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to list lab icons: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.IconListResponse{Icons: icons})
}

// @Summary Reconcile lab custom icons
// @Description Copies used custom icons from the global ~/.clab/icons library into the lab-local .clab-icons directory and removes unused lab-local custom icons.
// @Tags UI
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param labName path string true "Lab name"
// @Param request body models.IconReconcileRequest true "Used custom icon names"
// @Success 200 {object} models.SimpleSuccessResponse "Reconcile success"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/labs/{labName}/ui/icons/reconcile [post]
func ReconcileLabIconsHandler(c *gin.Context) {
	username := c.GetString("username")
	labName := c.Param("labName")
	if !isValidLabName(labName) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid lab name"})
		return
	}

	var req models.IconReconcileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	if err := reconcileLabIcons(username, labName, req.UsedIcons); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to reconcile lab icons: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.SimpleSuccessResponse{Success: true})
}

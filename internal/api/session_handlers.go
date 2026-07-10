package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/auth"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

const apiContractVersion = "v1"

var advertisedCapabilities = []string{
	"captures",
	"lab-lifecycle",
	"lifecycle-logs-ndjson",
	"runtime-events-ndjson",
	"runtime-images",
	"terminal-websocket",
	"topology-events-ndjson",
	"topology-files",
	"workspace-files",
}

// GetSessionHandler returns the identity and token lifetime for the current caller.
// @Summary Get authenticated session
// @Description Returns the stable API identity, roles, and bearer-token lifetime for the current caller.
// @Tags Session
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.SessionResponse "Authenticated session"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Router /api/v1/session [get]
func GetSessionHandler(c *gin.Context) {
	username := c.GetString("username")
	roles := []string{"api-user"}
	if isSuperuser(username) {
		roles = append(roles, "superuser")
	}

	response := models.SessionResponse{
		Username: username,
		Roles:    roles,
	}
	if claimsValue, exists := c.Get(authClaimsContextKey); exists {
		if claims, ok := claimsValue.(*auth.Claims); ok {
			if claims.IssuedAt != nil {
				issuedAt := claims.IssuedAt.Time.UTC()
				response.IssuedAt = &issuedAt
			}
			if claims.ExpiresAt != nil {
				expiresAt := claims.ExpiresAt.Time.UTC()
				response.ExpiresAt = &expiresAt
			}
		}
	}

	c.JSON(http.StatusOK, response)
}

// GetCapabilitiesHandler returns stable machine-readable server capabilities.
// @Summary Get API capabilities
// @Description Returns the API contract version, server version, runtime, and optional protocol features supported by this build.
// @Tags Session
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.CapabilitiesResponse "API capabilities"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Router /api/v1/capabilities [get]
func GetCapabilitiesHandler(c *gin.Context) {
	features := append([]string(nil), advertisedCapabilities...)
	c.JSON(http.StatusOK, models.CapabilitiesResponse{
		APIVersion:    apiContractVersion,
		ServerVersion: apiServerVersion,
		Runtime:       config.AppConfig.ClabRuntime,
		Features:      features,
	})
}

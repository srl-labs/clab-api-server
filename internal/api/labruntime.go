// internal/api/labruntime.go
package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// requireContainerRuntime guards routes that talk to Docker or Podman directly. With a
// lab runtime (c9s) they answer 501 "<operation> is not supported by lab runtime c9s".
func requireContainerRuntime(operation string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := clab.RequireContainerRuntime(operation); err != nil {
			c.AbortWithStatusJSON(http.StatusNotImplemented, models.ErrorResponse{Error: err.Error()})
			return
		}
		c.Next()
	}
}

// isUnsupportedByLabRuntime reports an operation the configured lab runtime cannot serve.
func isUnsupportedByLabRuntime(err error) bool {
	return errors.Is(err, clab.ErrNotSupportedByLabRuntime)
}

// serviceErrorStatus maps a service error to an HTTP status: 501 for operations the lab
// runtime cannot serve, fallback otherwise.
func serviceErrorStatus(err error, fallback int) int {
	if isUnsupportedByLabRuntime(err) {
		return http.StatusNotImplemented
	}
	return fallback
}

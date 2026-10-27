// internal/api/labruntime.go
package api

import (
	"errors"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/auth"
	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/kube"
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

// kubeUsers answers the c9s scoper's questions about Linux users and the shared workspace.
type kubeUsers struct{}

// KubeUsers returns the Linux user lookups the c9s scoper uses.
func KubeUsers() kube.Users { return kubeUsers{} }

func (kubeUsers) IsSuperuser(user string) bool { return isSuperuser(user) }

func (kubeUsers) InGroup(user, group string) bool {
	inGroup, err := auth.IsUserInGroup(user, group)
	if err != nil {
		log.Warnf("Group check of user '%s' in '%s' failed: %v", user, group, err)
		return false
	}
	return inGroup
}

// SharedGroup returns the group that owns the directory of a topology in the shared
// workspace. Its members share the lab's namespace.
func (kubeUsers) SharedGroup(topoPath string) (string, bool) {
	topoPath = strings.TrimSpace(topoPath)
	if topoPath == "" || !isSharedLabPath(topoPath) {
		return "", false
	}
	info, err := os.Stat(filepath.Dir(topoPath))
	if err != nil {
		return "", true
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", true
	}
	group, err := user.LookupGroupId(strconv.FormatUint(uint64(stat.Gid), 10))
	if err != nil {
		return "", true
	}
	return group.Name, true
}

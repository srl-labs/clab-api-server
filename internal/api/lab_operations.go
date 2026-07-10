package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

type labOperationRegistry struct {
	mu     sync.Mutex
	active map[string]string
}

var labOperations = &labOperationRegistry{
	active: make(map[string]string),
}

// deployReconfigureRequested keeps cleanup=true as a compatibility alias for
// clients that historically used that query parameter for deploy replacement.
func deployReconfigureRequested(c *gin.Context) bool {
	return c.Query("reconfigure") == "true" || c.Query("cleanup") == "true"
}

func (r *labOperationRegistry) begin(labName, operation string) (func(), string, bool) {
	key := strings.TrimSpace(labName)
	if key == "" {
		return func() {}, "", true
	}

	op := strings.TrimSpace(operation)
	if op == "" {
		op = "unknown"
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if active, ok := r.active[key]; ok {
		return nil, active, false
	}

	r.active[key] = op
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.active[key] == op {
			delete(r.active, key)
		}
	}, "", true
}

func beginLabOperationOrConflict(c *gin.Context, labName, operation string) (func(), bool) {
	release, active, ok := labOperations.begin(labName, operation)
	if ok {
		return release, true
	}

	c.Header("Retry-After", "2")
	c.JSON(http.StatusConflict, models.ErrorResponse{
		Error: fmt.Sprintf("Lab '%s' is busy with %s operation.", labName, active),
	})
	return nil, false
}

func ensureLabDestroyed(ctx context.Context, svc *clab.Service, labName string) error {
	containers, err := svc.ListContainers(ctx, clab.ListOptions{LabName: labName})
	if err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "no containers found") ||
			strings.Contains(msg, "no containerlab labs found") ||
			strings.Contains(msg, "not found") {
			return nil
		}
		return fmt.Errorf("failed to verify lab '%s' destroy state: %w", labName, err)
	}

	names := make([]string, 0, len(containers))
	for _, container := range containers {
		info := clab.ContainerToClabContainerInfo(container)
		if info.LabName != labName {
			continue
		}
		if info.Name != "" {
			names = append(names, info.Name)
		} else if info.ContainerID != "" {
			names = append(names, info.ContainerID)
		}
	}

	if len(names) > 0 {
		return fmt.Errorf(
			"destroy verification failed for lab '%s': %d container(s) still exist: %s",
			labName,
			len(names),
			strings.Join(names, ", "),
		)
	}

	return nil
}

package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// lifecycleRequestMargin is the time a lifecycle request gets beyond containerlab's
// timeout, for the checks and bookkeeping around the containerlab call, so the request
// does not end before containerlab reports its own timeout.
const lifecycleRequestMargin = 5 * time.Minute

// parseLifecycleTimeoutQuery reads the optional `timeout` query parameter of deploy,
// redeploy, apply and destroy: a positive Go duration (like containerlab's --timeout) of
// at most clab.MaxLifecycleTimeout. Zero means the server's default. It answers 400 and
// returns false for an invalid value.
func parseLifecycleTimeoutQuery(c *gin.Context) (time.Duration, bool) {
	raw, exists := c.GetQuery("timeout")
	if !exists || strings.TrimSpace(raw) == "" {
		return 0, true
	}
	timeout, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || timeout <= 0 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error: "Invalid 'timeout' query parameter. Use a positive duration like '10m'.",
		})
		return 0, false
	}
	if timeout > clab.MaxLifecycleTimeout {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error: fmt.Sprintf("Invalid 'timeout' query parameter: at most %s.", formatDuration(clab.MaxLifecycleTimeout)),
		})
		return 0, false
	}
	return timeout, true
}

// lifecycleRequestTimeout is how long a lifecycle request may run: containerlab's timeout
// for each of its containerlab calls (a redeploy destroys, then deploys) plus a margin.
func lifecycleRequestTimeout(timeout time.Duration, calls int) time.Duration {
	if calls < 1 {
		calls = 1
	}
	return time.Duration(calls)*clab.LifecycleTimeout(timeout) + lifecycleRequestMargin
}

// formatDuration prints a duration without trailing zero units: 10m, 1h30m, 45s.
func formatDuration(d time.Duration) string {
	text := d.String()
	if strings.HasSuffix(text, "m0s") {
		text = strings.TrimSuffix(text, "0s")
	}
	if strings.HasSuffix(text, "h0m") {
		text = strings.TrimSuffix(text, "0m")
	}
	return text
}

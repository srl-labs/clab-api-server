// internal/api/lab_host_handlers.go
package api

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/capture"
	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/kube"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// labHostCluster holds the names of the c9s server's kubeconfig context and cluster.
var labHostCluster struct {
	sync.RWMutex
	context string
	cluster string
}

// SetLabHostCluster sets the kubeconfig context and cluster name /api/v1/lab-host reports
// on c9s: names only, never the cluster's address or credentials.
func SetLabHostCluster(contextName, cluster string) {
	labHostCluster.Lock()
	defer labHostCluster.Unlock()
	labHostCluster.context, labHostCluster.cluster = contextName, cluster
}

// @Summary Get the lab host
// @Description Returns the runtime the server runs labs with and, on c9s, the Kubernetes cluster and deploy defaults the signed-in user's labs get.
// @Description
// @Description **Notes**
// @Description - `c9s` is only set when `runtime` is `c9s`. It names the kubeconfig context and cluster (`in-cluster` with the Pod's ServiceAccount) but never the cluster's address, credentials or file paths.
// @Description - `namespacePattern` is the server's namespace template rendered for the signed-in user, with `{lab}` left in. `sharedNamespacePattern` is the namespace of labs in the shared workspace.
// @Description - `metrics` reports whether the cluster serves `metrics.k8s.io`, which node stats need.
// @Description - `defaultTimeout` is containerlab's timeout of a deploy, redeploy, apply or destroy without `timeout` (with every runtime).
// @Description - `capture` is how the server captures packets, with every runtime: whether it runs Wireshark VNC sessions (`wiresharkVnc`; on c9s only while Docker answers on the server host), their image and pull policy and, with Docker and Podman, Edgeshark's packetflix port and the names (not values) of its extra environment variables.
// @Description - `c9s.noTopologyCR` is false: the server deploys every lab with clabernetes' Topology resource.
// @Description - The server must list `lab-host-info` in the `features` of `/health`.
// @Tags Health
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.LabHostResponse "Lab runtime and, on c9s, the cluster and deploy defaults"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Router /api/v1/lab-host [get]
func LabHostHandler(c *gin.Context) {
	response := models.LabHostResponse{
		Runtime:        clab.RuntimeKind(),
		DefaultTimeout: formatDuration(clab.DefaultLifecycleTimeout()),
		Capture:        captureLabHost(),
	}
	if clab.IsLabRuntime() {
		response.C9s = c9sLabHost(c.GetString("username"))
	}
	c.JSON(http.StatusOK, response)
}

// c9sLabHost describes the cluster and deploy defaults of a user's c9s labs.
func c9sLabHost(username string) *models.C9sLabHost {
	labHostCluster.RLock()
	contextName, cluster := labHostCluster.context, labHostCluster.cluster
	labHostCluster.RUnlock()

	cfg := config.AppConfig
	return &models.C9sLabHost{
		Context:                contextName,
		Cluster:                cluster,
		NamespacePattern:       kube.NamespacePattern(cfg.ClabKubeNamespaceTemplate, username),
		SharedNamespacePattern: kube.SharedNamespacePattern,
		ExposeType:             cfg.ClabC9sExposeType,
		Persistence:            cfg.ClabC9sPersistence,
		ImagePullSecret:        cfg.PullSecretName(),
		LabQuota:               cfg.ClabKubeLabQuota != "",
		NoTopologyCR:           clab.LabRuntimeNoTopologyCR,
		Metrics:                nodeStatsAvailable != nil && nodeStatsAvailable(),
	}
}

// captureLabHost describes Wireshark VNC and Edgeshark as the capture manager runs them.
func captureLabHost() models.CaptureLabHost {
	cfg := config.AppConfig
	normalized := capture.NormalizeConfig(capture.ManagerConfig{
		Runtime:               cfg.ClabRuntime,
		PacketflixPort:        cfg.CapturePacketflixPort,
		WiresharkDockerImage:  cfg.CaptureWiresharkDockerImage,
		WiresharkPullPolicy:   cfg.CaptureWiresharkPullPolicy,
		EdgesharkExtraEnvVars: cfg.CaptureEdgesharkExtraEnvVars,
	})
	result := models.CaptureLabHost{
		WiresharkVnc:        wiresharkVncAvailable(),
		WiresharkImage:      normalized.WiresharkDockerImage,
		WiresharkPullPolicy: normalized.WiresharkPullPolicy,
	}
	if !clab.IsLabRuntime() {
		result.Edgeshark = &models.EdgesharkLabHost{
			PacketflixPort: normalized.PacketflixPort,
			ExtraEnvVars:   capture.ExtraEnvVarNames(normalized.EdgesharkExtraEnvVars),
		}
	}
	return result
}

// wiresharkVncAvailable reports whether the server runs Wireshark VNC sessions: always next
// to Docker and Podman labs; for c9s labs while Docker answers on the server host.
func wiresharkVncAvailable() bool {
	return wiresharkVncProbe()
}

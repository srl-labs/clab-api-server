package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/srl-labs/clab-api-server/internal/auth"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// getLabHost asks GET /api/v1/lab-host as user and returns the raw body.
func getLabHost(t *testing.T, router *gin.Engine, user string) []byte {
	t.Helper()
	token, err := auth.GenerateJWT(user, time.Hour)
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/lab-host", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	return recorder.Body.Bytes()
}

func TestLabHostOnDockerNamesOnlyTheRuntime(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previous := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previous })
	config.AppConfig.ClabRuntime = config.RuntimeDocker
	config.AppConfig.JWTSecret = "test-secret"

	router := gin.New()
	SetupRoutes(router)

	unauthenticated := httptest.NewRecorder()
	router.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/api/v1/lab-host", nil))
	require.Equal(t, http.StatusUnauthorized, unauthenticated.Code)

	// Unset capture settings report the defaults the capture manager applies.
	require.JSONEq(t, `{
		"runtime": "docker",
		"defaultTimeout": "5m",
		"capture": {
			"wiresharkVnc": true,
			"wiresharkImage": "ghcr.io/srl-labs/wireshark-vnc-docker:latest",
			"wiresharkPullPolicy": "always",
			"edgeshark": {"packetflixPort": 5001, "extraEnvVars": []}
		}
	}`, string(getLabHost(t, router, "alice")))

	config.AppConfig.ClabRuntime = config.RuntimePodman
	config.AppConfig.CaptureWiresharkDockerImage = " registry.example/wireshark-vnc:1.2 "
	config.AppConfig.CaptureWiresharkPullPolicy = "Missing"
	config.AppConfig.CapturePacketflixPort = 5101
	config.AppConfig.CaptureEdgesharkExtraEnvVars = "NO_PROXY=localhost, HTTP_PROXY=http://user:secret@proxy:3128"
	body := getLabHost(t, router, "alice")
	require.JSONEq(t, `{
		"runtime": "podman",
		"defaultTimeout": "5m",
		"capture": {
			"wiresharkVnc": true,
			"wiresharkImage": "registry.example/wireshark-vnc:1.2",
			"wiresharkPullPolicy": "missing",
			"edgeshark": {"packetflixPort": 5101, "extraEnvVars": ["HTTP_PROXY", "NO_PROXY"]}
		}
	}`, string(body))
	// Edgeshark's variables are named, never their values.
	require.NotContains(t, string(body), "secret")
	require.NotContains(t, string(body), "localhost")

	// A pull policy the capture manager does not know falls back to always, as it does.
	config.AppConfig.CaptureWiresharkPullPolicy = "sometimes"
	var labHost models.LabHostResponse
	require.NoError(t, json.Unmarshal(getLabHost(t, router, "alice"), &labHost))
	require.Equal(t, "always", labHost.Capture.WiresharkPullPolicy)
}

func TestLabHostOnC9sDescribesTheClusterForTheUser(t *testing.T) {
	api := newC9sAPI(t)
	previousCluster := labHostCluster.cluster
	previousContext := labHostCluster.context
	t.Cleanup(func() { SetLabHostCluster(previousContext, previousCluster) })

	config.AppConfig.ClabKubeconfig = "/etc/clab-api-server/secret-kubeconfig"
	config.AppConfig.ClabKubeContext = "c9s-provisioner"
	config.AppConfig.ClabKubeUserPrefix = "clab:"
	config.AppConfig.ClabKubeNamespaceTemplate = "c9s-{user}-{lab}"
	config.AppConfig.ClabKubeLabQuota = "/etc/clab-api-server/lab-quota.yaml"
	config.AppConfig.ClabC9sImagePullSecret = "clab-api-server/regcred"
	config.AppConfig.ClabC9sExposeType = "None"
	config.AppConfig.ClabC9sPersistence = true
	config.AppConfig.CaptureWiresharkDockerImage = "registry.example/wireshark-vnc:1.2"
	config.AppConfig.CaptureWiresharkPullPolicy = "never"
	config.AppConfig.CaptureEdgesharkExtraEnvVars = "HTTP_PROXY=http://proxy:3128"
	SetLabHostCluster("c9s-provisioner", "c9s")
	SetNodeStatsAvailability(func() bool { return true })

	body := getLabHost(t, api.router, "alice")
	require.JSONEq(t, `{
		"runtime": "c9s",
		"defaultTimeout": "10m",
		"capture": {
			"wiresharkVnc": false,
			"wiresharkImage": "registry.example/wireshark-vnc:1.2",
			"wiresharkPullPolicy": "never"
		},
		"c9s": {
			"context": "c9s-provisioner",
			"cluster": "c9s",
			"namespacePattern": "c9s-alice-{lab}",
			"sharedNamespacePattern": "c9s-shared-{lab}",
			"exposeType": "None",
			"persistence": true,
			"imagePullSecret": "regcred",
			"labQuota": true,
			"noTopologyCR": false,
			"metrics": true
		}
	}`, string(body))
	for _, secret := range []string{"/etc/", "kubeconfig", "lab-quota", "clab-api-server/", "clab:", "https://", "token"} {
		require.NotContains(t, string(body), secret)
	}

	// Rendered for each user, as the namespaces of that user's labs are named.
	var other models.LabHostResponse
	require.NoError(t, json.Unmarshal(getLabHost(t, api.router, "J.Doe"), &other))
	require.Equal(t, "c9s-j-doe-{lab}", other.C9s.NamespacePattern)
	require.NotContains(t, other.C9s.NamespacePattern, "{user}")
	require.True(t, strings.Contains(other.C9s.NamespacePattern, "{lab}"))

	// In a Pod, without a pull secret, quota or metrics API.
	SetLabHostCluster("", "in-cluster")
	SetNodeStatsAvailability(func() bool { return false })
	config.AppConfig.ClabC9sImagePullSecret = ""
	config.AppConfig.ClabKubeLabQuota = ""
	config.AppConfig.ClabC9sPersistence = false
	config.AppConfig.ClabC9sExposeType = "LoadBalancer"
	require.JSONEq(t, `{
		"runtime": "c9s",
		"defaultTimeout": "10m",
		"capture": {
			"wiresharkVnc": false,
			"wiresharkImage": "registry.example/wireshark-vnc:1.2",
			"wiresharkPullPolicy": "never"
		},
		"c9s": {
			"context": "",
			"cluster": "in-cluster",
			"namespacePattern": "c9s-alice-{lab}",
			"sharedNamespacePattern": "c9s-shared-{lab}",
			"exposeType": "LoadBalancer",
			"persistence": false,
			"imagePullSecret": "",
			"labQuota": false,
			"noTopologyCR": false,
			"metrics": false
		}
	}`, string(getLabHost(t, api.router, "alice")))
}

func TestHealthAdvertisesLabHostInfo(t *testing.T) {
	previous := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previous })
	for _, runtime := range []string{config.RuntimeDocker, config.RuntimePodman, config.RuntimeC9s} {
		config.AppConfig.ClabRuntime = runtime
		require.Contains(t, healthResponse(t).Features, "lab-host-info", runtime)
	}
}

package clab

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/srl-labs/clab-api-server/internal/config"
)

func TestLifecycleTimeoutDefaultsToTheRuntimes(t *testing.T) {
	previous := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previous })

	config.AppConfig.ClabRuntime = "docker"
	require.Equal(t, 5*time.Minute, LifecycleTimeout(0))
	require.Equal(t, 20*time.Minute, LifecycleTimeout(20*time.Minute))
	require.Equal(t, 5*time.Minute, destroyTimeout(DestroyOptions{}))
	require.Equal(t, 30*time.Second, destroyTimeout(DestroyOptions{Timeout: 30 * time.Second}))
	require.Equal(t, 2*time.Minute, destroyTimeout(DestroyOptions{Graceful: true}))
	require.Equal(t, 30*time.Second, destroyTimeout(DestroyOptions{Graceful: true, Timeout: 30 * time.Second}))
	require.Equal(t, 5*time.Second, destroyTimeout(DestroyOptions{Graceful: true, Timeout: 30 * time.Second,
		GracefulTimeout: 5 * time.Second}))

	config.AppConfig.ClabRuntime = config.RuntimeC9s
	require.Equal(t, 10*time.Minute, LifecycleTimeout(0), "containerlab's c9s default")
	require.Equal(t, 45*time.Minute, LifecycleTimeout(45*time.Minute))
}

package clab

import (
	"fmt"
	"testing"
	"time"

	clabcore "github.com/srl-labs/containerlab/core"
	clablinks "github.com/srl-labs/containerlab/links"
	"github.com/stretchr/testify/require"
)

func TestContainerlabConstructionPreservesSpecialLinkNodes(t *testing.T) {
	for _, owner := range []string{"", "test-owner"} {
		t.Run("owner="+owner, func(t *testing.T) {
			containerlabMu.Lock()
			drainSpecialLinkNodes()
			host := clablinks.GetHostLinkNode()
			mgmt := clablinks.GetMgmtBrLinkNode()
			hostEP := clablinks.NewEndpointHost(clablinks.NewEndpointGeneric(host, "host-port", nil))
			mgmtEP := clablinks.NewEndpointBridge(clablinks.NewEndpointGeneric(mgmt, "mgmt-port", nil), true)
			_ = host.AddEndpoint(hostEP)
			_ = mgmt.AddEndpoint(mgmtEP)
			_ = clablinks.SetMgmtNetUnderlyingBridge("lab-bridge")
			containerlabMu.Unlock()
			t.Cleanup(func() {
				containerlabMu.Lock()
				defer containerlabMu.Unlock()
				drainSpecialLinkNodes()
			})

			var err error
			if owner == "" {
				_, err = newContainerLab()
			} else {
				_, err = newContainerLabForOwner(owner)
			}
			require.NoError(t, err)
			require.Equal(t, []clablinks.Endpoint{hostEP}, host.GetEndpoints())
			require.Equal(t, []clablinks.Endpoint{mgmtEP}, mgmt.GetEndpoints())
			require.Equal(t, "lab-bridge", mgmt.GetShortName())
		})
	}
}

func TestContainerlabOperationKeepsEndpointsUntilCompletion(t *testing.T) {
	unlock := lockContainerlabOperation()
	// Always release the lock before waiting for a blocked constructor on failure.
	released := false
	defer func() {
		if !released {
			unlock()
		}
	}()

	host := clablinks.GetHostLinkNode()
	mgmt := clablinks.GetMgmtBrLinkNode()
	for _, node := range []clablinks.Node{host, mgmt} {
		for _, name := range []string{"eth1", "eth2", "eth3"} {
			ep := clablinks.NewEndpointHost(clablinks.NewEndpointGeneric(node, name, nil))
			require.NoError(t, node.AddEndpoint(ep))
		}
	}
	require.NoError(t, clablinks.SetMgmtNetUnderlyingBridge("lab-bridge"))

	started := make(chan struct{})
	observed := make(chan error, 1)
	go func() {
		close(started)
		_, err := newContainerLab(func(*clabcore.CLab) error {
			if len(host.GetEndpoints()) != 0 || len(mgmt.GetEndpoints()) != 0 || mgmt.GetShortName() != "mgmt-net" {
				return fmt.Errorf("special link state was not reset before the next constructor")
			}
			return nil
		})
		observed <- err
	}()
	<-started
	select {
	case err := <-observed:
		t.Fatalf("constructor ran before the active operation completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	require.Len(t, host.GetEndpoints(), 3)
	require.Len(t, mgmt.GetEndpoints(), 3)
	require.Equal(t, "lab-bridge", mgmt.GetShortName())

	unlock()
	released = true
	select {
	case err := <-observed:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("constructor remained blocked after the operation completed")
	}
}

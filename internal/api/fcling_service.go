package api

import (
	"context"
	"sync"
	"time"

	"github.com/charmbracelet/log"

	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/fcling"
)

// fclingCleanupTimeout bounds what a lab operation waits for its lab's engine to go.
const fclingCleanupTimeout = time.Minute

var (
	fclingManager   *fcling.Manager
	fclingManagerMu sync.RWMutex
)

// InitFclingManager starts the fcling manager. A lab runtime has no container runtime to run
// engines with, so there is none then.
func InitFclingManager() {
	fclingManagerMu.Lock()
	defer fclingManagerMu.Unlock()

	if fclingManager != nil || clab.IsLabRuntime() {
		return
	}
	fclingManager = fcling.NewManager(config.FclingConfig())
}

// ShutdownFclingManager stops the manager. The labs' engines keep running.
func ShutdownFclingManager() {
	fclingManagerMu.Lock()
	manager := fclingManager
	fclingManager = nil
	fclingManagerMu.Unlock()

	if manager != nil {
		manager.Shutdown(context.Background())
	}
}

// GetFclingManager returns the manager, nil when there is none.
func GetFclingManager() *fcling.Manager {
	fclingManagerMu.RLock()
	defer fclingManagerMu.RUnlock()
	return fclingManager
}

// stopFclingEngine stops a lab's engine and keeps its history: before the lab goes, so that
// it does not hold on to the lab's management network, and whenever the lab's topology may
// change, since fcling reads it only at start. Never fails the operation it is part of.
func stopFclingEngine(labName string) {
	manager := GetFclingManager()
	if manager == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), fclingCleanupTimeout)
	defer cancel()
	if err := manager.Stop(ctx, labName); err != nil {
		log.Warnf("Failed stopping the fcling engine of lab '%s': %v", labName, err)
	}
}

// removeFclingEngine removes what a destroyed lab's engine left, its history included. Never
// fails the operation it is part of.
func removeFclingEngine(labName string) {
	manager := GetFclingManager()
	if manager == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), fclingCleanupTimeout)
	defer cancel()
	if err := manager.Remove(ctx, labName); err != nil {
		log.Warnf("Failed removing the fcling engine of lab '%s': %v", labName, err)
	}
}

package fcling

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/charmbracelet/log"
)

const (
	// DefaultGnmiPort is where fcling looks for its nodes unless told otherwise.
	DefaultGnmiPort = 57400
	// DefaultStateDir is where the port chosen for each lab is kept (FCLING_STATE_DIR).
	DefaultStateDir = "/var/lib/clab-api-server/fcling"

	// GnmiPortLabel says which port an engine was started with.
	GnmiPortLabel = "clab-fcling-gnmi-port"

	gnmiPortFileSuffix = ".gnmi-port"
)

// ValidGnmiPort says whether a port can be given to fcling.
func ValidGnmiPort(port int) bool {
	return port >= 1 && port <= 65535
}

func parseGnmiPort(text string) int {
	port, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || !ValidGnmiPort(port) {
		return 0
	}
	return port
}

func (c Config) gnmiPortFile(labName string) string {
	return filepath.Join(c.StateDir, labName+gnmiPortFileSuffix)
}

// LabGnmiPort is the port of a lab's nodes: the one chosen for the lab, else the server's.
func (c Config) LabGnmiPort(labName string) int {
	c = c.normalized()
	content, err := os.ReadFile(c.gnmiPortFile(labName))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Warnf("fcling: failed reading the gNMI port of lab '%s': %v", labName, err)
		}
		return c.GnmiPort
	}
	if port := parseGnmiPort(string(content)); port != 0 {
		return port
	}
	return c.GnmiPort
}

// saveGnmiPort remembers a lab's port. It outlives the lab, which is usually deployed again
// behind the same management setup, and the engine: stopping one removes its container.
func (c Config) saveGnmiPort(labName string, port int) error {
	if err := os.MkdirAll(c.StateDir, 0o750); err != nil {
		return fmt.Errorf("failed saving the gNMI port of lab '%s': %w", labName, err)
	}
	if err := os.WriteFile(c.gnmiPortFile(labName), []byte(strconv.Itoa(port)+"\n"), 0o640); err != nil {
		return fmt.Errorf("failed saving the gNMI port of lab '%s': %w", labName, err)
	}
	return nil
}

// gnmiPortArgs is fcling's global option for a port. fcling's default needs none, which also
// leaves an image with a port of its own as it is.
func gnmiPortArgs(port int) []string {
	if port == 0 || port == DefaultGnmiPort {
		return nil
	}
	return []string{"-p", strconv.Itoa(port)}
}

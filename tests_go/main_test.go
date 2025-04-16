// tests_go/main_test.go
package tests_go

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/joho/godotenv" // go get github.com/joho/godotenv
)

// --- Configuration Struct ---

type TestConfig struct {
	APIURL                string
	SuperuserUser         string
	SuperuserPass         string
	APIUserUser           string
	APIUserPass           string
	UnauthUser            string
	UnauthPass            string
	RequestTimeout        time.Duration
	DeployTimeout         time.Duration
	CleanupTimeout        time.Duration
	StabilizePause        time.Duration
	CleanupPause          time.Duration
	LabNamePrefix         string
	SimpleTopologyContent string
}

var cfg TestConfig

// --- TestMain for Global Setup ---

func TestMain(m *testing.M) {
	// Find .env file relative to the test file location
	// Assumes .env is in the same directory as the Go test files
	envPath := ".env" // Adjust if your .env is elsewhere relative to tests_go
	err := godotenv.Load(envPath)
	if err != nil {
		fmt.Printf("Warning: Could not load .env file from %s: %v\n", envPath, err)
		// Continue execution, relying on environment variables or defaults
	}

	// Load configuration from environment variables
	cfg = TestConfig{
		APIURL:                getEnv("API_URL", "http://127.0.0.1:8080"),
		SuperuserUser:         getEnv("SUPERUSER_USER", "root"),
		SuperuserPass:         getEnv("SUPERUSER_PASS", "rootpassword"), // Provide defaults or fail if critical
		APIUserUser:           getEnv("APIUSER_USER", "test"),
		APIUserPass:           getEnv("APIUSER_PASS", "test"),
		UnauthUser:            getEnv("UNAUTH_USER", "test2"),
		UnauthPass:            getEnv("UNAUTH_PASS", "test2"),
		RequestTimeout:        getEnvDuration("PYTEST_TIMEOUT_REQUEST", 15*time.Second),
		DeployTimeout:         getEnvDuration("PYTEST_TIMEOUT_DEPLOY", 240*time.Second),
		CleanupTimeout:        getEnvDuration("PYTEST_TIMEOUT_CLEANUP", 180*time.Second),
		StabilizePause:        getEnvDuration("PYTEST_STABILIZE_PAUSE", 10*time.Second),
		CleanupPause:          getEnvDuration("PYTEST_CLEANUP_PAUSE", 3*time.Second), // Use PYTEST_CLEANUP_PAUSE
		LabNamePrefix:         getEnv("PYTEST_LAB_NAME_PREFIX", "gotest"),
		SimpleTopologyContent: getEnvOrDie("PYTEST_SIMPLE_TOPOLOGY_CONTENT"), // Make topology mandatory
	}

	// Validate topology content placeholder
	if !strings.Contains(cfg.SimpleTopologyContent, "{lab_name}") {
		fmt.Println("Error: PYTEST_SIMPLE_TOPOLOGY_CONTENT must contain '{lab_name}' placeholder.")
		os.Exit(1)
	}

	// Seed random number generator for unique names
	rand.Seed(time.Now().UnixNano())

	// Run tests
	exitCode := m.Run()
	os.Exit(exitCode)
}

// --- Helper Functions ---

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	fmt.Printf("Warning: Environment variable %s not set, using default: %s\n", key, fallback)
	return fallback
}

func getEnvOrDie(key string) string {
	value, exists := os.LookupEnv(key)
	if !exists || value == "" {
		fmt.Printf("Error: Required environment variable %s is not set or is empty.\n", key)
		os.Exit(1) // Fail fast if required env var is missing
	}
	return value
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return fallback
	}
	valueInt, err := time.ParseDuration(valueStr + "s") // Assume value is in seconds
	if err != nil {
		fmt.Printf("Warning: Invalid duration format for %s ('%s'). Using default: %v. Error: %v\n", key, valueStr, fallback, err)
		return fallback
	}
	return valueInt
}

func randomSuffix(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// login performs API login and returns the token or fails the test.
func login(t *testing.T, username, password string) string {
	t.Helper() // Marks this as a test helper
	loginURL := fmt.Sprintf("%s/login", cfg.APIURL)
	payload := map[string]string{
		"username": username,
		"password": password,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal login payload: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", loginURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		t.Fatalf("Failed to create login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to execute login request: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body) // Read body for potential error messages

	if resp.StatusCode != http.StatusOK {
		// Allow 401 for specific auth tests, fail otherwise
		if resp.StatusCode == http.StatusUnauthorized && (strings.Contains(t.Name(), "InvalidLogin") || strings.Contains(t.Name(), "UnauthorizedUser")) {
			// This is expected in these specific tests, return empty token
			return ""
		}
		t.Fatalf("Login failed for user '%s'. Status: %d, Body: %s", username, resp.StatusCode, string(bodyBytes))
	}

	var loginResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(bodyBytes, &loginResp); err != nil {
		t.Fatalf("Failed to unmarshal login response: %v. Body: %s", err, string(bodyBytes))
	}

	if loginResp.Token == "" {
		t.Fatalf("Login successful but token is empty for user '%s'", username)
	}

	return loginResp.Token
}

// getAuthHeaders creates standard authorization headers.
func getAuthHeaders(token string) http.Header {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)
	headers.Set("Content-Type", "application/json") // Default content type
	return headers
}

// --- Lab Lifecycle Helpers ---

type labInfo struct {
	Name string
	// Add other relevant info if needed later
}

// createLab sends a request to deploy a lab.
func createLab(t *testing.T, headers http.Header, labName, topologyContent string, reconfigure bool, timeout time.Duration) error {
	t.Helper()
	deployURL := fmt.Sprintf("%s/api/v1/labs", cfg.APIURL)
	payload := map[string]string{
		"topologyContent": topologyContent,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal deploy payload: %w", err)
	}

	reqURL, _ := url.Parse(deployURL)
	query := reqURL.Query()
	if reconfigure {
		query.Set("reconfigure", "true")
	}
	reqURL.RawQuery = query.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", reqURL.String(), bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create deploy request: %w", err)
	}
	req.Header = headers // Use provided headers

	t.Logf("Attempting to create/reconfigure lab '%s'...", labName)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute deploy request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		// Allow 409 Conflict for specific tests, return specific error
		if resp.StatusCode == http.StatusConflict && strings.Contains(t.Name(), "Duplicate") {
			return fmt.Errorf("conflict: %w", os.ErrExist) // Use a standard error for conflict
		}
		// Allow 403 Forbidden for specific tests
		if resp.StatusCode == http.StatusForbidden && strings.Contains(t.Name(), "NonOwner") {
			return fmt.Errorf("forbidden: %w", os.ErrPermission) // Use standard error for permission issue
		}
		return fmt.Errorf("deploy failed. Status: %d, Body: %s", resp.StatusCode, string(bodyBytes))
	}

	t.Logf("Lab '%s' created/reconfigured successfully.", labName)
	return nil
}

// destroyLab sends a request to destroy a lab.
func destroyLab(t *testing.T, headers http.Header, labName string, cleanup bool, timeout time.Duration) error {
	t.Helper()
	destroyURL := fmt.Sprintf("%s/api/v1/labs/%s", cfg.APIURL, labName)
	reqURL, _ := url.Parse(destroyURL)
	query := reqURL.Query()
	if cleanup {
		query.Set("cleanup", "true")
	}
	reqURL.RawQuery = query.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "DELETE", reqURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create destroy request: %w", err)
	}
	req.Header = headers

	t.Logf("Attempting to destroy lab '%s' (cleanup=%t)...", labName, cleanup)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// Don't fail teardown catastrophically, just log warning
		t.Logf("Warning: Failed to execute destroy request for lab '%s': %v", labName, err)
		return fmt.Errorf("failed to execute destroy request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	// Log warnings for non-200 or 404 during cleanup
	if resp.StatusCode == http.StatusNotFound {
		t.Logf("Warning: Lab '%s' not found during cleanup (Status %d).", labName, resp.StatusCode)
		return nil // Not found is okay during cleanup
	} else if resp.StatusCode != http.StatusOK {
		t.Logf("Warning: Failed cleanup for lab '%s'. Status: %d, Body: %s", labName, resp.StatusCode, string(bodyBytes))
		return fmt.Errorf("destroy failed. Status: %d", resp.StatusCode)
	}

	t.Logf("Lab '%s' destroyed successfully.", labName)
	return nil
}

// setupEphemeralLab creates a lab as apiuser and registers cleanup using superuser.
func setupEphemeralLab(t *testing.T) (labName string, userHeaders http.Header) {
	t.Helper()

	// Get tokens and headers
	apiUserToken := login(t, cfg.APIUserUser, cfg.APIUserPass)
	superuserToken := login(t, cfg.SuperuserUser, cfg.SuperuserPass)
	userHeaders = getAuthHeaders(apiUserToken)
	superuserHeaders := getAuthHeaders(superuserToken)

	// Generate unique lab name
	labName = fmt.Sprintf("%s-eph-%s", cfg.LabNamePrefix, randomSuffix(5))
	topology := strings.ReplaceAll(cfg.SimpleTopologyContent, "{lab_name}", labName)

	// Create lab as apiuser
	t.Logf("---> [SETUP] Creating ephemeral lab: %s (as %s)", labName, cfg.APIUserUser)
	err := createLab(t, userHeaders, labName, topology, false, cfg.DeployTimeout)
	if err != nil {
		t.Fatalf("SETUP Failed: Could not create ephemeral lab '%s': %v", labName, err)
	}
	t.Logf("  `-> [SETUP] Lab '%s' created successfully.", labName)

	// Register cleanup function to run when the test finishes
	t.Cleanup(func() {
		t.Logf("<--- [TEARDOWN] Cleaning up ephemeral lab: %s (as %s)", labName, cfg.SuperuserUser)
		err := destroyLab(t, superuserHeaders, labName, true, cfg.CleanupTimeout) // Use superuser for cleanup
		if err != nil {
			t.Logf("  `-> [TEARDOWN] Warning: Error during cleanup for lab '%s': %v", labName, err)
		} else {
			t.Logf("  `-> [TEARDOWN] Lab '%s' cleanup successful or lab not found.", labName)
		}
		t.Logf("  `-> [TEARDOWN] Pausing for %v after cleanup...", cfg.CleanupPause)
		time.Sleep(cfg.CleanupPause)
	})

	t.Logf("  `-> [SETUP] Pausing for %v after lab creation...", cfg.StabilizePause)
	time.Sleep(cfg.StabilizePause)

	return labName, userHeaders // Return lab name and the user's headers for use in the test
}

// setupSuperuserLab creates a lab as superuser and registers cleanup (also as superuser).
func setupSuperuserLab(t *testing.T) (labName string, superuserHeaders http.Header) {
	t.Helper()

	// Get token and headers
	superuserToken := login(t, cfg.SuperuserUser, cfg.SuperuserPass)
	superuserHeaders = getAuthHeaders(superuserToken)

	// Generate unique lab name
	labName = fmt.Sprintf("%s-su-eph-%s", cfg.LabNamePrefix, randomSuffix(5))
	topology := strings.ReplaceAll(cfg.SimpleTopologyContent, "{lab_name}", labName)

	// Create lab as superuser
	t.Logf("---> [SETUP-SU] Creating superuser ephemeral lab: %s", labName)
	err := createLab(t, superuserHeaders, labName, topology, false, cfg.DeployTimeout)
	if err != nil {
		t.Fatalf("SETUP-SU Failed: Could not create superuser lab '%s': %v", labName, err)
	}
	t.Logf("  `-> [SETUP-SU] Lab '%s' created successfully.", labName)

	// Register cleanup function
	t.Cleanup(func() {
		t.Logf("<--- [TEARDOWN-SU] Cleaning up superuser ephemeral lab: %s", labName)
		err := destroyLab(t, superuserHeaders, labName, true, cfg.CleanupTimeout) // Use superuser for cleanup
		if err != nil {
			t.Logf("  `-> [TEARDOWN-SU] Warning: Error during cleanup for lab '%s': %v", labName, err)
		} else {
			t.Logf("  `-> [TEARDOWN-SU] Lab '%s' cleanup successful or lab not found.", labName)
		}
		t.Logf("  `-> [TEARDOWN-SU] Pausing for %v after cleanup...", cfg.CleanupPause)
		time.Sleep(cfg.CleanupPause)
	})

	t.Logf("  `-> [SETUP-SU] Pausing for %v after lab creation...", cfg.StabilizePause)
	time.Sleep(cfg.StabilizePause)

	return labName, superuserHeaders
}

// --- Generic HTTP Request Helper ---

// doRequest performs an HTTP request and handles common error checking/logging.
// Returns the response body bytes and status code on success, or error.
func doRequest(t *testing.T, method, urlStr string, headers http.Header, body io.Reader, timeout time.Duration) ([]byte, int, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Track if this is a JSON request by checking Content-Type header
	isJSON := false
	if headers.Get("Content-Type") == "application/json" {
		isJSON = true
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request (%s %s): %w", method, urlStr, err)
	}
	req.Header = headers

	// Log request details
	t.Logf("==> REQUEST: %s %s", method, urlStr)
	t.Logf("    Headers: %v", formatHeaders(headers))

	// Log request body if it exists and can be read
	if body != nil {
		if bodyReader, ok := body.(io.ReadSeeker); ok {
			// If body can be read multiple times, log it
			bodyContent, readErr := io.ReadAll(bodyReader)
			if readErr == nil {
				// Reset the reader position for the actual request
				bodyReader.Seek(0, io.SeekStart)
				if isJSON {
					t.Logf("    Body (JSON): %s", prettyJSON(bodyContent))
				} else {
					t.Logf("    Body: %s", string(bodyContent))
				}
			}
		}
	}

	// Execute request
	startTime := time.Now()
	resp, err := http.DefaultClient.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		t.Logf("==> ERROR: Request failed after %v: %v", duration, err)
		return nil, 0, fmt.Errorf("failed to execute request (%s %s): %w", method, urlStr, err)
	}
	defer resp.Body.Close()

	// Read response body
	respBodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		t.Logf("==> WARNING: Failed to read response body: %v", readErr)
	}

	// Log response details
	t.Logf("<== RESPONSE: %d %s (%v)", resp.StatusCode, resp.Status, duration)
	t.Logf("    Headers: %v", formatHeaders(resp.Header))

	// Format response body based on content type
	if len(respBodyBytes) > 0 {
		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "application/json") {
			t.Logf("    Body (JSON): %s", prettyJSON(respBodyBytes))
		} else if len(respBodyBytes) < 2000 {
			t.Logf("    Body: %s", string(respBodyBytes))
		} else {
			t.Logf("    Body: (truncated) %s...", string(respBodyBytes[:2000]))
		}
	} else {
		t.Logf("    Body: (empty)")
	}

	return respBodyBytes, resp.StatusCode, readErr
}

// formatHeaders returns a formatted string representation of headers
func formatHeaders(headers http.Header) string {
	if len(headers) == 0 {
		return "(none)"
	}

	var parts []string
	for name, values := range headers {
		if name == "Authorization" {
			// Mask authorization token for security
			parts = append(parts, fmt.Sprintf("%s: Bearer ***", name))
		} else {
			parts = append(parts, fmt.Sprintf("%s: %s", name, strings.Join(values, ", ")))
		}
	}
	return strings.Join(parts, ", ")
}

// prettyJSON formats JSON for readability
func prettyJSON(data []byte) string {
	var out bytes.Buffer
	err := json.Indent(&out, data, "        ", "  ")
	if err != nil {
		// If indentation fails, return the original string
		return string(data)
	}
	return out.String()
}

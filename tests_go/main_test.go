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
	"regexp" // Import regexp
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

	// Use doRequest for consistent logging and execution
	bodyBytes, statusCode, err := doRequest(t, "POST", loginURL, getAuthHeaders(""), bytes.NewBuffer(jsonPayload), cfg.RequestTimeout)
	if err != nil {
		t.Fatalf("Login request execution failed: %v", err)
	}

	if statusCode != http.StatusOK {
		// Allow 401 for specific auth tests, fail otherwise
		if statusCode == http.StatusUnauthorized && (strings.Contains(t.Name(), "InvalidLogin") || strings.Contains(t.Name(), "UnauthorizedUser")) {
			// This is expected in these specific tests, return empty token
			return ""
		}
		t.Fatalf("Login failed for user '%s'. Status: %d, Body: %s", username, statusCode, string(bodyBytes))
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
	if token != "" { // Only add auth header if token is provided
		headers.Set("Authorization", "Bearer "+token)
	}
	headers.Set("Content-Type", "application/json") // Default content type
	return headers
}

// --- Lab Lifecycle Helpers ---

type labInfo struct {
	Name string
	// Add other relevant info if needed later
}

// createLab sends a request to deploy a lab.
// Returns response body, status code, and transport error.
func createLab(t *testing.T, headers http.Header, labName, topologyContent string, reconfigure bool, timeout time.Duration) ([]byte, int, error) {
	t.Helper()
	deployURL := fmt.Sprintf("%s/api/v1/labs", cfg.APIURL)
	payload := map[string]string{
		"topologyContent": topologyContent,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal deploy payload: %w", err)
	}

	reqURL, _ := url.Parse(deployURL)
	query := reqURL.Query()
	if reconfigure {
		query.Set("reconfigure", "true")
	}
	reqURL.RawQuery = query.Encode()

	t.Logf("Attempting to create/reconfigure lab '%s'...", labName)
	// Use doRequest for execution and logging
	bodyBytes, statusCode, err := doRequest(t, "POST", reqURL.String(), headers, bytes.NewBuffer(jsonPayload), timeout)

	if err != nil {
		// Transport level error occurred
		return bodyBytes, statusCode, fmt.Errorf("deploy request execution failed: %w", err)
	}

	// Log success/failure based on status code, but let the test handle assertion
	if statusCode == http.StatusOK {
		t.Logf("Lab '%s' create/reconfigure request returned Status OK (200).", labName)
	} else {
		t.Logf("Lab '%s' create/reconfigure request returned Status %d.", labName, statusCode)
	}

	return bodyBytes, statusCode, nil // Return results for the test to check
}

// destroyLab sends a request to destroy a lab.
// Returns response body, status code, and transport error.
func destroyLab(t *testing.T, headers http.Header, labName string, cleanup bool, timeout time.Duration) ([]byte, int, error) {
	t.Helper()
	destroyURL := fmt.Sprintf("%s/api/v1/labs/%s", cfg.APIURL, labName)
	reqURL, _ := url.Parse(destroyURL)
	query := reqURL.Query()
	if cleanup {
		query.Set("cleanup", "true")
	}
	reqURL.RawQuery = query.Encode()

	t.Logf("Attempting to destroy lab '%s' (cleanup=%t)...", labName, cleanup)
	// Use doRequest for execution and logging
	bodyBytes, statusCode, err := doRequest(t, "DELETE", reqURL.String(), headers, nil, timeout)

	if err != nil {
		// Don't fail teardown catastrophically, just log warning
		t.Logf("Warning: Failed to execute destroy request for lab '%s': %v", labName, err)
		return bodyBytes, statusCode, fmt.Errorf("destroy request execution failed: %w", err)
	}

	// Log warnings for non-200 or 404 during cleanup
	if statusCode == http.StatusNotFound {
		t.Logf("Lab '%s' not found during cleanup (Status 404).", labName)
		// Not an error in cleanup context
	} else if statusCode != http.StatusOK {
		t.Logf("Warning: Non-OK status during cleanup for lab '%s'. Status: %d", labName, statusCode)
		// Not necessarily a fatal error for cleanup, but good to know
	} else {
		t.Logf("Lab '%s' destroy request returned Status OK (200).", labName)
	}

	return bodyBytes, statusCode, nil // Return results
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
	bodyBytes, statusCode, err := createLab(t, userHeaders, labName, topology, false, cfg.DeployTimeout)
	if err != nil {
		t.Fatalf("SETUP Failed: Could not execute create ephemeral lab request for '%s': %v", labName, err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("SETUP Failed: Could not create ephemeral lab '%s'. Status: %d, Body: %s", labName, statusCode, string(bodyBytes))
	}
	t.Logf("  `-> [SETUP] Lab '%s' created successfully.", labName)

	// Register cleanup function to run when the test finishes
	t.Cleanup(func() {
		t.Logf("<--- [TEARDOWN] Cleaning up ephemeral lab: %s (as %s)", labName, cfg.SuperuserUser)
		_, _, err := destroyLab(t, superuserHeaders, labName, true, cfg.CleanupTimeout) // Use superuser for cleanup
		if err != nil {
			// Error is already logged in destroyLab, just add context
			t.Logf("  `-> [TEARDOWN] Note: Error occurred during destroy execution for lab '%s'.", labName)
		} else {
			t.Logf("  `-> [TEARDOWN] Lab '%s' destroy request completed.", labName)
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
	bodyBytes, statusCode, err := createLab(t, superuserHeaders, labName, topology, false, cfg.DeployTimeout)
	if err != nil {
		t.Fatalf("SETUP-SU Failed: Could not execute create superuser lab request for '%s': %v", labName, err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("SETUP-SU Failed: Could not create superuser lab '%s'. Status: %d, Body: %s", labName, statusCode, string(bodyBytes))
	}
	t.Logf("  `-> [SETUP-SU] Lab '%s' created successfully.", labName)

	// Register cleanup function
	t.Cleanup(func() {
		t.Logf("<--- [TEARDOWN-SU] Cleaning up superuser ephemeral lab: %s", labName)
		_, _, err := destroyLab(t, superuserHeaders, labName, true, cfg.CleanupTimeout) // Use superuser for cleanup
		if err != nil {
			t.Logf("  `-> [TEARDOWN-SU] Note: Error occurred during destroy execution for lab '%s'.", labName)
		} else {
			t.Logf("  `-> [TEARDOWN-SU] Lab '%s' destroy request completed.", labName)
		}
		t.Logf("  `-> [TEARDOWN-SU] Pausing for %v after cleanup...", cfg.CleanupPause)
		time.Sleep(cfg.CleanupPause)
	})

	t.Logf("  `-> [SETUP-SU] Pausing for %v after lab creation...", cfg.StabilizePause)
	time.Sleep(cfg.StabilizePause)

	return labName, superuserHeaders
}

// --- Generic HTTP Request Helper ---

var authRegex = regexp.MustCompile(`(?i)(Authorization: Bearer) \S+`)

// logHeaders formats and logs HTTP headers, masking Authorization.
func logHeaders(t *testing.T, prefix string, headers http.Header) {
	t.Helper()
	if headers == nil || len(headers) == 0 {
		t.Logf("%s Headers: (none)", prefix)
		return
	}
	t.Logf("%s Headers:", prefix)
	for key, values := range headers {
		headerLine := fmt.Sprintf("%s: %s", key, strings.Join(values, ", "))
		// Mask Authorization token
		maskedLine := authRegex.ReplaceAllString(headerLine, "$1 ********")
		t.Logf("  %s", maskedLine)
	}
}

// logBody logs the body, truncating if necessary.
func logBody(t *testing.T, prefix string, bodyBytes []byte) {
	t.Helper()
	if len(bodyBytes) == 0 {
		t.Logf("%s Body: (empty)", prefix)
		return
	}
	const maxLogLen = 1024 // Max characters to log
	if len(bodyBytes) <= maxLogLen {
		t.Logf("%s Body:\n---\n%s\n---", prefix, string(bodyBytes))
	} else {
		t.Logf("%s Body: (truncated to %d bytes)\n---\n%s\n...[truncated]...", prefix, maxLogLen, string(bodyBytes[:maxLogLen]))
	}
}

// doRequest performs an HTTP request and handles common error checking/logging.
// Returns the response body bytes and status code on success, or error.
func doRequest(t *testing.T, method, urlStr string, headers http.Header, reqBodyReader io.Reader, timeout time.Duration) ([]byte, int, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// --- Log Request ---
	t.Logf(">>> Request Start: %s %s", method, urlStr)
	logHeaders(t, ">>> Request", headers)

	// Read request body for logging IF it exists
	var reqBodyBytes []byte
	var actualReqBodyReader io.Reader // The reader to use for the actual request
	if reqBodyReader != nil {
		var err error
		reqBodyBytes, err = io.ReadAll(reqBodyReader)
		if err != nil {
			t.Logf(">>> Warning: Failed to read request body for logging: %v", err)
			// Attempt to proceed with the original reader if read failed? Or fail?
			// Let's proceed with a nil body for the actual request if logging read failed.
			actualReqBodyReader = nil // Can't reuse original reader after partial read
		} else {
			actualReqBodyReader = bytes.NewReader(reqBodyBytes) // Use the read bytes for the actual request
		}
		logBody(t, ">>> Request", reqBodyBytes)
	} else {
		logBody(t, ">>> Request", nil) // Log empty body
		actualReqBodyReader = nil
	}

	req, err := http.NewRequestWithContext(ctx, method, urlStr, actualReqBodyReader)
	if err != nil {
		t.Logf(">>> Request Error: Failed to create request object: %v", err)
		return nil, 0, fmt.Errorf("failed to create request (%s %s): %w", method, urlStr, err)
	}
	req.Header = headers // Assign headers *after* creating request

	// --- Execute Request ---
	startTime := time.Now()
	resp, err := http.DefaultClient.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		t.Logf("<<< Response Error: Failed to execute request (%s %s) after %v: %v", method, urlStr, duration, err)
		return nil, 0, fmt.Errorf("failed to execute request (%s %s): %w", method, urlStr, err)
	}
	defer resp.Body.Close()

	// --- Log Response ---
	t.Logf("<<< Response Received: Status %d (%s) from %s %s in %v", resp.StatusCode, http.StatusText(resp.StatusCode), method, urlStr, duration)
	logHeaders(t, "<<< Response", resp.Header)

	respBodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		t.Logf("<<< Warning: Failed to read response body (%s %s): %v", method, urlStr, readErr)
		// Continue with the bytes read so far
	}
	logBody(t, "<<< Response", respBodyBytes)
	t.Logf("<<< Response End: %s %s", method, urlStr)

	// Return the body, status, and the potential *body read* error (transport error is handled above)
	return respBodyBytes, resp.StatusCode, readErr
}

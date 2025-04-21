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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/joho/godotenv"
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
	LogLevel              string // Added log level configuration
	rng                   *rand.Rand
}

// LogLevel constants
const (
	LogLevelDebug = "debug" // Full HTTP request/response details
	LogLevelInfo  = "info"  // Standard test information
	LogLevelError = "error" // Only errors
)

var cfg TestConfig

// --- TestMain for Global Setup ---

func TestMain(m *testing.M) {
	// Find .env file relative to the test file location
	envPath := ".env" // Adjust if your .env is elsewhere relative to tests_go
	err := godotenv.Load(envPath)
	if err != nil {
		fmt.Printf("Warning: Could not load .env file from %s: %v\n", envPath, err)
	}

	// Initialize the random number generator
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	cfg = TestConfig{
		APIURL:                getEnv("API_URL", "http://127.0.0.1:8080"),
		SuperuserUser:         getEnv("SUPERUSER_USER", "root"),
		SuperuserPass:         getEnv("SUPERUSER_PASS", "rootpassword"),
		APIUserUser:           getEnv("APIUSER_USER", "test"),
		APIUserPass:           getEnv("APIUSER_PASS", "test"),
		UnauthUser:            getEnv("UNAUTH_USER", "test2"),
		UnauthPass:            getEnv("UNAUTH_PASS", "test2"),
		RequestTimeout:        getEnvDuration("GOTEST_TIMEOUT_REQUEST", 15*time.Second),
		DeployTimeout:         getEnvDuration("GOTEST_TIMEOUT_DEPLOY", 240*time.Second),
		CleanupTimeout:        getEnvDuration("GOTEST_TIMEOUT_CLEANUP", 180*time.Second),
		StabilizePause:        getEnvDuration("GOTEST_STABILIZE_PAUSE", 10*time.Second),
		CleanupPause:          getEnvDuration("GOTEST_CLEANUP_PAUSE", 3*time.Second),
		LabNamePrefix:         getEnv("GOTEST_LAB_NAME_PREFIX", "gotest"),
		SimpleTopologyContent: getEnvOrDie("GOTEST_SIMPLE_TOPOLOGY_CONTENT"),
		LogLevel:              getEnv("GOTEST_LOG_LEVEL", LogLevelInfo),
		rng:                   rng,
	}

	if !strings.Contains(cfg.SimpleTopologyContent, "{lab_name}") {
		fmt.Println("Error: GOTEST_SIMPLE_TOPOLOGY_CONTENT must contain '{lab_name}' placeholder.")
		os.Exit(1)
	}

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
		os.Exit(1)
	}
	return value
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return fallback
	}
	valueInt, err := time.ParseDuration(valueStr + "s")
	if err != nil {
		fmt.Printf("Warning: Invalid duration format for %s ('%s'). Using default: %v. Error: %v\n", key, valueStr, fallback, err)
		return fallback
	}
	return valueInt
}

// Updated to use the provided random source
func randomSuffix(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[cfg.rng.Intn(len(letters))]
	}
	return string(b)
}

// --- Improved Logging Functions ---

func logDebug(t *testing.T, format string, args ...interface{}) {
	if cfg.LogLevel == LogLevelDebug {
		t.Logf("🔍 DEBUG: "+format, args...)
	}
}

func logInfo(t *testing.T, format string, args ...interface{}) {
	if cfg.LogLevel == LogLevelDebug || cfg.LogLevel == LogLevelInfo {
		t.Logf("ℹ️ "+format, args...)
	}
}

func logSuccess(t *testing.T, format string, args ...interface{}) {
	if cfg.LogLevel == LogLevelDebug || cfg.LogLevel == LogLevelInfo {
		t.Logf("✅ "+format, args...)
	}
}

func logWarning(t *testing.T, format string, args ...interface{}) {
	if cfg.LogLevel == LogLevelDebug || cfg.LogLevel == LogLevelInfo || cfg.LogLevel == LogLevelError {
		t.Logf("⚠️ "+format, args...)
	}
}

func logError(t *testing.T, format string, args ...interface{}) {
	if cfg.LogLevel == LogLevelDebug || cfg.LogLevel == LogLevelInfo || cfg.LogLevel == LogLevelError {
		t.Logf("❌ ERROR: "+format, args...)
	}
}

func logSetup(t *testing.T, format string, args ...interface{}) {
	if cfg.LogLevel == LogLevelDebug || cfg.LogLevel == LogLevelInfo {
		t.Logf("🔧 SETUP: "+format, args...)
	}
}

func logTeardown(t *testing.T, format string, args ...interface{}) {
	if cfg.LogLevel == LogLevelDebug || cfg.LogLevel == LogLevelInfo {
		t.Logf("🧹 TEARDOWN: "+format, args...)
	}
}

func logTest(t *testing.T, format string, args ...interface{}) {
	if cfg.LogLevel == LogLevelDebug || cfg.LogLevel == LogLevelInfo {
		t.Logf("🧪 TEST: "+format, args...)
	}
}

func login(t *testing.T, username, password string) string {
	t.Helper()
	loginURL := fmt.Sprintf("%s/login", cfg.APIURL)
	payload := map[string]string{
		"username": username,
		"password": password,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal login payload: %v", err)
	}

	logDebug(t, "Logging in as '%s'", username)
	bodyBytes, statusCode, err := doRequest(t, "POST", loginURL, getAuthHeaders(""), bytes.NewBuffer(jsonPayload), cfg.RequestTimeout)
	if err != nil {
		logError(t, "Login request execution failed: %v", err)
		t.Fatalf("Login request execution failed: %v", err)
	}

	if statusCode != http.StatusOK {
		if statusCode == http.StatusUnauthorized && (strings.Contains(t.Name(), "InvalidLogin") || strings.Contains(t.Name(), "UnauthorizedUser")) {
			logInfo(t, "Expected unauthorized status received (401) for '%s'", username)
			return ""
		}
		logError(t, "Login failed for user '%s'. Status: %d", username, statusCode)
		t.Fatalf("Login failed for user '%s'. Status: %d, Body: %s", username, statusCode, string(bodyBytes))
	}

	var loginResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(bodyBytes, &loginResp); err != nil {
		logError(t, "Failed to unmarshal login response: %v", err)
		t.Fatalf("Failed to unmarshal login response: %v. Body: %s", err, string(bodyBytes))
	}

	if loginResp.Token == "" {
		logError(t, "Login successful but token is empty for user '%s'", username)
		t.Fatalf("Login successful but token is empty for user '%s'", username)
	}

	logSuccess(t, "User '%s' logged in successfully", username)
	return loginResp.Token
}

func getAuthHeaders(token string) http.Header {
	headers := http.Header{}
	if token != "" {
		headers.Set("Authorization", "Bearer "+token)
	}
	headers.Set("Content-Type", "application/json")
	return headers
}

// --- Lab Lifecycle Helpers ---

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

	logInfo(t, "Creating%s lab '%s'...",
		func() string {
			if reconfigure {
				return "/reconfiguring"
			}
			return ""
		}(), labName)

	bodyBytes, statusCode, err := doRequest(t, "POST", reqURL.String(), headers, bytes.NewBuffer(jsonPayload), timeout)

	if err != nil {
		logError(t, "Failed to execute lab creation request: %v", err)
		return bodyBytes, statusCode, fmt.Errorf("deploy request execution failed: %w", err)
	}

	if statusCode == http.StatusOK {
		logSuccess(t, "Lab '%s' create/reconfigure returned Status OK (200)", labName)
	} else {
		logInfo(t, "Lab '%s' create/reconfigure returned Status %d", labName, statusCode)
	}

	return bodyBytes, statusCode, nil
}

func destroyLab(t *testing.T, headers http.Header, labName string, cleanup bool, timeout time.Duration) ([]byte, int, error) {
	t.Helper()
	destroyURL := fmt.Sprintf("%s/api/v1/labs/%s", cfg.APIURL, labName)
	reqURL, _ := url.Parse(destroyURL)
	query := reqURL.Query()
	if cleanup {
		query.Set("cleanup", "true")
	}
	reqURL.RawQuery = query.Encode()

	logInfo(t, "Destroying lab '%s' (cleanup=%t)...", labName, cleanup)
	bodyBytes, statusCode, err := doRequest(t, "DELETE", reqURL.String(), headers, nil, timeout)

	if err != nil {
		logWarning(t, "Failed to execute destroy request for lab '%s': %v", labName, err)
		return bodyBytes, statusCode, fmt.Errorf("destroy request execution failed: %w", err)
	}

	if statusCode == http.StatusNotFound {
		logWarning(t, "Lab '%s' not found during cleanup (Status 404)", labName)
	} else if statusCode != http.StatusOK {
		logWarning(t, "Non-OK status during cleanup for lab '%s'. Status: %d", labName, statusCode)
	} else {
		logSuccess(t, "Lab '%s' destroyed successfully", labName)
	}

	return bodyBytes, statusCode, nil
}

func setupEphemeralLab(t *testing.T) (labName string, userHeaders http.Header) {
	t.Helper()
	apiUserToken := login(t, cfg.APIUserUser, cfg.APIUserPass)
	superuserToken := login(t, cfg.SuperuserUser, cfg.SuperuserPass)
	userHeaders = getAuthHeaders(apiUserToken)
	superuserHeaders := getAuthHeaders(superuserToken)

	labName = fmt.Sprintf("%s-eph-%s", cfg.LabNamePrefix, randomSuffix(5))
	topology := strings.ReplaceAll(cfg.SimpleTopologyContent, "{lab_name}", labName)

	logSetup(t, "Creating ephemeral lab: %s (as %s)", labName, cfg.APIUserUser)
	bodyBytes, statusCode, err := createLab(t, userHeaders, labName, topology, false, cfg.DeployTimeout)
	if err != nil {
		logError(t, "SETUP Failed: Could not execute create ephemeral lab request: %v", err)
		t.Fatalf("SETUP Failed: Could not execute create ephemeral lab request for '%s': %v", labName, err)
	}
	if statusCode != http.StatusOK {
		logError(t, "SETUP Failed: Could not create ephemeral lab. Status: %d", statusCode)
		t.Fatalf("SETUP Failed: Could not create ephemeral lab '%s'. Status: %d, Body: %s", labName, statusCode, string(bodyBytes))
	}
	logSuccess(t, "Lab '%s' created successfully", labName)

	t.Cleanup(func() {
		logTeardown(t, "Cleaning up ephemeral lab: %s (as %s)", labName, cfg.SuperuserUser)
		_, _, err := destroyLab(t, superuserHeaders, labName, true, cfg.CleanupTimeout)
		if err != nil {
			logWarning(t, "Error occurred during destroy execution for lab '%s'", labName)
		} else {
			logSuccess(t, "Lab '%s' cleanup completed", labName)
		}
		logDebug(t, "Pausing for %v after cleanup...", cfg.CleanupPause)
		time.Sleep(cfg.CleanupPause)
	})

	logDebug(t, "Pausing for %v after lab creation...", cfg.StabilizePause)
	time.Sleep(cfg.StabilizePause)

	return labName, userHeaders
}

func setupSuperuserLab(t *testing.T) (labName string, superuserHeaders http.Header) {
	t.Helper()
	superuserToken := login(t, cfg.SuperuserUser, cfg.SuperuserPass)
	superuserHeaders = getAuthHeaders(superuserToken)

	labName = fmt.Sprintf("%s-su-eph-%s", cfg.LabNamePrefix, randomSuffix(5))
	topology := strings.ReplaceAll(cfg.SimpleTopologyContent, "{lab_name}", labName)

	logSetup(t, "Creating superuser ephemeral lab: %s", labName)
	bodyBytes, statusCode, err := createLab(t, superuserHeaders, labName, topology, false, cfg.DeployTimeout)
	if err != nil {
		logError(t, "SETUP-SU Failed: Could not execute create superuser lab request: %v", err)
		t.Fatalf("SETUP-SU Failed: Could not execute create superuser lab request for '%s': %v", labName, err)
	}
	if statusCode != http.StatusOK {
		logError(t, "SETUP-SU Failed: Could not create superuser lab. Status: %d", statusCode)
		t.Fatalf("SETUP-SU Failed: Could not create superuser lab '%s'. Status: %d, Body: %s", labName, statusCode, string(bodyBytes))
	}
	logSuccess(t, "Superuser lab '%s' created successfully", labName)

	t.Cleanup(func() {
		logTeardown(t, "Cleaning up superuser ephemeral lab: %s", labName)
		_, _, err := destroyLab(t, superuserHeaders, labName, true, cfg.CleanupTimeout)
		if err != nil {
			logWarning(t, "Error occurred during destroy execution for lab '%s'", labName)
		} else {
			logSuccess(t, "Superuser lab '%s' cleanup completed", labName)
		}
		logDebug(t, "Pausing for %v after cleanup...", cfg.CleanupPause)
		time.Sleep(cfg.CleanupPause)
	})

	logDebug(t, "Pausing for %v after lab creation...", cfg.StabilizePause)
	time.Sleep(cfg.StabilizePause)

	return labName, superuserHeaders
}

// --- Generic HTTP Request Helper ---

var authRegex = regexp.MustCompile(`(?i)(Authorization: Bearer) \S+`)

func logHeaders(t *testing.T, prefix string, headers http.Header) {
	t.Helper()
	if cfg.LogLevel != LogLevelDebug {
		return
	}

	if len(headers) == 0 {
		logDebug(t, "%s Headers: (none)", prefix)
		return
	}

	logDebug(t, "%s Headers:", prefix)
	for key, values := range headers {
		headerLine := fmt.Sprintf("%s: %s", key, strings.Join(values, ", "))
		maskedLine := authRegex.ReplaceAllString(headerLine, "$1 ********")
		logDebug(t, "  %s", maskedLine)
	}
}

// logBody logs the body, masking password if JSON and truncating if necessary.
func logBody(t *testing.T, prefix string, bodyBytes []byte) {
	t.Helper()
	if cfg.LogLevel != LogLevelDebug {
		return
	}

	if len(bodyBytes) == 0 {
		logDebug(t, "%s Body: (empty)", prefix)
		return
	}

	maskedBody := bodyBytes // Start with original bytes

	// Attempt to mask password if content looks like JSON
	if bytes.HasPrefix(bodyBytes, []byte("{")) && bytes.HasSuffix(bodyBytes, []byte("}")) { // Basic JSON check
		var data map[string]interface{}
		// Use a temporary reader for unmarshaling to avoid consuming original bytes if needed elsewhere
		tempReader := bytes.NewReader(bodyBytes)
		decoder := json.NewDecoder(tempReader)
		if err := decoder.Decode(&data); err == nil {
			// Check for password field (case-insensitive)
			for k, v := range data {
				if strings.ToLower(k) == "password" {
					if _, ok := v.(string); ok { // Only mask if it's a string
						data[k] = "********" // Mask it
						break                // Assume only one password field
					}
				}
			}
			// Attempt to marshal back the modified data
			maskedBytes, marshalErr := json.MarshalIndent(data, "", "  ") // Use indent for readability
			if marshalErr == nil {
				maskedBody = maskedBytes // Use the masked version
			} else {
				logWarning(t, "%s Failed to re-marshal body after masking: %v", prefix, marshalErr)
				// Fall back to logging original (truncated) body below
				maskedBody = bodyBytes
			}
		} else {
			// Not valid JSON or decode error, log original (truncated) below
			maskedBody = bodyBytes
		}
	}

	// Log the (potentially masked) body, truncated if necessary
	const maxLogLen = 1024
	if len(maskedBody) <= maxLogLen {
		logDebug(t, "%s Body:\n---\n%s\n---", prefix, string(maskedBody))
	} else {
		logDebug(t, "%s Body: (truncated to %d bytes)\n---\n%s\n...[truncated]...", prefix, maxLogLen, string(maskedBody[:maxLogLen]))
	}
}

func doRequest(t *testing.T, method, urlStr string, headers http.Header, reqBodyReader io.Reader, timeout time.Duration) ([]byte, int, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	logDebug(t, "Request Start: %s %s", method, urlStr)
	logHeaders(t, "Request", headers)

	var reqBodyBytes []byte
	var actualReqBodyReader io.Reader
	if reqBodyReader != nil {
		var err error
		reqBodyBytes, err = io.ReadAll(reqBodyReader)
		if err != nil {
			logWarning(t, "Failed to read request body for logging: %v", err)
			actualReqBodyReader = nil
		} else {
			actualReqBodyReader = bytes.NewReader(reqBodyBytes)
		}
		// Pass the original bytes read for logging (masking happens inside logBody)
		logBody(t, "Request", reqBodyBytes)
	} else {
		logBody(t, "Request", nil)
		actualReqBodyReader = nil
	}

	req, err := http.NewRequestWithContext(ctx, method, urlStr, actualReqBodyReader)
	if err != nil {
		logError(t, "Failed to create request object: %v", err)
		return nil, 0, fmt.Errorf("failed to create request (%s %s): %w", method, urlStr, err)
	}
	req.Header = headers

	startTime := time.Now()
	resp, err := http.DefaultClient.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		logError(t, "Failed to execute request (%s %s) after %v: %v", method, urlStr, duration, err)
		return nil, 0, fmt.Errorf("failed to execute request (%s %s): %w", method, urlStr, err)
	}
	defer resp.Body.Close()

	logDebug(t, "Response Received: Status %d (%s) from %s %s in %v",
		resp.StatusCode, http.StatusText(resp.StatusCode), method, urlStr, duration)
	logHeaders(t, "Response", resp.Header)

	respBodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		logWarning(t, "Failed to read response body (%s %s): %v", method, urlStr, readErr)
	}
	// Pass response body bytes for logging (masking isn't typically needed for responses)
	logBody(t, "Response", respBodyBytes)
	logDebug(t, "Response End: %s %s", method, urlStr)

	return respBodyBytes, resp.StatusCode, readErr
}

// tests_go/suite_base_test.go
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
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
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

// Global config variable loaded in TestMain
var globalCfg TestConfig

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

	globalCfg = TestConfig{
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

	if !strings.Contains(globalCfg.SimpleTopologyContent, "{lab_name}") {
		fmt.Println("Error: GOTEST_SIMPLE_TOPOLOGY_CONTENT must contain '{lab_name}' placeholder.")
		os.Exit(1)
	}

	exitCode := m.Run()
	os.Exit(exitCode)
}

// --- Base Suite Definition ---

type BaseSuite struct {
	suite.Suite
	cfg TestConfig // Each suite instance gets a copy of the global config

	// Tokens can be stored here if needed across tests within a suite
	// e.g., apiUserToken string
	// e.g., superuserToken string
}

// SetupSuite runs once before the suite's tests run
func (s *BaseSuite) SetupSuite() {
	s.cfg = globalCfg // Assign the globally loaded config to the suite instance
	s.T().Log("BaseSuite SetupSuite completed.")
}

// TearDownSuite runs once after all tests in the suite finish
func (s *BaseSuite) TearDownSuite() {
	s.T().Log("BaseSuite TearDownSuite completed.")
}

// SetupTest runs before each test in the suite
func (s *BaseSuite) SetupTest() {
	// Common setup for *every* test can go here
	// s.T().Logf("SetupTest for %s", s.T().Name())
}

// TearDownTest runs after each test in the suite
func (s *BaseSuite) TearDownTest() {
	// Common teardown for *every* test can go here
	// s.T().Logf("TearDownTest for %s", s.T().Name())
}

// --- Helper Functions (now methods on BaseSuite) ---

// Updated to use the suite's random source
func (s *BaseSuite) randomSuffix(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[s.cfg.rng.Intn(len(letters))]
	}
	return string(b)
}

// --- Improved Logging Functions (now methods on BaseSuite) ---

func (s *BaseSuite) logDebug(format string, args ...interface{}) {
	if s.cfg.LogLevel == LogLevelDebug {
		s.T().Logf("🔍 DEBUG: "+format, args...)
	}
}

func (s *BaseSuite) logInfo(format string, args ...interface{}) {
	if s.cfg.LogLevel == LogLevelDebug || s.cfg.LogLevel == LogLevelInfo {
		s.T().Logf("ℹ️ "+format, args...)
	}
}

func (s *BaseSuite) logSuccess(format string, args ...interface{}) {
	if s.cfg.LogLevel == LogLevelDebug || s.cfg.LogLevel == LogLevelInfo {
		s.T().Logf("✅ "+format, args...)
	}
}

func (s *BaseSuite) logWarning(format string, args ...interface{}) {
	if s.cfg.LogLevel == LogLevelDebug || s.cfg.LogLevel == LogLevelInfo || s.cfg.LogLevel == LogLevelError {
		s.T().Logf("⚠️ "+format, args...)
	}
}

func (s *BaseSuite) logError(format string, args ...interface{}) {
	if s.cfg.LogLevel == LogLevelDebug || s.cfg.LogLevel == LogLevelInfo || s.cfg.LogLevel == LogLevelError {
		s.T().Logf("❌ ERROR: "+format, args...)
	}
}

func (s *BaseSuite) logSetup(format string, args ...interface{}) {
	if s.cfg.LogLevel == LogLevelDebug || s.cfg.LogLevel == LogLevelInfo {
		s.T().Logf("🔧 SETUP: "+format, args...)
	}
}

func (s *BaseSuite) logTeardown(format string, args ...interface{}) {
	if s.cfg.LogLevel == LogLevelDebug || s.cfg.LogLevel == LogLevelInfo {
		s.T().Logf("🧹 TEARDOWN: "+format, args...)
	}
}

func (s *BaseSuite) logTest(format string, args ...interface{}) {
	if s.cfg.LogLevel == LogLevelDebug || s.cfg.LogLevel == LogLevelInfo {
		s.T().Logf("🧪 TEST: "+format, args...)
	}
}

func (s *BaseSuite) login(username, password string) string {
	s.T().Helper()
	loginURL := fmt.Sprintf("%s/login", s.cfg.APIURL)
	payload := map[string]string{
		"username": username,
		"password": password,
	}
	jsonPayload, err := json.Marshal(payload)
	require.NoError(s.T(), err, "Failed to marshal login payload")

	s.logDebug("Logging in as '%s'", username)
	bodyBytes, statusCode, err := s.doRequest("POST", loginURL, s.getAuthHeaders(""), bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	require.NoError(s.T(), err, "Login request execution failed")

	// Special handling for expected failures in specific tests
	isAuthTestExpectingFailure := strings.Contains(s.T().Name(), "InvalidLogin") || strings.Contains(s.T().Name(), "UnauthorizedUser")

	if statusCode != http.StatusOK {
		if statusCode == http.StatusUnauthorized && isAuthTestExpectingFailure {
			s.logInfo("Expected unauthorized status received (401) for '%s'", username)
			return "" // Return empty token for expected failures
		}
		s.logError("Login failed for user '%s'. Status: %d", username, statusCode)
		require.FailNowf(s.T(), "Login failed", "User: %s, Status: %d, Body: %s", username, statusCode, string(bodyBytes))
	}

	require.Equal(s.T(), http.StatusOK, statusCode, "Login failed for user '%s'. Body: %s", username, string(bodyBytes))

	var loginResp struct {
		Token string `json:"token"`
	}
	err = json.Unmarshal(bodyBytes, &loginResp)
	require.NoError(s.T(), err, "Failed to unmarshal login response. Body: %s", string(bodyBytes))
	require.NotEmpty(s.T(), loginResp.Token, "Login successful but token is empty for user '%s'", username)

	s.logSuccess("User '%s' logged in successfully", username)
	return loginResp.Token
}

func (s *BaseSuite) getAuthHeaders(token string) http.Header {
	headers := http.Header{}
	if token != "" {
		headers.Set("Authorization", "Bearer "+token)
	}
	headers.Set("Content-Type", "application/json")
	return headers
}

// --- Lab Lifecycle Helpers (now methods on BaseSuite) ---

// createLab sends the request to create/reconfigure a lab.
// It returns the raw response body, status code, and any transport error.
// Assertions on the status code should be done by the caller.
func (s *BaseSuite) createLab(headers http.Header, labName, topologyContent string, reconfigure bool, timeout time.Duration) ([]byte, int, error) {
	s.T().Helper()
	deployURL := fmt.Sprintf("%s/api/v1/labs", s.cfg.APIURL)
	payload := map[string]string{
		"topologyContent": topologyContent,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal deploy payload: %w", err) // Return error for caller
	}

	reqURL, _ := url.Parse(deployURL)
	query := reqURL.Query()
	if reconfigure {
		query.Set("reconfigure", "true")
	}
	reqURL.RawQuery = query.Encode()

	action := "Creating"
	if reconfigure {
		action = "Reconfiguring"
	}
	s.logInfo("%s lab '%s'...", action, labName)

	bodyBytes, statusCode, err := s.doRequest("POST", reqURL.String(), headers, bytes.NewBuffer(jsonPayload), timeout)

	// Log outcome but return results for caller to assert
	if err != nil {
		s.logError("Failed to execute lab %s request: %v", strings.ToLower(action), err)
	} else if statusCode == http.StatusOK {
		s.logSuccess("Lab '%s' %s returned Status OK (200)", labName, strings.ToLower(action))
	} else {
		s.logInfo("Lab '%s' %s returned Status %d", labName, strings.ToLower(action), statusCode)
	}

	return bodyBytes, statusCode, err // Return results for caller
}

// destroyLab sends the request to destroy a lab.
// It logs warnings on errors but returns results for the caller (often cleanup).
func (s *BaseSuite) destroyLab(headers http.Header, labName string, cleanup bool, timeout time.Duration) ([]byte, int, error) {
	s.T().Helper()
	destroyURL := fmt.Sprintf("%s/api/v1/labs/%s", s.cfg.APIURL, labName)
	reqURL, _ := url.Parse(destroyURL)
	query := reqURL.Query()
	if cleanup {
		query.Set("cleanup", "true")
	}
	reqURL.RawQuery = query.Encode()

	s.logInfo("Destroying lab '%s' (cleanup=%t)...", labName, cleanup)
	bodyBytes, statusCode, err := s.doRequest("DELETE", reqURL.String(), headers, nil, timeout)

	if err != nil {
		s.logWarning("Failed to execute destroy request for lab '%s': %v", labName, err)
		// Return error but don't fail the test here, usually called in cleanup
	} else if statusCode == http.StatusNotFound {
		s.logWarning("Lab '%s' not found during cleanup (Status 404)", labName)
	} else if statusCode != http.StatusOK {
		s.logWarning("Non-OK status (%d) during cleanup for lab '%s'. Body: %s", statusCode, labName, string(bodyBytes))
	} else {
		s.logSuccess("Lab '%s' destroyed successfully", labName)
	}

	return bodyBytes, statusCode, err
}

// setupEphemeralLab creates a lab as the standard API user.
// It returns the lab name and auth headers for that user.
// IMPORTANT: It registers cleanup using defer within the *calling test method's scope*.
func (s *BaseSuite) setupEphemeralLab() (labName string, userHeaders http.Header) {
	s.T().Helper()
	apiUserToken := s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	userHeaders = s.getAuthHeaders(apiUserToken)

	labName = fmt.Sprintf("%s-eph-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	topology := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", labName)

	s.logSetup("Creating ephemeral lab: %s (as %s)", labName, s.cfg.APIUserUser)
	bodyBytes, statusCode, err := s.createLab(userHeaders, labName, topology, false, s.cfg.DeployTimeout)
	require.NoError(s.T(), err, "SETUP Failed: Could not execute create ephemeral lab request for '%s'", labName)
	require.Equal(s.T(), http.StatusOK, statusCode, "SETUP Failed: Could not create ephemeral lab '%s'. Body: %s", labName, string(bodyBytes))
	s.logSuccess("Lab '%s' created successfully", labName)

	// *** Cleanup is registered by the CALLER using defer ***
	// Example in test:
	// labName, userHeaders := s.setupEphemeralLab()
	// defer s.cleanupLab(labName, true) // Use superuser for cleanup

	s.logDebug("Pausing for %v after lab creation...", s.cfg.StabilizePause)
	time.Sleep(s.cfg.StabilizePause)

	return labName, userHeaders
}

// setupSuperuserLab creates a lab as the superuser.
// It returns the lab name and auth headers for the superuser.
// IMPORTANT: It registers cleanup using defer within the *calling test method's scope*.
func (s *BaseSuite) setupSuperuserLab() (labName string, superuserHeaders http.Header) {
	s.T().Helper()
	superuserToken := s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass)
	superuserHeaders = s.getAuthHeaders(superuserToken)

	labName = fmt.Sprintf("%s-su-eph-%s", s.cfg.LabNamePrefix, s.randomSuffix(5))
	topology := strings.ReplaceAll(s.cfg.SimpleTopologyContent, "{lab_name}", labName)

	s.logSetup("Creating superuser ephemeral lab: %s", labName)
	bodyBytes, statusCode, err := s.createLab(superuserHeaders, labName, topology, false, s.cfg.DeployTimeout)
	require.NoError(s.T(), err, "SETUP-SU Failed: Could not execute create superuser lab request for '%s'", labName)
	require.Equal(s.T(), http.StatusOK, statusCode, "SETUP-SU Failed: Could not create superuser lab '%s'. Body: %s", labName, string(bodyBytes))
	s.logSuccess("Superuser lab '%s' created successfully", labName)

	// *** Cleanup is registered by the CALLER using defer ***
	// Example in test:
	// labName, suHeaders := s.setupSuperuserLab()
	// defer s.cleanupLab(labName, true) // Use superuser for cleanup

	s.logDebug("Pausing for %v after lab creation...", s.cfg.StabilizePause)
	time.Sleep(s.cfg.StabilizePause)

	return labName, superuserHeaders
}

// cleanupLab is a helper to be called via defer in tests after setup*Lab helpers.
// It uses superuser credentials for reliable cleanup.
func (s *BaseSuite) cleanupLab(labName string, performCleanup bool) {
	s.T().Helper()
	s.logTeardown("Initiating cleanup for lab: %s (as %s)", labName, s.cfg.SuperuserUser)
	// Login as superuser specifically for cleanup
	superuserToken := s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass)
	superuserHeaders := s.getAuthHeaders(superuserToken)

	_, _, err := s.destroyLab(superuserHeaders, labName, performCleanup, s.cfg.CleanupTimeout)
	if err != nil {
		s.logWarning("Error occurred during destroy execution for lab '%s' in cleanup: %v", labName, err)
		// Don't fail the test during cleanup, just log
	} else {
		s.logSuccess("Lab '%s' cleanup completed", labName)
	}
	s.logDebug("Pausing for %v after cleanup...", s.cfg.CleanupPause)
	time.Sleep(s.cfg.CleanupPause)
}

// --- Generic HTTP Request Helper (method on BaseSuite) ---

var authRegex = regexp.MustCompile(`(?i)(Authorization: Bearer) \S+`)

func (s *BaseSuite) logHeaders(prefix string, headers http.Header) {
	s.T().Helper()
	if s.cfg.LogLevel != LogLevelDebug {
		return
	}

	if len(headers) == 0 {
		s.logDebug("%s Headers: (none)", prefix)
		return
	}

	s.logDebug("%s Headers:", prefix)
	for key, values := range headers {
		headerLine := fmt.Sprintf("%s: %s", key, strings.Join(values, ", "))
		maskedLine := authRegex.ReplaceAllString(headerLine, "$1 ********")
		s.logDebug("  %s", maskedLine)
	}
}

// logBody logs the body, masking password if JSON and truncating if necessary.
func (s *BaseSuite) logBody(prefix string, bodyBytes []byte) {
	s.T().Helper()
	if s.cfg.LogLevel != LogLevelDebug {
		return
	}

	if len(bodyBytes) == 0 {
		s.logDebug("%s Body: (empty)", prefix)
		return
	}

	maskedBody := bodyBytes // Start with original bytes

	// Attempt to mask password if content looks like JSON
	if bytes.HasPrefix(bodyBytes, []byte("{")) && bytes.HasSuffix(bodyBytes, []byte("}")) { // Basic JSON check
		var data map[string]interface{}
		tempReader := bytes.NewReader(bodyBytes)
		decoder := json.NewDecoder(tempReader)
		if err := decoder.Decode(&data); err == nil {
			// Check for password field (case-insensitive)
			for k, v := range data {
				if strings.ToLower(k) == "password" {
					if _, ok := v.(string); ok {
						data[k] = "********"
						break
					}
				}
			}
			maskedBytes, marshalErr := json.MarshalIndent(data, "", "  ")
			if marshalErr == nil {
				maskedBody = maskedBytes
			} else {
				s.logWarning("%s Failed to re-marshal body after masking: %v", prefix, marshalErr)
				maskedBody = bodyBytes
			}
		} else {
			maskedBody = bodyBytes
		}
	}

	// Log the (potentially masked) body, truncated if necessary
	const maxLogLen = 1024
	if len(maskedBody) <= maxLogLen {
		s.logDebug("%s Body:\n---\n%s\n---", prefix, string(maskedBody))
	} else {
		s.logDebug("%s Body: (truncated to %d bytes)\n---\n%s\n...[truncated]...", prefix, maxLogLen, string(maskedBody[:maxLogLen]))
	}
}

// doRequest performs the HTTP request and returns body, status, and error.
// It now uses suite's logging and config. Requires caller to handle errors/status codes.
func (s *BaseSuite) doRequest(method, urlStr string, headers http.Header, reqBodyReader io.Reader, timeout time.Duration) ([]byte, int, error) {
	s.T().Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	s.logDebug("Request Start: %s %s", method, urlStr)
	s.logHeaders("Request", headers)

	var reqBodyBytes []byte
	var actualReqBodyReader io.Reader
	if reqBodyReader != nil {
		var err error
		reqBodyBytes, err = io.ReadAll(reqBodyReader)
		if err != nil {
			s.logWarning("Failed to read request body for logging: %v", err)
			// Continue without logging body if read fails, but maybe error out?
			// For now, just log and proceed with nil reader
			actualReqBodyReader = nil
		} else {
			actualReqBodyReader = bytes.NewReader(reqBodyBytes)
		}
		s.logBody("Request", reqBodyBytes) // Pass original bytes
	} else {
		s.logBody("Request", nil)
		actualReqBodyReader = nil
	}

	req, err := http.NewRequestWithContext(ctx, method, urlStr, actualReqBodyReader)
	if err != nil {
		s.logError("Failed to create request object: %v", err)
		return nil, 0, fmt.Errorf("failed to create request (%s %s): %w", method, urlStr, err)
	}
	req.Header = headers

	startTime := time.Now()
	resp, err := http.DefaultClient.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		s.logError("Failed to execute request (%s %s) after %v: %v", method, urlStr, duration, err)
		// Return error for the caller to handle
		return nil, 0, fmt.Errorf("failed to execute request (%s %s): %w", method, urlStr, err)
	}
	defer resp.Body.Close()

	s.logDebug("Response Received: Status %d (%s) from %s %s in %v",
		resp.StatusCode, http.StatusText(resp.StatusCode), method, urlStr, duration)
	s.logHeaders("Response", resp.Header)

	respBodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		// Log warning but return the error and potentially partial body
		s.logWarning("Failed to read response body (%s %s): %v", method, urlStr, readErr)
	}
	s.logBody("Response", respBodyBytes)
	s.logDebug("Response End: %s %s", method, urlStr)

	// Return body, status, and potential read error
	return respBodyBytes, resp.StatusCode, readErr
}

// mustMarshal helper adapted for suite context
func (s *BaseSuite) mustMarshal(v interface{}) []byte {
	s.T().Helper()
	data, err := json.Marshal(v)
	require.NoError(s.T(), err, "Failed to marshal JSON")
	return data
}

// --- Environment Variable Helpers (remain standalone functions) ---

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
		os.Exit(1) // Exit during setup if required env var is missing
	}
	return value
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return fallback
	}
	// Attempt to parse assuming seconds first, then full duration string
	valueDuration, errSec := time.ParseDuration(valueStr + "s")
	if errSec == nil {
		return valueDuration
	}
	valueIntDur, errDur := time.ParseDuration(valueStr)
	if errDur != nil {
		fmt.Printf("Warning: Invalid duration format for %s ('%s'). Tried adding 's' and direct parse. Using default: %v. Errors: %v, %v\n", key, valueStr, fallback, errSec, errDur)
		return fallback
	}
	return valueIntDur
}

// --- Clab Data Structures (remain standalone) ---
type ClabContainerInfo struct {
	Name        string `json:"name"`
	ContainerID string `json:"container_id"`
	Image       string `json:"image"`
	Kind        string `json:"kind"`
	State       string `json:"state"`
	IPv4Address string `json:"ipv4_address"`
	IPv6Address string `json:"ipv6_address"`
	LabName     string `json:"lab_name"`
	Owner       string `json:"owner"`
}

type ClabInspectOutput map[string][]ClabContainerInfo

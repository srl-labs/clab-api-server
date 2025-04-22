// tests_go/auth_suite_test.go
package tests_go

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
)

// AuthSuite tests authentication endpoints
type AuthSuite struct {
	BaseSuite
}

// TestAuthSuite runs the AuthSuite
func TestAuthSuite(t *testing.T) {
	suite.Run(t, new(AuthSuite))
}

func (s *AuthSuite) TestLoginSuperuser() {
	s.logTest("Attempting valid login for superuser: %s", s.cfg.SuperuserUser)
	token := s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass) // login helper handles assertions

	s.Assert().NotEmpty(token, "Expected a non-empty token for superuser login")
	s.Assert().Greater(len(token), 10, "Token seems too short")
	if s.T().Failed() { // Only log success if previous asserts passed
		return
	}
	s.logSuccess("Superuser login successful, token received")
}

func (s *AuthSuite) TestLoginAPIUser() {
	s.logTest("Attempting valid login for apiuser: %s", s.cfg.APIUserUser)
	token := s.login(s.cfg.APIUserUser, s.cfg.APIUserPass) // login helper handles assertions

	s.Assert().NotEmpty(token, "Expected a non-empty token for apiuser login")
	s.Assert().Greater(len(token), 10, "Token seems too short")
	if s.T().Failed() {
		return
	}
	s.logSuccess("Apiuser login successful, token received")
}

func (s *AuthSuite) TestInvalidLogin() {
	s.logTest("Attempting invalid login (wrong user/pass - expecting 401 Unauthorized)")
	loginURL := s.cfg.APIURL + "/login"
	payload := map[string]string{
		"username": "nonexistent_user_!@#$",
		"password": "wrong_password_$%^",
	}
	// Use doRequest directly for non-200 expectations
	bodyBytes, statusCode, err := s.doRequest("POST", loginURL, s.getAuthHeaders(""), // No token needed
		bytes.NewBuffer(s.mustMarshal(payload)), s.cfg.RequestTimeout)

	s.Require().NoError(err, "Request execution failed") // Transport error should fail test

	s.logInfo("Received status %d for invalid login", statusCode)
	s.Assert().Equal(http.StatusUnauthorized, statusCode, "Expected status 401 Unauthorized")

	// Check for error field in response body
	var errResp struct {
		Error string `json:"error"`
	}
	// Use Assert() here so we still check the status code even if unmarshal fails
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Assert().NoError(err, "Could not unmarshal error response: %v", err)
	s.Assert().NotEmpty(errResp.Error, "Expected 'error' field in JSON response for invalid login")

	if statusCode == http.StatusUnauthorized && errResp.Error != "" {
		s.logSuccess("Invalid login correctly rejected with 401 Unauthorized")
	}
}

func (s *AuthSuite) TestUnauthorizedUserLogin() {
	s.logTest("Attempting login for unauthorized user: %s (expecting 401 Unauthorized)", s.cfg.UnauthUser)
	loginURL := s.cfg.APIURL + "/login"
	payload := map[string]string{
		"username": s.cfg.UnauthUser,
		"password": s.cfg.UnauthPass,
	}
	// Use doRequest directly
	bodyBytes, statusCode, err := s.doRequest("POST", loginURL, s.getAuthHeaders(""), // No token needed
		bytes.NewBuffer(s.mustMarshal(payload)), s.cfg.RequestTimeout)

	s.Require().NoError(err, "Request execution failed") // Transport error should fail test

	s.logInfo("Received status %d for unauthorized user login", statusCode)
	s.Assert().Equal(http.StatusUnauthorized, statusCode, "Expected status 401 for user not in allowed groups")

	var errResp struct {
		Error string `json:"error"`
	}
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Assert().NoError(err, "Could not unmarshal error response: %v", err)
	s.Assert().NotEmpty(errResp.Error, "Expected 'error' field in JSON response for unauthorized login")

	if statusCode == http.StatusUnauthorized && errResp.Error != "" {
		s.logSuccess("Unauthorized user login correctly rejected with 401 Unauthorized")
	}
}

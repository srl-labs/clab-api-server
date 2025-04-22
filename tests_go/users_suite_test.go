// tests_go/users_suite_test.go
package tests_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// UserSuite tests user management endpoints
type UserSuite struct {
	BaseSuite
	apiUserToken     string
	apiUserHeaders   http.Header
	superuserToken   string
	superuserHeaders http.Header
}

// TestUserSuite runs the UserSuite
func TestUserSuite(t *testing.T) {
	suite.Run(t, new(UserSuite))
}

// SetupSuite logs in users needed for the tests in this suite
func (s *UserSuite) SetupSuite() {
	s.BaseSuite.SetupSuite() // Call base setup
	s.apiUserToken = s.login(s.cfg.APIUserUser, s.cfg.APIUserPass)
	s.apiUserHeaders = s.getAuthHeaders(s.apiUserToken)
	s.superuserToken = s.login(s.cfg.SuperuserUser, s.cfg.SuperuserPass)
	s.superuserHeaders = s.getAuthHeaders(s.superuserToken)
	s.Require().NotEmpty(s.apiUserToken)
	s.Require().NotEmpty(s.superuserToken)
}

// UserDetails represents information about a system user
type UserDetails struct {
	Username    string   `json:"username"`
	UID         string   `json:"uid,omitempty"`
	GID         string   `json:"gid,omitempty"`
	DisplayName string   `json:"displayName,omitempty"`
	HomeDir     string   `json:"homeDir,omitempty"`
	Shell       string   `json:"shell,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	IsSuperuser bool     `json:"isSuperuser,omitempty"`
	IsAPIUser   bool     `json:"isApiUser,omitempty"`
}

// UserCreateRequest represents a request to create a new system user
type UserCreateRequest struct {
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	DisplayName string   `json:"displayName,omitempty"`
	Shell       string   `json:"shell,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	IsSuperuser bool     `json:"isSuperuser,omitempty"`
}

// UserUpdateRequest represents a request to update user information
type UserUpdateRequest struct {
	DisplayName string   `json:"displayName,omitempty"`
	Shell       string   `json:"shell,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	IsSuperuser bool     `json:"isSuperuser,omitempty"`
}

// PasswordChangeRequest represents a request to change a user's password
type PasswordChangeRequest struct {
	CurrentPassword string `json:"currentPassword,omitempty"`
	NewPassword     string `json:"newPassword"`
}

// GenericSuccessResponse represents a standard success response
type GenericSuccessResponse struct {
	Message string `json:"message"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// TestListUsersSuperuser tests that superusers can list all users
func (s *UserSuite) TestListUsersSuperuser() {
	s.logTest("Testing list users endpoint as superuser (expecting 200 OK)")

	listURL := fmt.Sprintf("%s/api/v1/users", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", listURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute list users request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for superuser listing users. Body: %s", string(bodyBytes))

	// Verify we can parse the response as JSON array of UserDetails
	var users []UserDetails
	err = json.Unmarshal(bodyBytes, &users)
	s.Require().NoError(err, "Failed to unmarshal user list response. Body: %s", string(bodyBytes))

	// Check if the list contains the expected users
	s.Assert().NotEmpty(users, "User list should not be empty")

	// Find the superuser and API user in the list
	foundSuperuser := false
	foundAPIUser := false
	for _, user := range users {
		if user.Username == s.cfg.SuperuserUser {
			foundSuperuser = true
			s.Assert().True(user.IsSuperuser, "Superuser should have IsSuperuser=true")
		}
		if user.Username == s.cfg.APIUserUser {
			foundAPIUser = true
			s.Assert().True(user.IsAPIUser, "API user should have IsAPIUser=true")
		}
	}

	s.Assert().True(foundSuperuser, "Superuser '%s' should be in the user list", s.cfg.SuperuserUser)
	s.Assert().True(foundAPIUser, "API user '%s' should be in the user list", s.cfg.APIUserUser)

	if !s.T().Failed() {
		s.logSuccess("Successfully listed users as superuser")
	}
}

// TestListUsersRegularUser tests that regular users cannot list all users
func (s *UserSuite) TestListUsersRegularUser() {
	s.logTest("Testing list users endpoint as regular user (expecting 403 Forbidden)")

	listURL := fmt.Sprintf("%s/api/v1/users", s.cfg.APIURL)
	bodyBytes, statusCode, err := s.doRequest("GET", listURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute list users request")

	s.Assert().Equal(http.StatusForbidden, statusCode, "Expected status 403 for regular user listing users. Body: %s", string(bodyBytes))

	var errResp ErrorResponse
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response. Body: %s", string(bodyBytes))
	s.Assert().Contains(errResp.Error, "Superuser privileges required", "Error message should mention superuser privileges")

	if statusCode == http.StatusForbidden {
		s.logSuccess("Correctly received status 403 when regular user attempted to list all users")
	}
}

// TestGetUserDetailsSelf tests a user getting their own details
func (s *UserSuite) TestGetUserDetailsSelf() {
	s.logTest("Testing get user details endpoint for own account (expecting 200 OK)")

	userDetailsURL := fmt.Sprintf("%s/api/v1/users/%s", s.cfg.APIURL, s.cfg.APIUserUser)
	bodyBytes, statusCode, err := s.doRequest("GET", userDetailsURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute get own user details request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for user getting own details. Body: %s", string(bodyBytes))

	// Verify we can parse the response as UserDetails
	var userDetails UserDetails
	err = json.Unmarshal(bodyBytes, &userDetails)
	s.Require().NoError(err, "Failed to unmarshal user details response. Body: %s", string(bodyBytes))

	// Check if the details match the expected values
	s.Assert().Equal(s.cfg.APIUserUser, userDetails.Username, "Username should match")
	s.Assert().True(userDetails.IsAPIUser, "User should have IsAPIUser=true")

	if !s.T().Failed() {
		s.logSuccess("Successfully retrieved own user details")
	}
}

// TestGetUserDetailsSuperuser tests a superuser getting another user's details
func (s *UserSuite) TestGetUserDetailsSuperuser() {
	s.logTest("Testing get user details endpoint as superuser for another user (expecting 200 OK)")

	userDetailsURL := fmt.Sprintf("%s/api/v1/users/%s", s.cfg.APIURL, s.cfg.APIUserUser)
	bodyBytes, statusCode, err := s.doRequest("GET", userDetailsURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute get user details request as superuser")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for superuser getting another user's details. Body: %s", string(bodyBytes))

	// Verify we can parse the response as UserDetails
	var userDetails UserDetails
	err = json.Unmarshal(bodyBytes, &userDetails)
	s.Require().NoError(err, "Failed to unmarshal user details response. Body: %s", string(bodyBytes))

	// Check if the details match the expected values
	s.Assert().Equal(s.cfg.APIUserUser, userDetails.Username, "Username should match")
	s.Assert().True(userDetails.IsAPIUser, "User should have IsAPIUser=true")

	if !s.T().Failed() {
		s.logSuccess("Successfully retrieved another user's details as superuser")
	}
}

// TestGetUserDetailsUnauthorized tests a user trying to get another user's details
func (s *UserSuite) TestGetUserDetailsUnauthorized() {
	s.logTest("Testing get user details endpoint for another user (expecting 403 Forbidden)")

	userDetailsURL := fmt.Sprintf("%s/api/v1/users/%s", s.cfg.APIURL, s.cfg.SuperuserUser)
	bodyBytes, statusCode, err := s.doRequest("GET", userDetailsURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute get other user details request")

	s.Assert().Equal(http.StatusForbidden, statusCode, "Expected status 403. Body: %s", string(bodyBytes))

	var errResp ErrorResponse
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response. Body: %s", string(bodyBytes))
	s.Assert().Contains(errResp.Error, "permission", "Error message should mention permission")

	if statusCode == http.StatusForbidden {
		s.logSuccess("Correctly received status 403 when user attempted to get another user's details")
	}
}

// TestGetUserDetailsNonExistent tests getting details for a non-existent user
func (s *UserSuite) TestGetUserDetailsNonExistent() {
	s.logTest("Testing get user details endpoint for non-existent user (expecting 404 Not Found)")

	nonExistentUser := "nonexistent_user_" + s.randomSuffix(5)
	userDetailsURL := fmt.Sprintf("%s/api/v1/users/%s", s.cfg.APIURL, nonExistentUser)
	bodyBytes, statusCode, err := s.doRequest("GET", userDetailsURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute get non-existent user details request")

	s.Assert().Equal(http.StatusNotFound, statusCode, "Expected status 404. Body: %s", string(bodyBytes))

	var errResp ErrorResponse
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response. Body: %s", string(bodyBytes))
	s.Assert().Contains(errResp.Error, "not found", "Error message should mention user not found")

	if statusCode == http.StatusNotFound {
		s.logSuccess("Correctly received status 404 when getting details of non-existent user")
	}
}

// TestCreateUserSuperuser tests creating a new user as superuser
func (s *UserSuite) TestCreateUserSuperuser() {
	testUsername := "testuser_" + s.randomSuffix(5)
	s.logTest("Testing create user endpoint as superuser (expecting 201 Created)")

	// Clean up the test user after the test
	defer s.deleteTestUser(testUsername)

	createUserURL := fmt.Sprintf("%s/api/v1/users", s.cfg.APIURL)
	createUserRequest := UserCreateRequest{
		Username:    testUsername,
		Password:    "Test@123456",
		DisplayName: "Test User",
		Shell:       "/bin/bash",
		Groups:      []string{s.getEnvOrDefault("GOTEST_API_USER_GROUP", "clab_api")},
		IsSuperuser: false,
	}

	jsonPayload, err := json.Marshal(createUserRequest)
	s.Require().NoError(err, "Failed to marshal create user request")

	bodyBytes, statusCode, err := s.doRequest("POST", createUserURL, s.superuserHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute create user request")
	s.Require().Equal(http.StatusCreated, statusCode, "Expected status 201 for superuser creating a user. Body: %s", string(bodyBytes))

	// Verify we can parse the response
	var successResp GenericSuccessResponse
	err = json.Unmarshal(bodyBytes, &successResp)
	s.Require().NoError(err, "Failed to unmarshal success response. Body: %s", string(bodyBytes))
	s.Assert().Contains(successResp.Message, testUsername, "Success message should mention the created username")

	// Verify the user was actually created by getting their details
	s.verifyUserExists(testUsername)

	if !s.T().Failed() {
		s.logSuccess("Successfully created user %s as superuser", testUsername)
	}
}

// TestCreateUserRegularUser tests that a regular user cannot create users
func (s *UserSuite) TestCreateUserRegularUser() {
	testUsername := "testuser_" + s.randomSuffix(5)
	s.logTest("Testing create user endpoint as regular user (expecting 403 Forbidden)")

	createUserURL := fmt.Sprintf("%s/api/v1/users", s.cfg.APIURL)
	createUserRequest := UserCreateRequest{
		Username:    testUsername,
		Password:    "Test@123456",
		DisplayName: "Test User",
		Shell:       "/bin/bash",
		IsSuperuser: false,
	}

	jsonPayload, err := json.Marshal(createUserRequest)
	s.Require().NoError(err, "Failed to marshal create user request")

	bodyBytes, statusCode, err := s.doRequest("POST", createUserURL, s.apiUserHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute create user request as regular user")

	s.Assert().Equal(http.StatusForbidden, statusCode, "Expected status 403 for regular user creating a user. Body: %s", string(bodyBytes))

	var errResp ErrorResponse
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response. Body: %s", string(bodyBytes))
	s.Assert().Contains(errResp.Error, "Superuser privileges required", "Error message should mention superuser privileges")

	if statusCode == http.StatusForbidden {
		s.logSuccess("Correctly received status 403 when regular user attempted to create a user")
	}
}

// TestCreateUserDuplicate tests creating a user that already exists
func (s *UserSuite) TestCreateUserDuplicate() {
	// First create a test user
	testUsername := "testuser_" + s.randomSuffix(5)
	s.logTest("Testing create duplicate user (expecting 409 Conflict)")

	// Clean up the test user after the test
	defer s.deleteTestUser(testUsername)

	// Create the user first
	s.createTestUser(testUsername, "Test@123456", false)

	// Now try to create the same user again
	createUserURL := fmt.Sprintf("%s/api/v1/users", s.cfg.APIURL)
	createUserRequest := UserCreateRequest{
		Username:    testUsername,
		Password:    "AnotherPassword@123",
		DisplayName: "Duplicate Test User",
		Shell:       "/bin/bash",
		IsSuperuser: false,
	}

	jsonPayload, err := json.Marshal(createUserRequest)
	s.Require().NoError(err, "Failed to marshal create duplicate user request")

	bodyBytes, statusCode, err := s.doRequest("POST", createUserURL, s.superuserHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute create duplicate user request")

	s.Assert().Equal(http.StatusConflict, statusCode, "Expected status 409 for creating duplicate user. Body: %s", string(bodyBytes))

	var errResp ErrorResponse
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response. Body: %s", string(bodyBytes))
	s.Assert().Contains(errResp.Error, "already exists", "Error message should mention user already exists")

	if statusCode == http.StatusConflict {
		s.logSuccess("Correctly received status 409 when attempting to create a duplicate user")
	}
}

// TestUpdateUserSelf tests a user updating their own information
func (s *UserSuite) TestUpdateUserSelf() {
	// Create a test user
	testUsername := "testuser_" + s.randomSuffix(5)
	testPassword := "Test@123456"
	s.logTest("Testing update user endpoint for own account (expecting 200 OK)")

	// Clean up the test user after the test
	defer s.deleteTestUser(testUsername)

	// Create the user
	s.createTestUser(testUsername, testPassword, false)

	// Login as the test user
	testUserToken := s.login(testUsername, testPassword)
	testUserHeaders := s.getAuthHeaders(testUserToken)

	// Update the user's information
	updateUserURL := fmt.Sprintf("%s/api/v1/users/%s", s.cfg.APIURL, testUsername)
	updateUserRequest := UserUpdateRequest{
		DisplayName: "Updated Test User",
		Shell:       "/bin/bash",
		// Cannot update own superuser status
	}

	jsonPayload, err := json.Marshal(updateUserRequest)
	s.Require().NoError(err, "Failed to marshal update user request")

	bodyBytes, statusCode, err := s.doRequest("PUT", updateUserURL, testUserHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute update user request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for user updating own info. Body: %s", string(bodyBytes))

	// Verify we can parse the response
	var successResp GenericSuccessResponse
	err = json.Unmarshal(bodyBytes, &successResp)
	s.Require().NoError(err, "Failed to unmarshal success response. Body: %s", string(bodyBytes))
	s.Assert().Contains(successResp.Message, testUsername, "Success message should mention the updated username")

	// Verify the user details were updated
	userDetails := s.getUserDetails(testUsername, s.superuserHeaders)
	s.Assert().Equal("Updated Test User", userDetails.DisplayName, "DisplayName should be updated")
	s.Assert().Equal("/bin/bash", userDetails.Shell, "Shell should be updated")

	if !s.T().Failed() {
		s.logSuccess("Successfully updated own user information")
	}
}

// TestUpdateUserSuperuser tests a superuser updating another user's information
func (s *UserSuite) TestUpdateUserSuperuser() {
	// Create a test user
	testUsername := "testuser_" + s.randomSuffix(5)
	s.logTest("Testing update user endpoint as superuser for another user (expecting 200 OK)")

	// Clean up the test user after the test
	defer s.deleteTestUser(testUsername)

	// Create the user
	s.createTestUser(testUsername, "Test@123456", false)

	// Update the user's information as superuser
	updateUserURL := fmt.Sprintf("%s/api/v1/users/%s", s.cfg.APIURL, testUsername)
	updateUserRequest := UserUpdateRequest{
		DisplayName: "Superuser Updated User",
		Shell:       "/bin/zsh",
		IsSuperuser: true, // Promote to superuser
	}

	jsonPayload, err := json.Marshal(updateUserRequest)
	s.Require().NoError(err, "Failed to marshal update user request")

	bodyBytes, statusCode, err := s.doRequest("PUT", updateUserURL, s.superuserHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute update user request as superuser")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for superuser updating user. Body: %s", string(bodyBytes))

	// Verify we can parse the response
	var successResp GenericSuccessResponse
	err = json.Unmarshal(bodyBytes, &successResp)
	s.Require().NoError(err, "Failed to unmarshal success response. Body: %s", string(bodyBytes))
	s.Assert().Contains(successResp.Message, testUsername, "Success message should mention the updated username")

	// Verify the user details were updated
	userDetails := s.getUserDetails(testUsername, s.superuserHeaders)
	s.Assert().Equal("Superuser Updated User", userDetails.DisplayName, "DisplayName should be updated")
	s.Assert().Equal("/bin/zsh", userDetails.Shell, "Shell should be updated")
	s.Assert().True(userDetails.IsSuperuser, "User should now be a superuser")

	if !s.T().Failed() {
		s.logSuccess("Successfully updated another user's information as superuser")
	}
}

// TestUpdateUserUnauthorized tests a user trying to update another user's details
func (s *UserSuite) TestUpdateUserUnauthorized() {
	// Create a test user
	testUsername := "testuser_" + s.randomSuffix(5)
	s.logTest("Testing update user endpoint for another user (expecting 403 Forbidden)")

	// Clean up the test user after the test
	defer s.deleteTestUser(testUsername)

	// Create the user
	s.createTestUser(testUsername, "Test@123456", false)

	// Try to update another user's information as regular API user
	updateUserURL := fmt.Sprintf("%s/api/v1/users/%s", s.cfg.APIURL, testUsername)
	updateUserRequest := UserUpdateRequest{
		DisplayName: "Unauthorized Update",
		Shell:       "/bin/zsh",
	}

	jsonPayload, err := json.Marshal(updateUserRequest)
	s.Require().NoError(err, "Failed to marshal update user request")

	bodyBytes, statusCode, err := s.doRequest("PUT", updateUserURL, s.apiUserHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute update user request for another user")

	s.Assert().Equal(http.StatusForbidden, statusCode, "Expected status 403. Body: %s", string(bodyBytes))

	var errResp ErrorResponse
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response. Body: %s", string(bodyBytes))
	s.Assert().Contains(errResp.Error, "permission", "Error message should mention permission")

	if statusCode == http.StatusForbidden {
		s.logSuccess("Correctly received status 403 when user attempted to update another user's details")
	}
}

// TestUpdateNonExistentUser tests updating a non-existent user
func (s *UserSuite) TestUpdateNonExistentUser() {
	nonExistentUser := "nonexistent_user_" + s.randomSuffix(5)
	s.logTest("Testing update user endpoint for non-existent user (expecting 404 Not Found)")

	updateUserURL := fmt.Sprintf("%s/api/v1/users/%s", s.cfg.APIURL, nonExistentUser)
	updateUserRequest := UserUpdateRequest{
		DisplayName: "Non-existent User",
		Shell:       "/bin/bash",
	}

	jsonPayload, err := json.Marshal(updateUserRequest)
	s.Require().NoError(err, "Failed to marshal update non-existent user request")

	bodyBytes, statusCode, err := s.doRequest("PUT", updateUserURL, s.superuserHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute update non-existent user request")

	s.Assert().Equal(http.StatusNotFound, statusCode, "Expected status 404. Body: %s", string(bodyBytes))

	var errResp ErrorResponse
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response. Body: %s", string(bodyBytes))
	s.Assert().Contains(errResp.Error, "not found", "Error message should mention user not found")

	if statusCode == http.StatusNotFound {
		s.logSuccess("Correctly received status 404 when updating non-existent user")
	}
}

// TestDeleteUserSuperuser tests deleting a user as superuser
func (s *UserSuite) TestDeleteUserSuperuser() {
	// Create a test user
	testUsername := "deleteuser_" + s.randomSuffix(5)
	s.logTest("Testing delete user endpoint as superuser (expecting 200 OK)")

	// Create the user
	s.createTestUser(testUsername, "Test@123456", false)

	// Delete the user
	deleteUserURL := fmt.Sprintf("%s/api/v1/users/%s", s.cfg.APIURL, testUsername)
	bodyBytes, statusCode, err := s.doRequest("DELETE", deleteUserURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute delete user request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for superuser deleting a user. Body: %s", string(bodyBytes))

	// Verify we can parse the response
	var successResp GenericSuccessResponse
	err = json.Unmarshal(bodyBytes, &successResp)
	s.Require().NoError(err, "Failed to unmarshal success response. Body: %s", string(bodyBytes))
	s.Assert().Contains(successResp.Message, testUsername, "Success message should mention the deleted username")

	// Verify the user no longer exists
	s.verifyUserDoesNotExist(testUsername)

	if !s.T().Failed() {
		s.logSuccess("Successfully deleted user %s as superuser", testUsername)
	}
}

// TestDeleteUserRegularUser tests that a regular user cannot delete users
func (s *UserSuite) TestDeleteUserRegularUser() {
	// Create a test user
	testUsername := "deleteuser_" + s.randomSuffix(5)
	s.logTest("Testing delete user endpoint as regular user (expecting 403 Forbidden)")

	// Clean up the test user after the test
	defer s.deleteTestUser(testUsername)

	// Create the user
	s.createTestUser(testUsername, "Test@123456", false)

	// Try to delete the user as a regular API user
	deleteUserURL := fmt.Sprintf("%s/api/v1/users/%s", s.cfg.APIURL, testUsername)
	bodyBytes, statusCode, err := s.doRequest("DELETE", deleteUserURL, s.apiUserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute delete user request as regular user")

	s.Assert().Equal(http.StatusForbidden, statusCode, "Expected status 403. Body: %s", string(bodyBytes))

	var errResp ErrorResponse
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response. Body: %s", string(bodyBytes))
	s.Assert().Contains(errResp.Error, "Superuser privileges required", "Error message should mention superuser privileges")

	if statusCode == http.StatusForbidden {
		s.logSuccess("Correctly received status 403 when regular user attempted to delete a user")
	}
}

// TestDeleteSelf tests that a superuser cannot delete their own account
func (s *UserSuite) TestDeleteSelf() {
	s.logTest("Testing delete self endpoint (expecting 403 Forbidden)")

	deleteUserURL := fmt.Sprintf("%s/api/v1/users/%s", s.cfg.APIURL, s.cfg.SuperuserUser)
	bodyBytes, statusCode, err := s.doRequest("DELETE", deleteUserURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute delete self request")

	s.Assert().Equal(http.StatusForbidden, statusCode, "Expected status 403. Body: %s", string(bodyBytes))

	var errResp ErrorResponse
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response. Body: %s", string(bodyBytes))
	s.Assert().Contains(errResp.Error, "cannot delete your own account", "Error message should mention can't delete own account")

	if statusCode == http.StatusForbidden {
		s.logSuccess("Correctly received status 403 when superuser attempted to delete their own account")
	}
}

// TestDeleteNonExistentUser tests deleting a non-existent user
func (s *UserSuite) TestDeleteNonExistentUser() {
	nonExistentUser := "nonexistent_user_" + s.randomSuffix(5)
	s.logTest("Testing delete user endpoint for non-existent user (expecting 404 Not Found)")

	deleteUserURL := fmt.Sprintf("%s/api/v1/users/%s", s.cfg.APIURL, nonExistentUser)
	bodyBytes, statusCode, err := s.doRequest("DELETE", deleteUserURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute delete non-existent user request")

	s.Assert().Equal(http.StatusNotFound, statusCode, "Expected status 404. Body: %s", string(bodyBytes))

	var errResp ErrorResponse
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response. Body: %s", string(bodyBytes))
	s.Assert().Contains(errResp.Error, "not found", "Error message should mention user not found")

	if statusCode == http.StatusNotFound {
		s.logSuccess("Correctly received status 404 when deleting non-existent user")
	}
}

// TestChangePasswordSelf tests a user changing their own password
func (s *UserSuite) TestChangePasswordSelf() {
	// Create a test user
	testUsername := "pwduser_" + s.randomSuffix(5)
	initialPassword := "Initial@123456"
	newPassword := "Updated@123456"
	s.logTest("Testing change password endpoint for own account (expecting 200 OK)")

	// Clean up the test user after the test
	defer s.deleteTestUser(testUsername)

	// Create the user
	s.createTestUser(testUsername, initialPassword, false)

	// Login as the test user
	testUserToken := s.login(testUsername, initialPassword)
	testUserHeaders := s.getAuthHeaders(testUserToken)

	// Change the password
	changePasswordURL := fmt.Sprintf("%s/api/v1/users/%s/password", s.cfg.APIURL, testUsername)
	changePasswordRequest := PasswordChangeRequest{
		CurrentPassword: initialPassword,
		NewPassword:     newPassword,
	}

	jsonPayload, err := json.Marshal(changePasswordRequest)
	s.Require().NoError(err, "Failed to marshal change password request")

	bodyBytes, statusCode, err := s.doRequest("PUT", changePasswordURL, testUserHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute change password request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for user changing own password. Body: %s", string(bodyBytes))

	// Verify we can parse the response
	var successResp GenericSuccessResponse
	err = json.Unmarshal(bodyBytes, &successResp)
	s.Require().NoError(err, "Failed to unmarshal success response. Body: %s", string(bodyBytes))
	s.Assert().Contains(successResp.Message, "Password changed", "Success message should confirm password change")

	// Verify the password was actually changed by logging in with the new password
	newLoginToken := s.login(testUsername, newPassword)
	s.Assert().NotEmpty(newLoginToken, "Should be able to login with the new password")

	if !s.T().Failed() {
		s.logSuccess("Successfully changed own password")
	}
}

// TestChangePasswordIncorrectCurrent tests changing password with incorrect current password
func (s *UserSuite) TestChangePasswordIncorrectCurrent() {
	// Create a test user
	testUsername := "pwduser_" + s.randomSuffix(5)
	correctPassword := "Correct@123456"
	incorrectPassword := "Wrong@123456"
	newPassword := "Updated@123456"
	s.logTest("Testing change password with incorrect current password (expecting 401 Unauthorized)")

	// Clean up the test user after the test
	defer s.deleteTestUser(testUsername)

	// Create the user
	s.createTestUser(testUsername, correctPassword, false)

	// Login as the test user
	testUserToken := s.login(testUsername, correctPassword)
	testUserHeaders := s.getAuthHeaders(testUserToken)

	// Try to change the password with incorrect current password
	changePasswordURL := fmt.Sprintf("%s/api/v1/users/%s/password", s.cfg.APIURL, testUsername)
	changePasswordRequest := PasswordChangeRequest{
		CurrentPassword: incorrectPassword, // Wrong password
		NewPassword:     newPassword,
	}

	jsonPayload, err := json.Marshal(changePasswordRequest)
	s.Require().NoError(err, "Failed to marshal change password request")

	bodyBytes, statusCode, err := s.doRequest("PUT", changePasswordURL, testUserHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute change password request with incorrect current password")

	s.Assert().Equal(http.StatusUnauthorized, statusCode, "Expected status 401. Body: %s", string(bodyBytes))

	var errResp ErrorResponse
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response. Body: %s", string(bodyBytes))
	s.Assert().Contains(errResp.Error, "incorrect", "Error message should mention incorrect password")

	if statusCode == http.StatusUnauthorized {
		s.logSuccess("Correctly received status 401 when changing password with incorrect current password")
	}
}

// TestChangePasswordSuperuser tests a superuser changing another user's password
func (s *UserSuite) TestChangePasswordSuperuser() {
	// Create a test user
	testUsername := "pwduser_" + s.randomSuffix(5)
	initialPassword := "Initial@123456"
	newPassword := "SuperuserSet@123456"
	s.logTest("Testing change password endpoint as superuser for another user (expecting 200 OK)")

	// Clean up the test user after the test
	defer s.deleteTestUser(testUsername)

	// Create the user
	s.createTestUser(testUsername, initialPassword, false)

	// Change the password as superuser (no current password needed)
	changePasswordURL := fmt.Sprintf("%s/api/v1/users/%s/password", s.cfg.APIURL, testUsername)
	changePasswordRequest := PasswordChangeRequest{
		// No current password needed for superuser
		NewPassword: newPassword,
	}

	jsonPayload, err := json.Marshal(changePasswordRequest)
	s.Require().NoError(err, "Failed to marshal change password request")

	bodyBytes, statusCode, err := s.doRequest("PUT", changePasswordURL, s.superuserHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute change password request as superuser")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 for superuser changing user password. Body: %s", string(bodyBytes))

	// Verify we can parse the response
	var successResp GenericSuccessResponse
	err = json.Unmarshal(bodyBytes, &successResp)
	s.Require().NoError(err, "Failed to unmarshal success response. Body: %s", string(bodyBytes))
	s.Assert().Contains(successResp.Message, "Password changed", "Success message should confirm password change")

	// Verify the password was actually changed by logging in with the new password
	newLoginToken := s.login(testUsername, newPassword)
	s.Assert().NotEmpty(newLoginToken, "Should be able to login with the new password")

	if !s.T().Failed() {
		s.logSuccess("Successfully changed another user's password as superuser")
	}
}

// TestChangePasswordUnauthorized tests a user trying to change another user's password
func (s *UserSuite) TestChangePasswordUnauthorized() {
	// Create a test user
	testUsername := "pwduser_" + s.randomSuffix(5)
	initialPassword := "Initial@123456"
	newPassword := "UnauthorizedAttempt@123456"
	s.logTest("Testing change password endpoint for another user (expecting 403 Forbidden)")

	// Clean up the test user after the test
	defer s.deleteTestUser(testUsername)

	// Create the user
	s.createTestUser(testUsername, initialPassword, false)

	// Try to change the password as a regular API user
	changePasswordURL := fmt.Sprintf("%s/api/v1/users/%s/password", s.cfg.APIURL, testUsername)
	changePasswordRequest := PasswordChangeRequest{
		NewPassword: newPassword,
	}

	jsonPayload, err := json.Marshal(changePasswordRequest)
	s.Require().NoError(err, "Failed to marshal change password request")

	bodyBytes, statusCode, err := s.doRequest("PUT", changePasswordURL, s.apiUserHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute change password request for another user")

	s.Assert().Equal(http.StatusForbidden, statusCode, "Expected status 403. Body: %s", string(bodyBytes))

	var errResp ErrorResponse
	err = json.Unmarshal(bodyBytes, &errResp)
	s.Require().NoError(err, "Failed to unmarshal error response. Body: %s", string(bodyBytes))
	s.Assert().Contains(errResp.Error, "permission", "Error message should mention permission")

	if statusCode == http.StatusForbidden {
		s.logSuccess("Correctly received status 403 when user attempted to change another user's password")
	}
}

// --- Helper methods ---

// Helper to get an environment variable with default fallback
// Gets the value directly from os.Getenv since we don't have AppEnv in the config
func (s *UserSuite) getEnvOrDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value != "" {
		return value
	}
	return fallback
}

// createTestUser creates a test user with the given username and password
func (s *UserSuite) createTestUser(username, password string, isSuperuser bool) {
	s.T().Helper()
	s.logSetup("Creating test user: %s (superuser=%t)", username, isSuperuser)

	// Determine groups based on user type
	var groups []string
	if isSuperuser {
		groups = []string{s.getEnvOrDefault("GOTEST_SUPERUSER_GROUP", "clab_admins")}
	} else {
		groups = []string{s.getEnvOrDefault("GOTEST_API_USER_GROUP", "clab_api")}
	}

	createUserURL := fmt.Sprintf("%s/api/v1/users", s.cfg.APIURL)
	createUserRequest := UserCreateRequest{
		Username:    username,
		Password:    password,
		DisplayName: "Test User " + username,
		Shell:       "/bin/bash",
		Groups:      groups,
		IsSuperuser: isSuperuser,
	}

	jsonPayload, err := json.Marshal(createUserRequest)
	s.Require().NoError(err, "Failed to marshal create test user request")

	bodyBytes, statusCode, err := s.doRequest("POST", createUserURL, s.superuserHeaders, bytes.NewBuffer(jsonPayload), s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute create test user request")

	if statusCode != http.StatusCreated {
		s.logError("Failed to create test user '%s'. Status: %d, Body: %s", username, statusCode, string(bodyBytes))
		s.FailNow("Failed to create test user")
	}

	s.logSuccess("Test user '%s' created successfully", username)

	// Small delay to ensure the user is fully created in the system
	time.Sleep(1 * time.Second)
}

// deleteTestUser deletes a test user with the given username
func (s *UserSuite) deleteTestUser(username string) {
	s.T().Helper()
	s.logTeardown("Deleting test user: %s", username)

	deleteUserURL := fmt.Sprintf("%s/api/v1/users/%s", s.cfg.APIURL, username)
	bodyBytes, statusCode, err := s.doRequest("DELETE", deleteUserURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)

	if err != nil {
		s.logWarning("Error deleting test user '%s': %v", username, err)
	} else if statusCode != http.StatusOK && statusCode != http.StatusNotFound {
		s.logWarning("Failed to delete test user '%s'. Status: %d, Body: %s", username, statusCode, string(bodyBytes))
	} else {
		s.logSuccess("Test user '%s' deleted successfully (or not found)", username)
	}

	// Small delay to ensure the user is fully deleted from the system
	time.Sleep(1 * time.Second)
}

// verifyUserExists checks if a user exists and has the expected attributes
func (s *UserSuite) verifyUserExists(username string) UserDetails {
	s.T().Helper()
	s.logInfo("Verifying user '%s' exists", username)

	userDetails := s.getUserDetails(username, s.superuserHeaders)
	s.Assert().Equal(username, userDetails.Username, "Username should match")

	return userDetails
}

// verifyUserDoesNotExist checks that a user does not exist
func (s *UserSuite) verifyUserDoesNotExist(username string) {
	s.T().Helper()
	s.logInfo("Verifying user '%s' does not exist", username)

	userDetailsURL := fmt.Sprintf("%s/api/v1/users/%s", s.cfg.APIURL, username)
	_, statusCode, _ := s.doRequest("GET", userDetailsURL, s.superuserHeaders, nil, s.cfg.RequestTimeout)
	s.Assert().Equal(http.StatusNotFound, statusCode, "User '%s' should not exist", username)
}

// getUserDetails gets a user's details
func (s *UserSuite) getUserDetails(username string, headers http.Header) UserDetails {
	s.T().Helper()

	userDetailsURL := fmt.Sprintf("%s/api/v1/users/%s", s.cfg.APIURL, username)
	bodyBytes, statusCode, err := s.doRequest("GET", userDetailsURL, headers, nil, s.cfg.RequestTimeout)
	s.Require().NoError(err, "Failed to execute get user details request")
	s.Require().Equal(http.StatusOK, statusCode, "Expected status 200 getting user details. Body: %s", string(bodyBytes))

	var userDetails UserDetails
	err = json.Unmarshal(bodyBytes, &userDetails)
	s.Require().NoError(err, "Failed to unmarshal user details response. Body: %s", string(bodyBytes))

	return userDetails
}

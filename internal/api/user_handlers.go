// internal/api/user_handlers.go
package api

import (
	"fmt"
	"net/http"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	"github.com/srl-labs/clab-api-server/internal/auth"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// @Summary List All Users
// @Description Get a list of all users in the system. Requires superuser privileges.
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Success 200 {array} models.UserDetails "List of user details"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden (User is not a superuser)"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/users [get]
func ListUsersHandler(c *gin.Context) {
	username := c.GetString("username")

	// Only superusers can list all users
	if !isSuperuser(username) {
		log.Warnf("User '%s' attempted to list all users without superuser privileges", username)
		c.JSON(http.StatusForbidden, models.ErrorResponse{Error: "Superuser privileges required for this operation"})
		return
	}

	users, err := auth.GetAllUsers()
	if err != nil {
		log.Errorf("Failed to get user list: %v", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to retrieve user list: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, users)
}

// @Summary Get User Details
// @Description Get detailed information about a specific user. Requires superuser privileges or the user's own account.
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Param username path string true "Username to get details for" example="john"
// @Success 200 {object} models.UserDetails "User details"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden (Not superuser or not the user's own account)"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/users/{username} [get]
func GetUserDetailsHandler(c *gin.Context) {
	requestingUser := c.GetString("username")
	targetUser := c.Param("username")

	// Check authorization - must be superuser or requesting own account
	if !isSuperuser(requestingUser) && requestingUser != targetUser {
		log.Warnf("User '%s' attempted to access details for user '%s' without permission", requestingUser, targetUser)
		c.JSON(http.StatusForbidden, models.ErrorResponse{Error: "You don't have permission to access this user's details"})
		return
	}

	userDetails, err := auth.GetUserDetails(targetUser)
	if err != nil {
		// Check if user not found
		if err.Error() == "user: unknown user "+targetUser {
			log.Infof("User '%s' requested details for non-existent user '%s'", requestingUser, targetUser)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: fmt.Sprintf("User '%s' not found", targetUser)})
			return
		}

		log.Errorf("Failed to get details for user '%s': %v", targetUser, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to retrieve user details: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, userDetails)
}

// @Summary Create User
// @Description Create a new system user. Requires superuser privileges.
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param user body models.UserCreateRequest true "User creation details"
// @Success 201 {object} models.GenericSuccessResponse "User created successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid request body"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden (User is not a superuser)"
// @Failure 409 {object} models.ErrorResponse "User already exists"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/users [post]
func CreateUserHandler(c *gin.Context) {
	requestingUser := c.GetString("username")

	// Only superusers can create users
	if !isSuperuser(requestingUser) {
		log.Warnf("User '%s' attempted to create a user without superuser privileges", requestingUser)
		c.JSON(http.StatusForbidden, models.ErrorResponse{Error: "Superuser privileges required for this operation"})
		return
	}

	var req models.UserCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("Invalid user creation request from user '%s': %v", requestingUser, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	// Create the user
	err := auth.CreateUser(req)
	if err != nil {
		// Check if the error indicates the user already exists
		if err.Error() == fmt.Sprintf("user '%s' already exists", req.Username) {
			log.Warnf("User '%s' attempted to create already existing user '%s'", requestingUser, req.Username)
			c.JSON(http.StatusConflict, models.ErrorResponse{Error: err.Error()})
			return
		}

		log.Errorf("Failed to create user '%s': %v", req.Username, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to create user: " + err.Error()})
		return
	}

	log.Infof("User '%s' successfully created new user '%s'", requestingUser, req.Username)
	c.JSON(http.StatusCreated, models.GenericSuccessResponse{Message: fmt.Sprintf("User '%s' created successfully", req.Username)})
}

// @Summary Update User
// @Description Update information for an existing user. Requires superuser privileges or the user's own account.
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param username path string true "Username to update" example="john"
// @Param user body models.UserUpdateRequest true "User details to update"
// @Success 200 {object} models.GenericSuccessResponse "User updated successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid request body"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden (Not superuser or not the user's own account)"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/users/{username} [put]
func UpdateUserHandler(c *gin.Context) {
	requestingUser := c.GetString("username")
	targetUser := c.Param("username")

	// Check authorization - must be superuser or requesting own account
	// Note: Regular users can't change superuser status even for themselves
	isRequestingSuperuser := isSuperuser(requestingUser)
	isSelfUpdate := requestingUser == targetUser

	if !isRequestingSuperuser && !isSelfUpdate {
		log.Warnf("User '%s' attempted to update user '%s' without permission", requestingUser, targetUser)
		c.JSON(http.StatusForbidden, models.ErrorResponse{Error: "You don't have permission to update this user"})
		return
	}

	var req models.UserUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("Invalid user update request from user '%s': %v", requestingUser, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	// If not superuser, ensure they're not trying to grant superuser status
	if !isRequestingSuperuser && req.IsSuperuser {
		log.Warnf("User '%s' attempted to grant superuser privileges", requestingUser)
		c.JSON(http.StatusForbidden, models.ErrorResponse{Error: "You don't have permission to modify superuser status"})
		return
	}

	// Update the user
	err := auth.UpdateUser(targetUser, req)
	if err != nil {
		// Check if user not found
		if err.Error() == fmt.Sprintf("user '%s' not found", targetUser) {
			log.Infof("User '%s' attempted to update non-existent user '%s'", requestingUser, targetUser)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
			return
		}

		log.Errorf("Failed to update user '%s': %v", targetUser, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to update user: " + err.Error()})
		return
	}

	log.Infof("User '%s' successfully updated user '%s'", requestingUser, targetUser)
	c.JSON(http.StatusOK, models.GenericSuccessResponse{Message: fmt.Sprintf("User '%s' updated successfully", targetUser)})
}

// @Summary Delete User
// @Description Delete a user from the system. Requires superuser privileges.
// @Tags Users
// @Security BearerAuth
// @Produce json
// @Param username path string true "Username to delete" example="john"
// @Success 200 {object} models.GenericSuccessResponse "User deleted successfully"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden (User is not a superuser)"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/users/{username} [delete]
func DeleteUserHandler(c *gin.Context) {
	requestingUser := c.GetString("username")
	targetUser := c.Param("username")

	// Only superusers can delete users
	if !isSuperuser(requestingUser) {
		log.Warnf("User '%s' attempted to delete user '%s' without superuser privileges", requestingUser, targetUser)
		c.JSON(http.StatusForbidden, models.ErrorResponse{Error: "Superuser privileges required for this operation"})
		return
	}

	// Prevent deleting yourself
	if requestingUser == targetUser {
		log.Warnf("User '%s' attempted to delete their own account", requestingUser)
		c.JSON(http.StatusForbidden, models.ErrorResponse{Error: "You cannot delete your own account"})
		return
	}

	// Delete the user
	err := auth.DeleteUser(targetUser)
	if err != nil {
		// Check if user not found
		if err.Error() == fmt.Sprintf("user '%s' not found", targetUser) {
			log.Infof("User '%s' attempted to delete non-existent user '%s'", requestingUser, targetUser)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
			return
		}

		log.Errorf("Failed to delete user '%s': %v", targetUser, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to delete user: " + err.Error()})
		return
	}

	log.Infof("User '%s' successfully deleted user '%s'", requestingUser, targetUser)
	c.JSON(http.StatusOK, models.GenericSuccessResponse{Message: fmt.Sprintf("User '%s' deleted successfully", targetUser)})
}

// @Summary Change User Password
// @Description Change password for a user. Requires superuser privileges or the user's own account.
// @Tags Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param username path string true "Username to change password for" example="john"
// @Param passwordChange body models.PasswordChangeRequest true "Password change details"
// @Success 200 {object} models.GenericSuccessResponse "Password changed successfully"
// @Failure 400 {object} models.ErrorResponse "Invalid request body"
// @Failure 401 {object} models.ErrorResponse "Unauthorized or incorrect current password"
// @Failure 403 {object} models.ErrorResponse "Forbidden (Not superuser or not the user's own account)"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /api/v1/users/{username}/password [put]
func ChangeUserPasswordHandler(c *gin.Context) {
	requestingUser := c.GetString("username")
	targetUser := c.Param("username")

	// Check authorization - must be superuser or requesting own account
	isRequestingSuperuser := isSuperuser(requestingUser)
	isSelfUpdate := requestingUser == targetUser

	if !isRequestingSuperuser && !isSelfUpdate {
		log.Warnf("User '%s' attempted to change password for user '%s' without permission", requestingUser, targetUser)
		c.JSON(http.StatusForbidden, models.ErrorResponse{Error: "You don't have permission to change this user's password"})
		return
	}

	var req models.PasswordChangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("Invalid password change request from user '%s': %v", requestingUser, err)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Invalid request body: " + err.Error()})
		return
	}

	// Current password is required if not superuser
	if !isRequestingSuperuser && isSelfUpdate && req.CurrentPassword == "" {
		log.Warnf("User '%s' attempted to change their password without providing current password", requestingUser)
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "Current password is required"})
		return
	}

	// Change the password
	err := auth.ChangeUserPassword(targetUser, req.CurrentPassword, req.NewPassword, isRequestingSuperuser)
	if err != nil {
		// Handle specific error cases
		if err.Error() == fmt.Sprintf("user '%s' not found", targetUser) {
			log.Infof("User '%s' attempted to change password for non-existent user '%s'", requestingUser, targetUser)
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: err.Error()})
			return
		} else if err.Error() == "current password is incorrect" {
			log.Warnf("User '%s' provided incorrect current password while changing password", requestingUser)
			c.JSON(http.StatusUnauthorized, models.ErrorResponse{Error: err.Error()})
			return
		}

		log.Errorf("Failed to change password for user '%s': %v", targetUser, err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "Failed to change password: " + err.Error()})
		return
	}

	log.Infof("User '%s' successfully changed password for user '%s'", requestingUser, targetUser)
	c.JSON(http.StatusOK, models.GenericSuccessResponse{Message: "Password changed successfully"})
}

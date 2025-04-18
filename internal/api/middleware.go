package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/srl-labs/clab-api-server/internal/auth"
	"github.com/srl-labs/clab-api-server/internal/models"
)

// AuthMiddleware validates the JWT token from the Authorization header
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.ErrorResponse{Error: "Authorization header required"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.ErrorResponse{Error: "Authorization header format must be Bearer {token}"})
			return
		}

		tokenString := parts[1]
		claims, err := auth.ValidateJWT(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.ErrorResponse{Error: "Invalid or expired token"})
			return
		}

		// Store username in context for handlers to use
		c.Set("username", claims.Username)
		c.Next()
	}
}

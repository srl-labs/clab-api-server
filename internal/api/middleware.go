package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/srl-labs/clab-api-server/internal/auth"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

const (
	authClaimsContextKey       = "authClaims"
	verifiedLabOwnerContextKey = "verifiedLabOwner"
)

// CORSMiddleware enables browser access for configured origins.
// Origins are matched exactly against CORS_ALLOWED_ORIGINS, unless "*" is set.
func CORSMiddleware() gin.HandlerFunc {
	allowedOrigins := map[string]struct{}{}
	allowAllOrigins := false
	for _, origin := range strings.Split(config.AppConfig.CORSAllowedOrigins, ",") {
		trimmed := strings.TrimSpace(origin)
		if trimmed == "" {
			continue
		}
		if trimmed == "*" {
			allowAllOrigins = true
			continue
		}
		allowedOrigins[trimmed] = struct{}{}
	}

	return func(c *gin.Context) {
		origin := strings.TrimSpace(c.GetHeader("Origin"))
		if origin == "" {
			c.Next()
			return
		}

		allowed := allowAllOrigins
		if !allowed {
			_, allowed = allowedOrigins[origin]
		}
		if !allowed {
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.Next()
			return
		}

		header := c.Writer.Header()
		if allowAllOrigins {
			header.Set("Access-Control-Allow-Origin", "*")
		} else {
			header.Set("Vary", "Origin")
			header.Set("Access-Control-Allow-Origin", origin)
		}
		header.Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD")
		header.Set("Access-Control-Allow-Headers", "Authorization,Content-Type,Accept")
		header.Set("Access-Control-Expose-Headers", "Content-Type")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

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
		c.Set(authClaimsContextKey, claims)
		c.Next()
	}
}

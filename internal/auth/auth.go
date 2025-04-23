// internal/auth/auth.go
package auth

import (
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/srl-labs/clab-api-server/internal/config"
)

// Global server start time used to invalidate tokens after restart
var (
	serverStartTime time.Time
	startTimeMutex  sync.RWMutex
)

// InitAuth initializes the auth package with the current server start time
func InitAuth() {
	startTimeMutex.Lock()
	serverStartTime = time.Now()
	startTimeMutex.Unlock()
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// GenerateJWT creates a new JWT for a given username
func GenerateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(config.AppConfig.JWTExpiration)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.AppConfig.JWTSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateJWT checks the validity of a JWT string
func ValidateJWT(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.AppConfig.JWTSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Add explicit expiration check to guarantee time validation
	if claims.ExpiresAt != nil {
		now := time.Now()
		if now.After(claims.ExpiresAt.Time) {
			return nil, fmt.Errorf("token has expired")
		}
	}

	// Check if token was issued before the server started (server restarted since token was issued)
	startTimeMutex.RLock()
	serverStart := serverStartTime
	startTimeMutex.RUnlock()

	if claims.IssuedAt != nil && claims.IssuedAt.Time.Before(serverStart) {
		return nil, fmt.Errorf("token invalidated by server restart")
	}

	return claims, nil
}

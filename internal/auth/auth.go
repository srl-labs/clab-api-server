// internal/auth/auth.go
package auth

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
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
	// JWT NumericDate values have one-second precision. Truncating the server
	// start time avoids rejecting tokens issued later in this same second.
	serverStartTime = time.Now().Truncate(time.Second)
	startTimeMutex.Unlock()
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

var loginDurationPattern = regexp.MustCompile(`(?i)(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h|d|w)`)

// ResolveLoginDuration validates an optional login duration string and returns the
// effective JWT lifetime for the newly issued token.
func ResolveLoginDuration(requested string, defaultDuration time.Duration) (time.Duration, error) {
	trimmed := strings.TrimSpace(requested)
	if trimmed == "" {
		return defaultDuration, nil
	}

	normalized, err := normalizeLoginDuration(trimmed)
	if err != nil {
		return 0, err
	}

	duration, err := time.ParseDuration(normalized)
	if err != nil {
		return 0, fmt.Errorf("invalid session duration %q: %w", requested, err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("invalid session duration %q: duration must be greater than zero", requested)
	}

	return duration, nil
}

func normalizeLoginDuration(value string) (string, error) {
	matches := loginDurationPattern.FindAllStringSubmatchIndex(value, -1)
	if len(matches) == 0 {
		return "", fmt.Errorf("invalid session duration %q", value)
	}

	var builder strings.Builder
	pos := 0
	for _, match := range matches {
		if match[0] != pos {
			return "", fmt.Errorf("invalid session duration %q", value)
		}

		amount := value[match[2]:match[3]]
		unit := strings.ToLower(value[match[4]:match[5]])

		switch unit {
		case "d":
			scaled, err := scaleLoginDurationUnit(amount, 24)
			if err != nil {
				return "", err
			}
			builder.WriteString(scaled)
		case "w":
			scaled, err := scaleLoginDurationUnit(amount, 7*24)
			if err != nil {
				return "", err
			}
			builder.WriteString(scaled)
		default:
			builder.WriteString(amount)
			builder.WriteString(unit)
		}

		pos = match[1]
	}

	if pos != len(value) {
		return "", fmt.Errorf("invalid session duration %q", value)
	}

	return builder.String(), nil
}

func scaleLoginDurationUnit(value string, factor float64) (string, error) {
	amount, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return "", fmt.Errorf("invalid session duration value %q: %w", value, err)
	}

	return strconv.FormatFloat(amount*factor, 'f', -1, 64) + "h", nil
}

// GenerateJWT creates a new JWT for a given username and expiration duration.
func GenerateJWT(username string, expiresIn time.Duration) (string, error) {
	expirationTime := time.Now().Add(expiresIn)
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
		if token.Method != jwt.SigningMethodHS256 {
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
	if strings.TrimSpace(claims.Username) == "" {
		return nil, fmt.Errorf("token username is required")
	}
	if strings.TrimSpace(claims.Subject) == "" || claims.Subject != claims.Username {
		return nil, fmt.Errorf("token subject must match username")
	}
	if claims.ExpiresAt == nil {
		return nil, fmt.Errorf("token expiration is required")
	}
	if claims.IssuedAt == nil {
		return nil, fmt.Errorf("token issued-at time is required")
	}
	if !claims.ExpiresAt.Time.After(claims.IssuedAt.Time) {
		return nil, fmt.Errorf("token expiration must be after issued-at time")
	}

	// Add explicit expiration check to guarantee time validation
	now := time.Now()
	if now.After(claims.ExpiresAt.Time) {
		return nil, fmt.Errorf("token has expired")
	}
	if claims.IssuedAt.Time.After(now.Add(time.Minute)) {
		return nil, fmt.Errorf("token issued-at time is in the future")
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

package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/srl-labs/clab-api-server/internal/config"
)

const authTestJWTSecret = "a393f7a7f1e73ad5eaa0dc30c50e68505b57b3a104be7a1ac461c20fca8df402"

func TestResolveLoginDuration(t *testing.T) {
	t.Parallel()

	defaultDuration := 24 * time.Hour
	tests := []struct {
		name      string
		requested string
		expected  time.Duration
		expectErr bool
	}{
		{name: "defaults to configured lifetime", requested: "", expected: defaultDuration},
		{name: "supports day suffix", requested: "7d", expected: 7 * 24 * time.Hour},
		{name: "supports compound go duration", requested: "1h30m", expected: 90 * time.Minute},
		{name: "supports decimal day suffix", requested: "1.5d", expected: 36 * time.Hour},
		{name: "supports week suffix", requested: "2w", expected: 14 * 24 * time.Hour},
		{name: "rejects invalid input", requested: "forever", expectErr: true},
		{name: "rejects non-positive durations", requested: "0h", expectErr: true},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			actual, err := ResolveLoginDuration(testCase.requested, defaultDuration)
			if testCase.expectErr {
				if err == nil {
					t.Fatalf("expected an error for %q", testCase.requested)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveLoginDuration(%q) returned error: %v", testCase.requested, err)
			}
			if actual != testCase.expected {
				t.Fatalf("ResolveLoginDuration(%q) = %s, want %s", testCase.requested, actual, testCase.expected)
			}
		})
	}
}

func TestValidateJWTRequiresServerClaims(t *testing.T) {
	previousSecret := config.AppConfig.JWTSecret
	config.AppConfig.JWTSecret = authTestJWTSecret
	t.Cleanup(func() { config.AppConfig.JWTSecret = previousSecret })
	InitAuth()

	now := time.Now()
	tests := []struct {
		name   string
		claims Claims
	}{
		{
			name: "missing username",
			claims: Claims{RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "alice",
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			}},
		},
		{
			name: "subject mismatch",
			claims: Claims{Username: "alice", RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "bob",
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			}},
		},
		{
			name: "missing expiration",
			claims: Claims{Username: "alice", RegisteredClaims: jwt.RegisteredClaims{
				Subject:  "alice",
				IssuedAt: jwt.NewNumericDate(now),
			}},
		},
		{
			name: "missing issued at",
			claims: Claims{Username: "alice", RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "alice",
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			}},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, &testCase.claims)
			signed, err := token.SignedString([]byte(authTestJWTSecret))
			if err != nil {
				t.Fatalf("sign token: %v", err)
			}
			if _, err := ValidateJWT(signed); err == nil {
				t.Fatal("ValidateJWT accepted an incomplete identity token")
			}
		})
	}
}

func TestValidateJWTAcceptsGeneratedToken(t *testing.T) {
	previousSecret := config.AppConfig.JWTSecret
	config.AppConfig.JWTSecret = authTestJWTSecret
	t.Cleanup(func() { config.AppConfig.JWTSecret = previousSecret })
	InitAuth()

	token, err := GenerateJWT("alice", time.Hour)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	claims, err := ValidateJWT(token)
	if err != nil {
		t.Fatalf("ValidateJWT: %v", err)
	}
	if claims.Username != "alice" || claims.Subject != "alice" {
		t.Fatalf("unexpected validated identity: username=%q subject=%q", claims.Username, claims.Subject)
	}
}

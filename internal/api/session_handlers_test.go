package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/srl-labs/clab-api-server/internal/auth"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/models"
)

func TestGetSessionHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousSuperuserGroup := config.AppConfig.SuperuserGroup
	config.AppConfig.SuperuserGroup = ""
	t.Cleanup(func() { config.AppConfig.SuperuserGroup = previousSuperuserGroup })

	issuedAt := time.Date(2026, time.July, 9, 8, 0, 0, 0, time.UTC)
	expiresAt := issuedAt.Add(24 * time.Hour)
	claims := &auth.Claims{
		Username: "alice",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("username", claims.Username)
		c.Set(authClaimsContextKey, claims)
		c.Next()
	})
	router.GET("/session", GetSessionHandler)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/session", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /session status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	var response models.SessionResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Username != "alice" {
		t.Fatalf("username = %q, want alice", response.Username)
	}
	if !reflect.DeepEqual(response.Roles, []string{"api-user"}) {
		t.Fatalf("roles = %#v, want api-user", response.Roles)
	}
	if response.IssuedAt == nil || !response.IssuedAt.Equal(issuedAt) {
		t.Fatalf("issuedAt = %v, want %s", response.IssuedAt, issuedAt)
	}
	if response.ExpiresAt == nil || !response.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("expiresAt = %v, want %s", response.ExpiresAt, expiresAt)
	}
}

func TestGetCapabilitiesHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousRuntime := config.AppConfig.ClabRuntime
	previousVersion := apiServerVersion
	config.AppConfig.ClabRuntime = "podman"
	apiServerVersion = "v-test"
	t.Cleanup(func() {
		config.AppConfig.ClabRuntime = previousRuntime
		apiServerVersion = previousVersion
	})

	router := gin.New()
	router.GET("/capabilities", GetCapabilitiesHandler)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/capabilities", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /capabilities status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	var response models.CapabilitiesResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.APIVersion != "v1" || response.ServerVersion != "v-test" || response.Runtime != "podman" {
		t.Fatalf("unexpected capability metadata: %#v", response)
	}
	if !reflect.DeepEqual(response.Features, advertisedCapabilities) {
		t.Fatalf("features = %#v, want %#v", response.Features, advertisedCapabilities)
	}
	if !containsString(response.Features, "lab-lifecycle") {
		t.Fatalf("features = %#v, want explicit lab-lifecycle capability", response.Features)
	}
}

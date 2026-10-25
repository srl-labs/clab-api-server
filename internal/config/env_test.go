package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestEnvKeysCoverConfigFields(t *testing.T) {
	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWd)
		viper.Reset()
	})

	keys := EnvKeys()
	for _, key := range []string{"JWT_SECRET", "TLS_KEY_FILE", "TLS_CERT_FILE", "SUPERUSER_GROUP", "API_PORT", "CLAB_RUNTIME"} {
		if !slices.Contains(keys, key) {
			t.Fatalf("expected EnvKeys to include %s, got %v", key, keys)
		}
	}

	// Every key LoadConfig registers must be covered, so new settings are scrubbed too.
	viper.Reset()
	if err := LoadConfig(".env"); err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	for _, key := range viper.AllKeys() {
		if !slices.Contains(keys, strings.ToUpper(key)) {
			t.Fatalf("viper key %q is missing from EnvKeys", key)
		}
	}
}

func TestScrubProcessEnvRemovesConfigAndKeepsValues(t *testing.T) {
	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWd)
		viper.Reset()
	})

	t.Setenv("JWT_SECRET", "env-secret")
	t.Setenv("JWT_EXPIRATION", "90m")
	t.Setenv("TLS_KEY_FILE", "/etc/clab-api/server.key")
	t.Setenv("API_PORT", "9443")
	t.Setenv("SUPERUSER_GROUP", "lab-admins")
	t.Setenv("CLAB_RUNTIME", "podman")
	t.Setenv("PATH", "/usr/local/bin:/usr/bin:/bin")
	t.Setenv("HOME", "/root")
	t.Setenv("HTTPS_PROXY", "http://proxy.example:3128")
	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	t.Setenv("CLAB_LABDIR_BASE", "/srv/labs")

	viper.Reset()
	if err := LoadConfig(".env"); err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	removed := ScrubProcessEnv()
	for _, key := range []string{"JWT_SECRET", "JWT_EXPIRATION", "TLS_KEY_FILE", "API_PORT", "SUPERUSER_GROUP"} {
		if !slices.Contains(removed, key) {
			t.Fatalf("expected %s to be reported as removed, got %v", key, removed)
		}
		if value, ok := os.LookupEnv(key); ok {
			t.Fatalf("expected %s to be removed from the environment, still set to %q", key, value)
		}
	}
	if got := os.ExpandEnv("${JWT_SECRET}"); got != "" {
		t.Fatalf("expected ${JWT_SECRET} to expand to nothing, got %q", got)
	}

	for key, want := range map[string]string{
		"CLAB_RUNTIME":     "podman",
		"PATH":             "/usr/local/bin:/usr/bin:/bin",
		"HOME":             "/root",
		"HTTPS_PROXY":      "http://proxy.example:3128",
		"DOCKER_HOST":      "unix:///var/run/docker.sock",
		"CLAB_LABDIR_BASE": "/srv/labs",
	} {
		if got := os.Getenv(key); got != want {
			t.Fatalf("expected %s to stay %q, got %q", key, want, got)
		}
	}

	if AppConfig.JWTSecret != "env-secret" {
		t.Fatalf("expected AppConfig.JWTSecret to survive scrubbing, got %q", AppConfig.JWTSecret)
	}
	if AppConfig.JWTExpiration != 90*time.Minute {
		t.Fatalf("expected AppConfig.JWTExpiration to survive scrubbing, got %s", AppConfig.JWTExpiration)
	}
	if AppConfig.TLSKeyFile != "/etc/clab-api/server.key" {
		t.Fatalf("expected AppConfig.TLSKeyFile to survive scrubbing, got %q", AppConfig.TLSKeyFile)
	}
	if got := viper.GetString("JWT_SECRET"); got != "env-secret" {
		t.Fatalf("expected viper JWT_SECRET to survive scrubbing, got %q", got)
	}
	if got := viper.GetDuration("JWT_EXPIRATION"); got != 90*time.Minute {
		t.Fatalf("expected viper JWT_EXPIRATION to survive scrubbing, got %s", got)
	}
	if got := viper.GetInt("API_PORT"); got != 9443 {
		t.Fatalf("expected viper API_PORT to survive scrubbing, got %d", got)
	}
}

func TestEnvFileValuesStayOutOfProcessEnv(t *testing.T) {
	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWd)
		viper.Reset()
	})

	// Make sure the variables start unset and are restored afterwards.
	t.Setenv("JWT_SECRET", "")
	t.Setenv("TLS_CERT_FILE", "")
	_ = os.Unsetenv("JWT_SECRET")
	_ = os.Unsetenv("TLS_CERT_FILE")

	envFile := filepath.Join(dir, "server.env")
	content := "JWT_SECRET=file-secret\nTLS_CERT_FILE=/etc/clab-api/server.crt\n"
	if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	viper.Reset()
	if err := LoadConfig(envFile); err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	if AppConfig.JWTSecret != "file-secret" {
		t.Fatalf("expected JWT_SECRET from env file, got %q", AppConfig.JWTSecret)
	}

	ScrubProcessEnv()
	for _, key := range []string{"JWT_SECRET", "TLS_CERT_FILE"} {
		if value, ok := os.LookupEnv(key); ok {
			t.Fatalf("expected %s from the env file to stay out of the environment, got %q", key, value)
		}
	}
	if got := viper.GetString("JWT_SECRET"); got != "file-secret" {
		t.Fatalf("expected viper JWT_SECRET to keep the env file value, got %q", got)
	}
}

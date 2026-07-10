package config

import (
	"os"
	"testing"

	"github.com/spf13/viper"
	termsvc "github.com/srl-labs/clab-api-server/internal/terminal"
)

const testJWTSecret = "5a5f88ca4de14cc9b5d34dd2760ea32b2cdced5b0fa97a9faeeb737f4098dbdb"

func useTestJWTSecret(t *testing.T) {
	t.Helper()
	t.Setenv("JWT_SECRET", testJWTSecret)
}

func TestLoadConfigDefaultsEnableTLSAutoCert(t *testing.T) {
	useTestJWTSecret(t)
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

	viper.Reset()
	if err := LoadConfig(".env"); err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if AppConfig.APIPort != "8090" {
		t.Fatalf("expected API_PORT default to be 8090, got %q", AppConfig.APIPort)
	}
	if AppConfig.APIListenAddress != "127.0.0.1" {
		t.Fatalf("expected API_LISTEN_ADDRESS default to be 127.0.0.1, got %q", AppConfig.APIListenAddress)
	}
	if AppConfig.APIUserGroup != "clab_api" || AppConfig.SuperuserGroup != "clab_admins" {
		t.Fatalf("unexpected default access groups: API=%q superuser=%q", AppConfig.APIUserGroup, AppConfig.SuperuserGroup)
	}
	if !AppConfig.TLSEnable {
		t.Fatal("expected TLS_ENABLE default to be true")
	}
	if !AppConfig.TLSAutoCert {
		t.Fatal("expected TLS_AUTO_CERT default to be true")
	}
	if AppConfig.TerminalMaxSessionsPerUser != termsvc.DefaultMaxSessionsPerUser {
		t.Fatalf(
			"expected TERMINAL_MAX_SESSIONS_PER_USER default to be %d, got %d",
			termsvc.DefaultMaxSessionsPerUser,
			AppConfig.TerminalMaxSessionsPerUser,
		)
	}
	if AppConfig.ClabLabsRoot != "" {
		t.Fatalf("expected CLAB_LABS_ROOT default to be empty, got %q", AppConfig.ClabLabsRoot)
	}
}

func TestLoadConfigListenAddressOverride(t *testing.T) {
	useTestJWTSecret(t)
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

	t.Setenv("API_LISTEN_ADDRESS", "::1")
	viper.Reset()
	if err := LoadConfig(".env"); err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if AppConfig.APIListenAddress != "::1" {
		t.Fatalf("expected API_LISTEN_ADDRESS to be ::1, got %q", AppConfig.APIListenAddress)
	}
}

func TestLoadConfigRejectsBlankListenAddress(t *testing.T) {
	useTestJWTSecret(t)
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

	t.Setenv("API_LISTEN_ADDRESS", "   ")
	viper.Reset()
	if err := LoadConfig(".env"); err == nil {
		t.Fatal("LoadConfig accepted a blank API_LISTEN_ADDRESS")
	}
}

func TestLoadConfigTerminalMaxSessionsPerUserOverride(t *testing.T) {
	useTestJWTSecret(t)
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

	t.Setenv("TERMINAL_MAX_SESSIONS_PER_USER", "150")
	viper.Reset()
	if err := LoadConfig(".env"); err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if AppConfig.TerminalMaxSessionsPerUser != 150 {
		t.Fatalf("expected TERMINAL_MAX_SESSIONS_PER_USER to be 150, got %d", AppConfig.TerminalMaxSessionsPerUser)
	}
}

func TestLoadConfigClabLabsRootOverride(t *testing.T) {
	useTestJWTSecret(t)
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

	t.Setenv("CLAB_LABS_ROOT", "/tmp/containerlab-labs/../containerlab-labs")
	viper.Reset()
	if err := LoadConfig(".env"); err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if AppConfig.ClabLabsRoot != "/tmp/containerlab-labs" {
		t.Fatalf("expected CLAB_LABS_ROOT to be cleaned, got %q", AppConfig.ClabLabsRoot)
	}
}

func TestLoadConfigRejectsRelativeClabLabsRoot(t *testing.T) {
	useTestJWTSecret(t)
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

	t.Setenv("CLAB_LABS_ROOT", "relative/labs")
	viper.Reset()
	if err := LoadConfig(".env"); err == nil {
		t.Fatal("expected LoadConfig to reject relative CLAB_LABS_ROOT")
	}
}

func TestLoadConfigRejectsTildeClabLabsRoot(t *testing.T) {
	useTestJWTSecret(t)
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

	t.Setenv("CLAB_LABS_ROOT", "~/labs")
	viper.Reset()
	if err := LoadConfig(".env"); err == nil {
		t.Fatal("expected LoadConfig to reject tilde CLAB_LABS_ROOT")
	}
}

func TestValidateJWTSecret(t *testing.T) {
	tests := []struct {
		name    string
		secret  string
		wantErr bool
	}{
		{name: "secure", secret: testJWTSecret},
		{name: "blank", secret: "   ", wantErr: true},
		{name: "short", secret: "too-short", wantErr: true},
		{name: "code default", secret: "default_secret_change_me", wantErr: true},
		{name: "example placeholder", secret: "a_very_secret_key_change_me_please", wantErr: true},
		{name: "long placeholder", secret: "please-change-me-before-production-1234567890", wantErr: true},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			err := ValidateJWTSecret(testCase.secret)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("ValidateJWTSecret() error = %v, wantErr=%t", err, testCase.wantErr)
			}
		})
	}
}

func TestLoadConfigRejectsPlaceholderJWTSecret(t *testing.T) {
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

	t.Setenv("JWT_SECRET", "a_very_secret_key_change_me_please")
	viper.Reset()
	if err := LoadConfig(".env"); err == nil {
		t.Fatal("LoadConfig accepted a placeholder JWT_SECRET")
	}
}

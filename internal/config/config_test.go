package config

import (
	"os"
	"testing"

	"github.com/spf13/viper"
	termsvc "github.com/srl-labs/clab-api-server/internal/terminal"
)

func TestLoadConfigDefaultsEnableTLSAutoCert(t *testing.T) {
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
	if AppConfig.ClabHostsFile != "" {
		t.Fatalf("expected CLAB_HOSTS_FILE default to be empty, got %q", AppConfig.ClabHostsFile)
	}
}

func TestLoadConfigTerminalMaxSessionsPerUserOverride(t *testing.T) {
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

func TestLoadConfigClabHostsFileOverride(t *testing.T) {
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

	t.Setenv("CLAB_HOSTS_FILE", "/proc/1/root/etc/../etc/hosts")
	viper.Reset()
	if err := LoadConfig(".env"); err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if AppConfig.ClabHostsFile != "/proc/1/root/etc/hosts" {
		t.Fatalf("expected CLAB_HOSTS_FILE to be cleaned, got %q", AppConfig.ClabHostsFile)
	}
}

func TestLoadConfigRejectsRelativeClabHostsFile(t *testing.T) {
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

	t.Setenv("CLAB_HOSTS_FILE", "relative/hosts")
	viper.Reset()
	if err := LoadConfig(".env"); err == nil {
		t.Fatal("expected LoadConfig to reject relative CLAB_HOSTS_FILE")
	}
}

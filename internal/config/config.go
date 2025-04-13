// internal/config/config.go
package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	APIPort              string        `mapstructure:"API_PORT"`
	JWTSecret            string        `mapstructure:"JWT_SECRET"`
	JWTExpirationMinutes time.Duration `mapstructure:"JWT_EXPIRATION_MINUTES"`
	SuperuserGroup       string        `mapstructure:"SUPERUSER_GROUP"`
	ClabRuntime          string        `mapstructure:"CLAB_RUNTIME"`
	LogLevel             string        `mapstructure:"LOG_LEVEL"`
	// --- New TLS Fields ---
	TLSEnable   bool   `mapstructure:"TLS_ENABLE"`
	TLSCertFile string `mapstructure:"TLS_CERT_FILE"`
	TLSKeyFile  string `mapstructure:"TLS_KEY_FILE"`
	// ----------------------
}

var AppConfig Config

func LoadConfig() error {
	viper.SetConfigFile(".env") // Look for .env file
	viper.AutomaticEnv()        // Read from environment variables as fallback/override

	// --- Set Defaults ---
	viper.SetDefault("API_PORT", "8080")
	viper.SetDefault("JWT_SECRET", "default_secret_change_me")
	viper.SetDefault("JWT_EXPIRATION_MINUTES", 60)
	viper.SetDefault("SUPERUSER_GROUP", "")
	viper.SetDefault("CLAB_RUNTIME", "docker")
	viper.SetDefault("LOG_LEVEL", "info")
	// --- New TLS Defaults ---
	viper.SetDefault("TLS_ENABLE", false) // Disabled by default
	viper.SetDefault("TLS_CERT_FILE", "") // No default paths
	viper.SetDefault("TLS_KEY_FILE", "")
	// ------------------------

	err := viper.ReadInConfig()
	// Ignore if .env file not found, rely on defaults/env vars
	if _, ok := err.(viper.ConfigFileNotFoundError); !ok && err != nil {
		return err
	}

	err = viper.Unmarshal(&AppConfig)
	if err != nil {
		return err
	}

	// Convert minutes to duration
	AppConfig.JWTExpirationMinutes = AppConfig.JWTExpirationMinutes * time.Minute

	return nil
}

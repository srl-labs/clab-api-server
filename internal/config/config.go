package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	APIPort             string        `mapstructure:"API_PORT"`
	JWTSecret           string        `mapstructure:"JWT_SECRET"`
	JWTExpirationMinutes time.Duration `mapstructure:"JWT_EXPIRATION_MINUTES"`
}

var AppConfig Config

func LoadConfig() error {
	viper.SetConfigFile(".env") // Look for .env file
	viper.AutomaticEnv()        // Read from environment variables as fallback/override

	viper.SetDefault("API_PORT", "8080")
	viper.SetDefault("JWT_SECRET", "default_secret_change_me")
	viper.SetDefault("JWT_EXPIRATION_MINUTES", 60)

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
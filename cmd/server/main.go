// cmd/server/main.go
package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"

	// Adjust these import paths if your module path is different
	_ "github.com/FloSch62/clab-api/docs" // swagger docs
	"github.com/FloSch62/clab-api/internal/api"
	"github.com/FloSch62/clab-api/internal/config"
)

// @title Containerlab API
// @version 1.0
// @description This is an API server to interact with Containerlab for authenticated Linux users. Runs clab commands as the API server's user. Requires PAM for authentication.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url https://swagger.io/support/
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @schemes http https

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token. Example: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

// IMPORTANT: The @BasePath /api/v1 applies to the routes documented by Swagger below *within* the /api/v1 group.
// The /login endpoint is intentionally kept separate at the root (POST /login) and is not part of this BasePath.
func main() {
	// --- Load configuration First ---
	if err := config.LoadConfig(); err != nil {
		// Use a basic logger here as the configured one isn't ready yet
		log.New(os.Stderr).Fatalf("Failed to load configuration: %v", err)
	}

	// --- Initialize Logger Based on Config ---
	log.SetOutput(os.Stderr) // Keep outputting to stderr for now
	log.SetTimeFormat("2006-01-02 15:04:05")

	// Set log level from config
	switch strings.ToLower(config.AppConfig.LogLevel) {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	default:
		log.Warnf("Invalid LOG_LEVEL '%s' specified in config, defaulting to 'info'", config.AppConfig.LogLevel)
		log.SetLevel(log.InfoLevel) // Default to info if invalid value
	}

	log.Infof("Configuration loaded successfully. Log level set to '%s'.", config.AppConfig.LogLevel) // Log this *after* setting the level

	// --- Log Loaded Configuration Details (using the configured logger) ---
	log.Debugf("API Port: %s", config.AppConfig.APIPort)
	log.Debugf("JWT Secret Loaded: %t", config.AppConfig.JWTSecret != "" && config.AppConfig.JWTSecret != "default_secret_change_me")
	log.Debugf("JWT Expiration: %s", config.AppConfig.JWTExpirationMinutes)
	log.Infof("Containerlab Runtime: %s", config.AppConfig.ClabRuntime)
	if config.AppConfig.JWTSecret == "default_secret_change_me" {
		log.Warn("Using default JWT secret. Change JWT_SECRET environment variable for production!")
	}

	// --- Check dependencies ---
	if _, err := exec.LookPath("clab"); err != nil {
		log.Fatalf("'clab' command not found in PATH. Please install Containerlab (containerlab.dev).")
	}
	log.Info("'clab' command found in PATH.")
	log.Warn("Ensure the user running *this API server* has permissions to interact with the configured container runtime daemon (e.g., Docker daemon via 'docker' group).")
	log.Warnf("Ensure the configured container runtime '%s' is installed and accessible.", config.AppConfig.ClabRuntime)
	log.Warn("Authentication uses PAM. Ensure the API server environment has necessary PAM libraries (e.g., libpam-dev) and configuration.")

	// --- Initialize Gin router ---
	// gin.SetMode(gin.ReleaseMode) // Uncomment for production
	router := gin.Default()

	// Setup API routes
	api.SetupRoutes(router)

	// Root handler
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message":        "Containerlab API (Sudoless Mode) is running.",
			"documentation":  "/swagger/index.html",
			"login_endpoint": "POST /login",
			"api_base_path":  "/api/v1",
			"clab_runtime":   config.AppConfig.ClabRuntime,
			"notes": []string{
				"Runs clab commands as the API server's user.",
				fmt.Sprintf("Requires %s permissions for the API server user.", config.AppConfig.ClabRuntime),
				"Uses PAM for user authentication.",
				"Labs are associated with users via Docker labels.",
			},
		})
	})

	// --- Start the server ---
	listenAddr := fmt.Sprintf(":%s", config.AppConfig.APIPort)
	log.Infof("Starting server on http://localhost%s", listenAddr)
	if err := router.Run(listenAddr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

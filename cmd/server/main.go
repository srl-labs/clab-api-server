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
	_ "github.com/srl-labs/clab-api-server/docs" // swagger docs
	"github.com/srl-labs/clab-api-server/internal/api"
	"github.com/srl-labs/clab-api-server/internal/config"
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

// @schemes http https

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token. Example: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
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
	log.Debugf("TLS Enabled: %t", config.AppConfig.TLSEnable)
	if config.AppConfig.TLSEnable {
		log.Debugf("TLS Cert File: %s", config.AppConfig.TLSCertFile)
		log.Debugf("TLS Key File: %s", config.AppConfig.TLSKeyFile)
	}
	if config.AppConfig.JWTSecret == "default_secret_change_me" {
		log.Warn("Using default JWT secret. Change JWT_SECRET environment variable for production!")
	}

	// --- Check dependencies ---
	if _, err := exec.LookPath("clab"); err != nil {
		log.Fatalf("'clab' command not found in PATH. Please install Containerlab (containerlab.dev).")
	}
	log.Info("'clab' command found in PATH.")

	// --- Initialize Gin router ---
	if strings.ToLower(config.AppConfig.GinMode) == "release" {
		gin.SetMode(gin.ReleaseMode)
	} else if strings.ToLower(config.AppConfig.GinMode) == "test" {
		gin.SetMode(gin.TestMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}
	log.Infof("Gin running in '%s' mode", config.AppConfig.GinMode)

	router := gin.Default()

	// Configure trusted proxies
	if config.AppConfig.TrustedProxies == "nil" {
		// Explicitly disable proxy trust
		log.Info("Proxy trust disabled (TRUSTED_PROXIES=nil)")
		router.SetTrustedProxies(nil)
	} else if config.AppConfig.TrustedProxies != "" {
		// Set specific trusted proxies
		proxyList := strings.Split(config.AppConfig.TrustedProxies, ",")
		// Trim any whitespace
		for i, proxy := range proxyList {
			proxyList[i] = strings.TrimSpace(proxy)
		}
		log.Infof("Setting trusted proxies: %v", proxyList)
		router.SetTrustedProxies(proxyList)
	} else {
		// Default behavior (trust all) - just log a warning
		log.Warn("All proxies are trusted (default). Set TRUSTED_PROXIES=nil to disable proxy trust or provide a comma-separated list of trusted proxy IPs.")
	}

	// Setup API routes
	api.SetupRoutes(router)

	// Root handler - CORRECTED login_endpoint path
	router.GET("/", func(c *gin.Context) {
		// Determine protocol based on config OR request header if behind trusted proxy
		protocol := "http"
		if config.AppConfig.TLSEnable {
			protocol = "https"
		} else if c.Request.Header.Get("X-Forwarded-Proto") == "https" {
			// If behind a trusted proxy that terminates TLS
			protocol = "https"
		}

		// Use the Host from the request header
		host := c.Request.Host // This includes hostname:port

		// Construct baseURL dynamically
		baseURL := fmt.Sprintf("%s://%s", protocol, host)

		c.JSON(http.StatusOK, gin.H{
			"message":        fmt.Sprintf("Containerlab API (Sudoless Mode) is running (%s).", protocol),
			"documentation":  fmt.Sprintf("%s/swagger/index.html", baseURL), // Dynamic URL
			"login_endpoint": fmt.Sprintf("POST %s/login", baseURL),
			"api_base_path":  fmt.Sprintf("%s/api/v1", baseURL), // Dynamic URL - This describes the base for *other* API calls
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
	serverBaseURL := fmt.Sprintf("http://localhost:%s", config.AppConfig.APIPort) // Base for logging start message
	if config.AppConfig.TLSEnable {
		serverBaseURL = fmt.Sprintf("https://localhost:%s", config.AppConfig.APIPort)
	}

	if config.AppConfig.TLSEnable {
		// Start HTTPS server
		log.Infof("Starting HTTPS server, accessible locally at %s (and potentially other IPs)", serverBaseURL)
		if config.AppConfig.TLSCertFile == "" || config.AppConfig.TLSKeyFile == "" {
			log.Fatalf("TLS is enabled but TLS_CERT_FILE or TLS_KEY_FILE is not set in config.")
		}
		// Check if files exist (optional but good practice)
		if _, err := os.Stat(config.AppConfig.TLSCertFile); os.IsNotExist(err) {
			log.Fatalf("TLS cert file not found: %s", config.AppConfig.TLSCertFile)
		}
		if _, err := os.Stat(config.AppConfig.TLSKeyFile); os.IsNotExist(err) {
			log.Fatalf("TLS key file not found: %s", config.AppConfig.TLSKeyFile)
		}

		if err := router.RunTLS(listenAddr, config.AppConfig.TLSCertFile, config.AppConfig.TLSKeyFile); err != nil {
			log.Fatalf("Failed to start HTTPS server: %v", err)
		}
	} else {
		// Start HTTP server
		log.Infof("Starting HTTP server, accessible locally at %s (and potentially other IPs)", serverBaseURL)
		if err := router.Run(listenAddr); err != nil {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}
}

// cmd/server/main.go
package main

import (
	"context" // Import context
	"errors"  // Import errors
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time" // Import time

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"

	_ "github.com/srl-labs/clab-api-server/docs"
	"github.com/srl-labs/clab-api-server/internal/api"
	"github.com/srl-labs/clab-api-server/internal/config"
)

// --- Version Info ---
var (
	version = "development"
	commit  = "none"
	date    = "unknown"
)

// --- Swagger annotations ---
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
	// --- Define and Parse Command Line Flags ---
	var showVersion bool
	var envFile string
	defaultEnvFile := ".env"

	flag.BoolVar(&showVersion, "version", false, "Print server version and exit")
	flag.BoolVar(&showVersion, "v", false, "Print server version and exit (shorthand)")
	flag.StringVar(&envFile, "env-file", defaultEnvFile, "Path to the .env configuration file")
	flag.Parse()

	// --- Handle -v/--version flag ---
	if showVersion {
		fmt.Printf("clab-api-server version: %s\n", version)
		fmt.Printf("commit: %s\n", commit)
		fmt.Printf("built: %s\n", date)
		os.Exit(0)
	}

	// --- Load configuration First ---
	basicLogger := log.New(os.Stderr)
	basicLogger.Infof("Attempting to load configuration from '%s' and environment variables...", envFile)
	err := config.LoadConfig(envFile)
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok && envFile == defaultEnvFile {
			basicLogger.Infof("Default config file '%s' not found. Using environment variables and defaults.", defaultEnvFile)
			viper.Reset()
			config.LoadConfig("") // Rely on env/defaults
		} else {
			basicLogger.Fatalf("Failed to load configuration: %v", err)
		}
	} else {
		basicLogger.Infof("Configuration file '%s' loaded successfully (or skipped if default and not found).", envFile)
	}

	// --- Initialize Logger Based on Config ---
	log.SetOutput(os.Stderr)
	log.SetTimeFormat("2006-01-02 15:04:05")
	switch strings.ToLower(config.AppConfig.LogLevel) {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	// ... other levels ...
	default:
		log.Warnf("Invalid LOG_LEVEL '%s', defaulting to 'info'", config.AppConfig.LogLevel)
		log.SetLevel(log.InfoLevel)
	}
	log.Infof("clab-api-server version %s starting...", version)
	log.Infof("Configuration processed. Log level set to '%s'.", config.AppConfig.LogLevel)
	// ... log other config details ...
	if config.AppConfig.JWTSecret == "default_secret_change_me" {
		log.Warn("Using default JWT secret. Change JWT_SECRET environment variable or .env file for production!")
	}

	// --- Check dependencies ---
	if _, err := exec.LookPath("clab"); err != nil {
		log.Fatalf("'clab' command not found in PATH. Please install Containerlab (containerlab.dev).")
	}
	log.Info("'clab' command found in PATH.")

	// --- Initialize SSH Manager ---
	log.Info("Initializing SSH Session Manager...")
	api.InitSSHManager() // Initialize before setting up routes

	// --- Initialize Gin router ---
	if strings.ToLower(config.AppConfig.GinMode) == "release" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode) // Default to debug
	}
	log.Infof("Gin running in '%s' mode", gin.Mode())
	router := gin.Default() // Use Default for logging and recovery middleware

	// Configure trusted proxies
	// ... (proxy configuration logic remains the same) ...
	if config.AppConfig.TrustedProxies == "nil" {
		log.Info("Proxy trust disabled (TRUSTED_PROXIES=nil)")
		_ = router.SetTrustedProxies(nil)
	} else if config.AppConfig.TrustedProxies != "" {
		proxyList := strings.Split(config.AppConfig.TrustedProxies, ",")
		for i, proxy := range proxyList {
			proxyList[i] = strings.TrimSpace(proxy)
		}
		log.Infof("Setting trusted proxies: %v", proxyList)
		if err := router.SetTrustedProxies(proxyList); err != nil {
			log.Warnf("Error setting trusted proxies: %v. Using default.", err)
		}
	} else {
		log.Warn("All proxies are trusted (default). Set TRUSTED_PROXIES=nil or provide a list.")
	}

	// Setup API routes
	api.SetupRoutes(router)

	// Root handler (remains the same)
	router.GET("/", func(c *gin.Context) {
		// ... root handler logic ...
		protocol := "http"
		if config.AppConfig.TLSEnable {
			protocol = "https"
		} else if c.Request.Header.Get("X-Forwarded-Proto") == "https" {
			protocol = "https"
		}

		host := c.Request.Host
		baseURL := fmt.Sprintf("%s://%s", protocol, host)

		c.JSON(http.StatusOK, gin.H{
			"message":        fmt.Sprintf("Containerlab API Server (Version: %s) is running (%s).", version, protocol),
			"documentation":  fmt.Sprintf("%s/swagger/index.html", baseURL),
			"login_endpoint": fmt.Sprintf("POST %s/login", baseURL),
			"api_base_path":  fmt.Sprintf("%s/api/v1", baseURL),
			"clab_runtime":   config.AppConfig.ClabRuntime,
			"notes": []string{
				"Runs clab commands as the API server's user.",
				fmt.Sprintf("Requires %s permissions for the API server user.", config.AppConfig.ClabRuntime),
				"Uses PAM for user authentication.",
				"Labs are associated with users via Docker labels.",
			},
		})
	})

	// --- Prepare Server Configuration ---
	listenAddr := fmt.Sprintf(":%s", config.AppConfig.APIPort)                    // Define ONCE here
	serverBaseURL := fmt.Sprintf("http://localhost:%s", config.AppConfig.APIPort) // Define ONCE here
	if config.AppConfig.TLSEnable {
		serverBaseURL = fmt.Sprintf("https://localhost:%s", config.AppConfig.APIPort) // Adjust if TLS
	}

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: router, // Use the Gin engine as the handler
		// Consider adding timeouts for production hardening:
		// ReadTimeout:  5 * time.Second,
		// WriteTimeout: 10 * time.Second,
		// IdleTimeout:  120 * time.Second,
	}

	// --- Start Server Goroutine ---
	go func() {
		protocol := "HTTP"
		if config.AppConfig.TLSEnable {
			protocol = "HTTPS"
			log.Infof("Starting %s server, accessible locally at %s (and potentially other IPs)", protocol, serverBaseURL)
			// Check TLS files before starting
			if config.AppConfig.TLSCertFile == "" || config.AppConfig.TLSKeyFile == "" {
				log.Fatalf("TLS is enabled but TLS_CERT_FILE or TLS_KEY_FILE is not set.")
			}
			if _, err := os.Stat(config.AppConfig.TLSCertFile); os.IsNotExist(err) {
				log.Fatalf("TLS cert file not found: %s", config.AppConfig.TLSCertFile)
			}
			if _, err := os.Stat(config.AppConfig.TLSKeyFile); os.IsNotExist(err) {
				log.Fatalf("TLS key file not found: %s", config.AppConfig.TLSKeyFile)
			}
			// Start HTTPS server
			if err := srv.ListenAndServeTLS(config.AppConfig.TLSCertFile, config.AppConfig.TLSKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("Failed to start %s server: %v", protocol, err)
			}
		} else {
			// Start HTTP server
			log.Infof("Starting %s server, accessible locally at %s (and potentially other IPs)", protocol, serverBaseURL)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("Failed to start %s server: %v", protocol, err)
			}
		}
		log.Info("Server listener stopped.") // Will log when ListenAndServe returns
	}()

	// --- Graceful Shutdown Handling ---
	quit := make(chan os.Signal, 1)
	// Notify about common termination signals
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	// Block until a signal is received
	sig := <-quit
	log.Infof("Received signal: %s. Shutting down server...", sig)

	// Create a context with a timeout for the shutdown
	// Give outstanding requests a deadline to finish
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // Adjust timeout as needed
	defer cancel()

	// Shutdown SSH Manager (can run concurrently with server shutdown)
	go api.ShutdownSSHManager() // No need to wait for this specifically unless it's critical

	// Attempt graceful shutdown of the HTTP server
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Info("Server exiting gracefully.")
}

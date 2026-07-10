// cmd/server/main.go
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"

	_ "github.com/srl-labs/clab-api-server/docs"
	"github.com/srl-labs/clab-api-server/internal/api"
	"github.com/srl-labs/clab-api-server/internal/auth"
	"github.com/srl-labs/clab-api-server/internal/clab"
	"github.com/srl-labs/clab-api-server/internal/config"
	"github.com/srl-labs/clab-api-server/internal/templates"
	"github.com/srl-labs/clab-api-server/internal/tlsconfig"
)

// --- Version Info ---
var (
	version = "development"
	commit  = "none"
	date    = "unknown"
)

// --- Swagger annotations ---
// @title Containerlab API Server
// @version 1.0
// @description REST API for authenticated Linux users to manage Containerlab deployments, topology files, node access, captures, and host networking tools.
// @description
// @description Most endpoints under /api/v1 require a JWT from POST /login. Send it as: Authorization: Bearer <token>.
// @contact.name Containerlab API Server maintainers
// @contact.url https://github.com/srl-labs/clab-api-server/issues
// @license.name Apache 2.0
// @license.url https://www.apache.org/licenses/LICENSE-2.0.html
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

	if flag.NArg() > 0 && flag.Arg(0) == "version" {
		os.Exit(runVersionCommand(context.Background(), flag.Args()[1:], os.Stdout, os.Stderr))
	}

	// --- Load configuration First ---
	basicLogger := log.New(os.Stderr)
	basicLogger.Infof("Attempting to load configuration from '%s' and environment variables...", envFile)
	err := config.LoadConfig(envFile)
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok && envFile == defaultEnvFile {
			basicLogger.Infof("Default config file '%s' not found. Using environment variables and defaults.", defaultEnvFile)
			viper.Reset()
			if fallbackErr := config.LoadConfig(""); fallbackErr != nil {
				basicLogger.Fatalf("Failed to load configuration from environment: %v", fallbackErr)
			}
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
	default:
		log.Warnf("Invalid LOG_LEVEL '%s', defaulting to 'info'", config.AppConfig.LogLevel)
		log.SetLevel(log.InfoLevel)
	}
	log.Infof("clab-api-server version %s starting...", version)
	log.Infof("Configuration processed. Log level set to '%s'.", config.AppConfig.LogLevel)
	// --- Initialize Containerlab Service ---
	log.Info("Initializing Containerlab service (using library directly)...")
	clabService := clab.NewService()
	api.SetClabService(clabService)
	log.Infof("Containerlab service initialized with runtime: %s", config.AppConfig.ClabRuntime)

	// --- Initialize SSH Manager ---
	log.Info("Initializing SSH Session Manager...")
	api.InitSSHManager()
	log.Infof("SSH port range configured: %d - %d", config.AppConfig.SSHBasePort, config.AppConfig.SSHMaxPort)

	// --- Initialize Terminal Manager ---
	log.Info("Initializing Terminal Session Manager...")
	api.InitTerminalManager()

	// --- Initialize Capture Manager ---
	log.Info("Initializing Capture Manager...")
	api.InitCaptureManager()

	// --- Initialize Authentication ---
	log.Info("Initializing authentication...")
	auth.InitAuth() // Initialize auth with server start time

	// --- Initialize Health Monitoring ---
	log.Info("Initializing Health Monitoring...")
	api.InitHealth(version)

	// --- Initialize Gin router ---
	if strings.ToLower(config.AppConfig.GinMode) == "release" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode) // Default to debug
	}
	log.Infof("Gin running in '%s' mode", gin.Mode())
	router := gin.Default() // Use Default for logging and recovery middleware

	// Then in the router setup section:
	if err := templates.LoadTemplates(router); err != nil {
		log.Fatalf("Failed to load embedded templates: %v", err)
	}

	// Configure trusted proxies
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
	router.Use(api.CORSMiddleware())
	api.SetupRoutes(router)

	// Root handler (remains the same)
	router.GET("/", func(c *gin.Context) {
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
	listenAddr := net.JoinHostPort(config.AppConfig.APIListenAddress, config.AppConfig.APIPort)
	advertisedHost := strings.TrimSpace(config.AppConfig.APIServerHost)
	if advertisedHost == "" {
		advertisedHost = config.AppConfig.APIListenAddress
	}
	if advertisedHost == "0.0.0.0" || advertisedHost == "::" {
		advertisedHost = "localhost"
	}
	serverBaseURL := "http://" + net.JoinHostPort(advertisedHost, config.AppConfig.APIPort)
	if config.AppConfig.TLSEnable {
		serverBaseURL = "https://" + net.JoinHostPort(advertisedHost, config.AppConfig.APIPort)
	}
	tlsCertFile := config.AppConfig.TLSCertFile
	tlsKeyFile := config.AppConfig.TLSKeyFile
	if config.AppConfig.TLSEnable {
		if (tlsCertFile == "") != (tlsKeyFile == "") {
			log.Fatal("TLS is enabled but only one of TLS_CERT_FILE or TLS_KEY_FILE is set.")
		}
		if tlsCertFile == "" && tlsKeyFile == "" {
			if !config.AppConfig.TLSAutoCert {
				log.Fatal("TLS is enabled but TLS_CERT_FILE and TLS_KEY_FILE are not set, and TLS_AUTO_CERT is false.")
			}

			certPaths, err := tlsconfig.DefaultCertificatePaths("clab-api-server")
			if err != nil {
				log.Fatalf("Failed to resolve auto TLS certificate path: %v", err)
			}
			hosts := tlsconfig.DefaultServerHosts(config.AppConfig.APIServerHost)
			generated, err := tlsconfig.EnsureSelfSignedCertificate(certPaths.CertFile, certPaths.KeyFile, hosts)
			if err != nil {
				log.Fatalf("Failed to prepare auto TLS certificate: %v", err)
			}
			tlsCertFile = certPaths.CertFile
			tlsKeyFile = certPaths.KeyFile
			if generated {
				log.Warnf("Generated self-signed TLS certificate at %s. Browsers and clients must trust it or opt into insecure verification.", tlsCertFile)
			} else {
				log.Infof("Using existing auto TLS certificate at %s", tlsCertFile)
			}
		}
		if _, err := os.Stat(tlsCertFile); os.IsNotExist(err) {
			log.Fatalf("TLS cert file not found: %s", tlsCertFile)
		}
		if _, err := os.Stat(tlsKeyFile); os.IsNotExist(err) {
			log.Fatalf("TLS key file not found: %s", tlsKeyFile)
		}
		fingerprint, err := tlsconfig.CertificateFingerprint(tlsCertFile)
		if err != nil {
			log.Fatalf("Failed to read TLS certificate fingerprint: %v", err)
		}
		log.Infof("TLS certificate SHA-256 fingerprint: %s", fingerprint)
	}

	srv := &http.Server{
		Addr:      listenAddr,
		Handler:   router,
		TLSConfig: tlsconfig.LocalServerTLSConfig(),
	}

	// --- Start Server Goroutine ---
	go func() {
		protocol := "HTTP"
		if config.AppConfig.TLSEnable {
			protocol = "HTTPS"
			log.Infof("Starting %s server on %s, advertised locally at %s", protocol, listenAddr, serverBaseURL)
			// Start HTTPS server
			if err := srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("Failed to start %s server: %v", protocol, err)
			}
		} else {
			// Start HTTP server
			log.Infof("Starting %s server on %s, advertised locally at %s", protocol, listenAddr, serverBaseURL)
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
	go api.ShutdownTerminalManager()
	go api.ShutdownCaptureManager()

	// Attempt graceful shutdown of the HTTP server
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Info("Server exiting gracefully.")
}

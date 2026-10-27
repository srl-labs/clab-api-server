// internal/api/routes.go
package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "github.com/srl-labs/clab-api-server/docs"
)

// SetupRoutes defines all the API endpoints and applies middleware.
func SetupRoutes(router *gin.Engine) {
	// --- Public Routes ---

	// Health check endpoint - intentionally public, no auth required
	router.GET("/health", HealthCheckHandler)

	// Login endpoint - intentionally *not* under /api/v1 group
	router.POST("/login", LoginHandler)

	// Packetflix capture websocket of a lab runtime capture ticket: the ticket is the
	// credential, so no bearer token. cshargextcap dials <path>/capture after a target
	// discovery at <path>/discover/mobyshark.
	router.GET("/api/v1/capture/packetflix/:ticket", requireLabRuntimeCapture(), PacketflixCaptureHandler)
	router.GET("/api/v1/capture/packetflix/:ticket/capture", requireLabRuntimeCapture(), PacketflixCshargextcapHandler)
	router.GET("/api/v1/capture/packetflix/:ticket/discover/mobyshark", requireLabRuntimeCapture(), PacketflixDiscoverHandler)

	// Swagger documentation route
	// URL needs to match the basePath in your main swagger annotations
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, ginSwagger.URL("/swagger/doc.json")))

	// ReDoc documentation route - serves a more user-friendly API documentation UI
	router.GET("/redoc", func(c *gin.Context) {
		c.HTML(http.StatusOK, "redoc.html", nil)
	})

	// --- Authenticated Routes (/api/v1) ---
	apiV1 := router.Group("/api/v1")
	apiV1.Use(AuthMiddleware()) // Apply JWT authentication middleware to all /api/v1 routes
	{
		// Health metrics endpoint (superuser only)
		apiV1.GET("/health/metrics", requireContainerRuntime("host health metrics"), SystemMetricsHandler)

		// Lab host: the runtime and, on c9s, the cluster and deploy defaults
		apiV1.GET("/lab-host", LabHostHandler)

		// Events stream
		apiV1.GET("/events", StreamEventsHandler)

		images := apiV1.Group("/images", requireContainerRuntime("image management"))
		{
			images.GET("", ListRuntimeImagesHandler)
			images.POST("/pull", PullRuntimeImageHandler)
			images.DELETE("", RemoveRuntimeImageHandler)
		}

		ui := apiV1.Group("/ui")
		{
			ui.GET("/custom-nodes", GetCustomNodesHandler)
			ui.PUT("/custom-nodes", PutCustomNodesHandler)
			ui.POST("/custom-nodes", SaveCustomNodeHandler)
			ui.DELETE("/custom-nodes/:name", DeleteCustomNodeHandler)
			ui.POST("/custom-nodes/default", SetDefaultCustomNodeHandler)

			ui.GET("/icons", ListGlobalIconsHandler)
			ui.POST("/icons", UploadGlobalIconHandler)
			ui.DELETE("/icons/:iconName", DeleteGlobalIconHandler)
		}

		// Lab management routes
		labs := apiV1.Group("/labs")
		{
			// Deploy new lab (JSON/URL method)
			labs.POST("", DeployLabHandler) // POST /api/v1/labs

			// Deploy new lab (Archive method)
			labs.POST("/archive", DeployLabArchiveHandler) // POST /api/v1/labs/archive

			// List labs for user (or all if superuser)
			labs.GET("", ListLabsHandler) // GET /api/v1/labs

			// List editable topology files exposed from the user's lab directory
			// Must be registered before /:labName routes.
			labs.GET("/topology/files", ListTopologiesHandler) // GET /api/v1/labs/topology/files
			labs.POST("/topology/import-from-url", ImportTopologyFromURLHandler)

			// File explorer operations scoped to the authenticated user's lab workspace root.
			labs.GET("/workspace/events", StreamWorkspaceEventsHandler)
			labs.GET("/workspace/tree", ListWorkspaceTreeHandler)           // GET /api/v1/labs/workspace/tree?path=...
			labs.GET("/workspace/file", GetWorkspaceFileHandler)            // GET /api/v1/labs/workspace/file?path=...
			labs.PUT("/workspace/file", PutWorkspaceFileHandler)            // PUT /api/v1/labs/workspace/file?path=...
			labs.DELETE("/workspace/file", DeleteWorkspaceFileHandler)      // DELETE /api/v1/labs/workspace/file?path=...
			labs.POST("/workspace/file/rename", RenameWorkspaceFileHandler) // POST /api/v1/labs/workspace/file/rename
			labs.POST("/workspace/directory", CreateWorkspaceDirectoryHandler)

			// Actions on a specific lab by name
			labSpecific := labs.Group("/:labName")
			{
				// Inspect lab details
				labSpecific.GET("", InspectLabHandler) // GET /api/v1/labs/{labName}

				// Destroy lab
				labSpecific.DELETE("", DestroyLabHandler) // DELETE /api/v1/labs/{labName}

				// Redeploy lab
				labSpecific.PUT("", RedeployLabHandler) // PUT /api/v1/labs/{labName}

				// Deploy on-disk topology file for this lab name
				labSpecific.POST("/deploy", DeployTopologyHandler) // POST /api/v1/labs/{labName}/deploy

				// Apply on-disk topology file for this lab name
				labSpecific.POST("/apply", ApplyTopologyHandler) // POST /api/v1/labs/{labName}/apply

				// Validate on-disk topology file for this lab name
				labSpecific.POST("/validate", ValidateTopologyHandler) // POST /api/v1/labs/{labName}/validate

				// Topology-aware lab node lifecycle actions
				labSpecific.POST("/start", StartLabNodesHandler)     // POST /api/v1/labs/{labName}/start
				labSpecific.POST("/stop", StopLabNodesHandler)       // POST /api/v1/labs/{labName}/stop
				labSpecific.POST("/restart", RestartLabNodesHandler) // POST /api/v1/labs/{labName}/restart

				// Inspect lab interfaces
				labSpecific.GET("/interfaces", requireContainerRuntime("interface inspection"), InspectInterfacesHandler) // GET /api/v1/labs/{labName}/interfaces
				labSpecific.GET("/links", requireContainerRuntime("link inspection"), ListLabLinksHandler)                // GET /api/v1/labs/{labName}/links

				// Stream CPU and memory usage of the lab's nodes
				labSpecific.GET("/stats", StreamLabStatsHandler) // GET /api/v1/labs/{labName}/stats

				// Save lab config
				labSpecific.POST("/save", SaveLabConfigHandler) // POST /api/v1/labs/{labName}/save

				// Save VM snapshots of vrnetlab nodes
				labSpecific.POST("/snapshots", requireContainerRuntime("VM snapshots"), SaveLabSnapshotsHandler) // POST /api/v1/labs/{labName}/snapshots

				// Capture
				labSpecific.POST("/capture/packetflix", requireContainerRuntime("Edgeshark packet capture"), BuildPacketflixCaptureHandler) // POST /api/v1/labs/{labName}/capture/packetflix
				labSpecific.POST("/capture/wireshark-vnc-sessions", requireWiresharkVnc(), CreateWiresharkVncSessionsHandler)               // POST /api/v1/labs/{labName}/capture/wireshark-vnc-sessions
				// Lab runtime (c9s) capture through clabwire
				labSpecific.GET("/capture/interfaces", requireLabRuntimeCapture(), ListCaptureInterfacesHandler) // GET /api/v1/labs/{labName}/capture/interfaces
				labSpecific.GET("/capture/stream", requireLabRuntimeCapture(), StreamCaptureHandler)             // GET /api/v1/labs/{labName}/capture/stream
				labSpecific.POST("/capture/tickets", requireLabRuntimeCapture(), CreateCaptureTicketHandler)     // POST /api/v1/labs/{labName}/capture/tickets

				// Sharing + tools
				labSpecific.POST("/sshx/:action", requireContainerRuntime("SSHX sharing"), LabSSHXShareHandler)    // POST /api/v1/labs/{labName}/sshx/{action}
				labSpecific.POST("/gotty/:action", requireContainerRuntime("GoTTY sharing"), LabGoTTYShareHandler) // POST /api/v1/labs/{labName}/gotty/{action}
				labSpecific.POST("/fcli", requireContainerRuntime("fcli"), RunLabFcliHandler)                      // POST /api/v1/labs/{labName}/fcli
				labSpecific.POST("/graph/drawio", GenerateLabDrawioHandler)
				labSpecific.POST("/graph/mermaid", GenerateLabMermaidHandler)
				labSpecific.POST("/graph/dot", GenerateLabDotHandler)
				labSpecific.GET("/tailscale", requireContainerRuntime("Tailscale status"), GetLabTailscaleStatusHandler) // GET /api/v1/labs/{labName}/tailscale

				// Execute command in lab
				labSpecific.POST("/exec", ExecCommandHandler) // POST /api/v1/labs/{labName}/exec

				// Read/write topology source documents for this lab.
				// For deployed labs these target the running topology source path first.
				labSpecific.GET("/topology/yaml", GetRunningLabYamlHandler)               // GET /api/v1/labs/{labName}/topology/yaml
				labSpecific.PUT("/topology/yaml", PutRunningLabYamlHandler)               // PUT /api/v1/labs/{labName}/topology/yaml
				labSpecific.GET("/topology/annotations", GetRunningLabAnnotationsHandler) // GET /api/v1/labs/{labName}/topology/annotations
				labSpecific.PUT("/topology/annotations", PutRunningLabAnnotationsHandler) // PUT /api/v1/labs/{labName}/topology/annotations
				labSpecific.GET("/topology/events", StreamTopologyFileEventsHandler)      // GET /api/v1/labs/{labName}/topology/events?path=...
				labSpecific.GET("/topology/file", GetTopologyFileHandler)                 // GET /api/v1/labs/{labName}/topology/file?path=...
				labSpecific.GET("/topology/rendered", RenderTopologyHandler)              // GET /api/v1/labs/{labName}/topology/rendered?path=...&varsPath=...
				labSpecific.HEAD("/topology/file", HeadTopologyFileHandler)               // HEAD /api/v1/labs/{labName}/topology/file?path=...
				labSpecific.PUT("/topology/file", PutTopologyFileHandler)                 // PUT /api/v1/labs/{labName}/topology/file?path=...
				labSpecific.DELETE("/topology/file", DeleteTopologyFileHandler)           // DELETE /api/v1/labs/{labName}/topology/file?path=...
				labSpecific.POST("/topology/file/rename", RenameTopologyFileHandler)      // POST /api/v1/labs/{labName}/topology/file/rename
				labSpecific.GET("/ui/icons", ListLabIconsHandler)                         // GET /api/v1/labs/{labName}/ui/icons
				labSpecific.POST("/ui/icons/reconcile", ReconcileLabIconsHandler)         // POST /api/v1/labs/{labName}/ui/icons/reconcile

				// Node Specific Routes (nested under lab)
				nodeSpecific := labSpecific.Group("/nodes/:nodeName")
				{
					// Request SSH Access to a specific node
					nodeSpecific.POST("/ssh", RequestSSHAccessHandler) // POST /api/v1/labs/{labName}/nodes/{nodeName}/ssh

					// Create interactive terminal session for a specific node
					nodeSpecific.POST("/terminal-sessions", RequestTerminalSessionHandler) // POST /api/v1/labs/{labName}/nodes/{nodeName}/terminal-sessions

					// Logs
					nodeSpecific.GET("/logs", GetNodeLogsHandler) // GET /api/v1/labs/{labName}/nodes/{nodeName}/logs

					// Lifecycle actions
					nodeSpecific.POST("/start", StartNodeHandler)                                               // POST /api/v1/labs/{labName}/nodes/{nodeName}/start
					nodeSpecific.POST("/stop", StopNodeHandler)                                                 // POST /api/v1/labs/{labName}/nodes/{nodeName}/stop
					nodeSpecific.POST("/restart", RestartNodeHandler)                                           // POST /api/v1/labs/{labName}/nodes/{nodeName}/restart
					nodeSpecific.POST("/pause", requireContainerRuntime("pausing nodes"), PauseNodeHandler)     // POST /api/v1/labs/{labName}/nodes/{nodeName}/pause
					nodeSpecific.POST("/unpause", requireContainerRuntime("pausing nodes"), UnpauseNodeHandler) // POST /api/v1/labs/{labName}/nodes/{nodeName}/unpause

					// Browser helper
					nodeSpecific.GET("/browser-ports", GetNodeBrowserPortsHandler)
					// HTTP proxy to a node port (lab runtimes)
					nodeSpecific.Any("/ports/:port/proxy/*proxyPath", ProxyNodePortHandler)
				}
			}
		}

		terminals := apiV1.Group("/terminal-sessions")
		{
			terminals.GET("/:sessionId", GetTerminalSessionHandler)           // GET /api/v1/terminal-sessions/{sessionId}
			terminals.DELETE("/:sessionId", TerminateTerminalSessionHandler)  // DELETE /api/v1/terminal-sessions/{sessionId}
			terminals.GET("/:sessionId/stream", StreamTerminalSessionHandler) // WS /api/v1/terminal-sessions/{sessionId}/stream
		}

		captureSessions := apiV1.Group("/capture/wireshark-vnc-sessions", requireWiresharkVnc())
		{
			captureSessions.DELETE("", DeleteAllWiresharkVncSessionsHandler)
			captureSessions.GET("/:sessionId/ready", GetWiresharkVncSessionReadyHandler)
			captureSessions.DELETE("/:sessionId", DeleteWiresharkVncSessionHandler)
			captureSessions.Any("/:sessionId/vnc/*proxyPath", ProxyWiresharkVncSessionHandler)
		}

		// SSH Session Management Routes (Global)
		ssh := apiV1.Group("/ssh")
		{
			// List active SSH sessions for the user (or all if superuser)
			ssh.GET("/sessions", ListSSHSessionsHandler) // GET /api/v1/ssh/sessions

			// Terminate a specific SSH session by port
			ssh.DELETE("/sessions/:port", TerminateSSHSessionHandler) // DELETE /api/v1/ssh/sessions/{port}
		}

		// Topology Generation Route
		apiV1.POST("/generate", GenerateTopologyHandler) // POST /api/v1/generate

		// Tools Routes (Mostly Superuser)
		tools := apiV1.Group("/tools")
		{
			edgeshark := tools.Group("/edgeshark", requireContainerRuntime("Edgeshark"))
			{
				edgeshark.GET("/status", GetEdgeSharkStatusHandler)
				edgeshark.POST("/install", InstallEdgeSharkHandler)
				edgeshark.POST("/uninstall", UninstallEdgeSharkHandler)
			}

			// Disable TX Offload (Superuser Only)
			tools.POST("/disable-tx-offload", requireContainerRuntime("disabling TX offload"), DisableTxOffloadHandler) // POST /api/v1/tools/disable-tx-offload

			// Certificate Tools (Superuser Only)
			certs := tools.Group("/certs")
			{
				certs.POST("/ca", CreateCAHandler)   // POST /api/v1/tools/certs/ca
				certs.POST("/sign", SignCertHandler) // POST /api/v1/tools/certs/sign
			} // End /certs group

			// vEth Tools (Superuser Only)
			tools.POST("/veth", requireContainerRuntime("veth tools"), CreateVethHandler) // POST /api/v1/tools/veth

			// VxLAN Tools (Superuser Only)
			vxlan := tools.Group("/vxlan", requireContainerRuntime("VxLAN tools"))
			{
				vxlan.POST("", CreateVxlanHandler)   // POST /api/v1/tools/vxlan
				vxlan.DELETE("", DeleteVxlanHandler) // DELETE /api/v1/tools/vxlan
			}

			// Netem Tools (Lab Owners + Superusers)
			netem := tools.Group("/netem", requireContainerRuntime("link impairment (netem)"))
			{
				netem.POST("/set", SetNetemHandler)     // POST /api/v1/tools/netem/set
				netem.GET("/show", ShowNetemHandler)    // GET /api/v1/tools/netem/show
				netem.POST("/reset", ResetNetemHandler) // POST /api/v1/tools/netem/reset
			}

		}

		// Version Info Routes
		version := apiV1.Group("/version")
		{
			version.GET("", GetVersionHandler)         // GET /api/v1/version
			version.GET("/check", CheckVersionHandler) // GET /api/v1/version/check
		}

		// --- Add User Management Routes ---
		users := apiV1.Group("/users")
		{
			// List all users (superuser only)
			users.GET("", ListUsersHandler)

			// Create a new user (superuser only)
			users.POST("", CreateUserHandler)

			// User-specific operations
			userSpecific := users.Group("/:username")
			{
				// Get user details (superuser or own account)
				userSpecific.GET("", GetUserDetailsHandler)

				// Update user (superuser or own account)
				userSpecific.PUT("", UpdateUserHandler)

				// Delete user (superuser only)
				userSpecific.DELETE("", DeleteUserHandler)

				// Change password (superuser or own account)
				userSpecific.PUT("/password", ChangeUserPasswordHandler)
			}
		}

	}
}

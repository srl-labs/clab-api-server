// internal/api/routes.go
package api

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "github.com/srl-labs/clab-api-server/docs"
)

// SetupRoutes defines all the API endpoints and applies middleware.
func SetupRoutes(router *gin.Engine) {
	// --- Public Routes ---

	// Login endpoint - intentionally *not* under /api/v1 group
	router.POST("/login", LoginHandler)

	// Swagger documentation route
	// URL needs to match the basePath in your main swagger annotations
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, ginSwagger.URL("/swagger/doc.json")))

	// --- Authenticated Routes (/api/v1) ---
	apiV1 := router.Group("/api/v1")
	apiV1.Use(AuthMiddleware()) // Apply JWT authentication middleware to all /api/v1 routes
	{
		// Lab management routes
		labs := apiV1.Group("/labs")
		{
			// Deploy new lab (JSON/URL method)
			labs.POST("", DeployLabHandler) // POST /api/v1/labs

			// Deploy new lab (Archive method)
			labs.POST("/archive", DeployLabArchiveHandler) // POST /api/v1/labs/archive

			// List labs for user (or all if superuser)
			labs.GET("", ListLabsHandler) // GET /api/v1/labs

			// Actions on a specific lab by name
			labSpecific := labs.Group("/:labName")
			{
				// Inspect lab details
				labSpecific.GET("", InspectLabHandler) // GET /api/v1/labs/{labName}

				// Destroy lab
				labSpecific.DELETE("", DestroyLabHandler) // DELETE /api/v1/labs/{labName}

				// Redeploy lab
				labSpecific.PUT("", RedeployLabHandler) // PUT /api/v1/labs/{labName}

				// Inspect lab interfaces
				labSpecific.GET("/interfaces", InspectInterfacesHandler) // GET /api/v1/labs/{labName}/interfaces

				// Save Lab Config
				labSpecific.POST("/save", SaveLabConfigHandler) // POST /api/v1/labs/{labName}/save

				// Execute Command in Lab
				labSpecific.POST("/exec", ExecCommandHandler) // POST /api/v1/labs/{labName}/exec

				// Node Specific Routes (nested under lab)
				nodeSpecific := labSpecific.Group("/nodes/:nodeName")
				{
					// Request SSH Access to a specific node
					nodeSpecific.POST("/ssh", RequestSSHAccessHandler) // POST /api/v1/labs/{labName}/nodes/{nodeName}/ssh

					// Show netem for all interfaces on node
					nodeSpecific.GET("/netem", ShowNetemHandler) // GET /api/v1/labs/{labName}/nodes/{nodeName}/netem

					// Interface Specific Routes (nested under node)
					interfaceSpecific := nodeSpecific.Group("/interfaces/:interfaceName")
					{
						// Set netem for specific interface
						interfaceSpecific.PUT("/netem", SetNetemHandler) // PUT /api/v1/labs/{labName}/nodes/{nodeName}/interfaces/{interfaceName}/netem
						// Reset netem for specific interface
						interfaceSpecific.DELETE("/netem", ResetNetemHandler) // DELETE /api/v1/labs/{labName}/nodes/{nodeName}/interfaces/{interfaceName}/netem
					}
				}
			}
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
			// Disable TX Offload (Superuser Only)
			tools.POST("/disable-tx-offload", DisableTxOffloadHandler) // POST /api/v1/tools/disable-tx-offload

			// Certificate Tools (Superuser Only)
			certs := tools.Group("/certs")
			{
				certs.POST("/ca", CreateCAHandler)   // POST /api/v1/tools/certs/ca
				certs.POST("/sign", SignCertHandler) // POST /api/v1/tools/certs/sign
			} // End /certs group

			// vEth Tools (Superuser Only)
			tools.POST("/veth", CreateVethHandler) // POST /api/v1/tools/veth

			// VxLAN Tools (Superuser Only)
			vxlan := tools.Group("/vxlan")
			{
				vxlan.POST("", CreateVxlanHandler)   // POST /api/v1/tools/vxlan
				vxlan.DELETE("", DeleteVxlanHandler) // DELETE /api/v1/tools/vxlan
			}

		}

		// Version Info Routes
		version := apiV1.Group("/version")
		{
			version.GET("", GetVersionHandler)         // GET /api/v1/version
			version.GET("/check", CheckVersionHandler) // GET /api/v1/version/check
		}

	}
}

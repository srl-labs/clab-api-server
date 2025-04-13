// internal/api/routes.go
package api

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	// Adjust import path if your module path is different
	_ "github.com/FloSch62/clab-api/docs"
)

func SetupRoutes(router *gin.Engine) {
	// --- Public Routes ---

	// Login endpoint - intentionally *not* under /api/v1 group
	router.POST("/login", LoginHandler)

	// Swagger documentation route
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, ginSwagger.URL("/swagger/doc.json")))

	// --- Authenticated Routes (/api/v1) ---
	apiV1 := router.Group("/api/v1")
	apiV1.Use(AuthMiddleware()) // Apply JWT authentication middleware
	{
		// Lab management routes
		labs := apiV1.Group("/labs")
		{
			// Deploy new lab
			labs.POST("", DeployLabHandler) // POST /api/v1/labs

			// List labs for user
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

				// --- NEW: Netem Routes (nested under node) ---
				nodeSpecific := labSpecific.Group("/nodes/:nodeName")
				{
					// Show netem for all interfaces on node
					nodeSpecific.GET("/netem", ShowNetemHandler) // GET /api/v1/labs/{labName}/nodes/{nodeName}/netem

					interfaceSpecific := nodeSpecific.Group("/interfaces/:interfaceName")
					{
						// Set netem for specific interface
						interfaceSpecific.PUT("/netem", SetNetemHandler) // PUT /api/v1/labs/{labName}/nodes/{nodeName}/interfaces/{interfaceName}/netem
						// Reset netem for specific interface
						interfaceSpecific.DELETE("/netem", ResetNetemHandler) // DELETE /api/v1/labs/{labName}/nodes/{nodeName}/interfaces/{interfaceName}/netem
						// GET specific interface netem could be added here if needed, but covered by node-level GET
					}
				}
			}
		}

		// Topology Generation Route ---
		apiV1.POST("/generate", GenerateTopologyHandler) // POST /api/v1/generate

		// --- NEW: Tools Routes (Top Level, mostly Superuser) ---
		tools := apiV1.Group("/tools")
		{
			// Disable TX Offload (Superuser Only)
			tools.POST("/disable-tx-offload", DisableTxOffloadHandler) // POST /api/v1/tools/disable-tx-offload

			// Certificate Tools (Superuser Only)
			certs := tools.Group("/certs")
			{
				certs.POST("/ca", CreateCAHandler)   // POST /api/v1/tools/certs/ca
				certs.POST("/sign", SignCertHandler) // POST /api/v1/tools/certs/sign
			}
			// --- NEW: vEth Tools (Superuser Only) ---
			tools.POST("/veth", CreateVethHandler) // POST /api/v1/tools/veth

			// --- NEW: VxLAN Tools (Superuser Only) ---
			tools.POST("/vxlan", CreateVxlanHandler)   // POST /api/v1/tools/vxlan
			tools.DELETE("/vxlan", DeleteVxlanHandler) // DELETE
		}
	}
}

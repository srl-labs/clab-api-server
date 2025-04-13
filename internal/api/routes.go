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

				// --- NEW: Save Lab Config ---
				labSpecific.POST("/save", SaveLabConfigHandler) // POST /api/v1/labs/{labName}/save

				// --- NEW: Execute Command in Lab ---
				labSpecific.POST("/exec", ExecCommandHandler) // POST /api/v1/labs/{labName}/exec
			}
		}

		// Topology Generation Route ---
		// Placed outside /labs group as it doesn't operate on an existing lab initially
		apiV1.POST("/generate", GenerateTopologyHandler) // POST /api/v1/generate

		// TODO: Add other potential top-level authenticated routes if needed
	}
}

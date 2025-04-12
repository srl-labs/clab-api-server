package api

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	// Adjust import path if your module path is different
	_ "github.com/yourusername/clab-api/docs"
)

func SetupRoutes(router *gin.Engine) {
	// --- Public Routes ---

	// Login endpoint - intentionally *not* under /api/v1 group
	// Accepts POST requests at /login
	router.POST("/login", LoginHandler)

	// Swagger documentation route
	// Access it at /swagger/index.html
	// This documentation describes the /api/v1 endpoints primarily.
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, ginSwagger.URL("/swagger/doc.json")))


	// --- Authenticated Routes ---

	// Group for authenticated API endpoints under /api/v1
	apiV1 := router.Group("/api/v1")
	apiV1.Use(AuthMiddleware()) // Apply JWT authentication middleware to all routes in this group
	{
		// Lab management routes (e.g., /api/v1/labs)
		labs := apiV1.Group("/labs")
		{
			// POST /api/v1/labs
			labs.POST("", DeployLabHandler)
			// GET /api/v1/labs
			labs.GET("", ListLabsHandler) // List all labs for the authenticated user
			// GET /api/v1/labs/{labName}
			labs.GET("/:labName", InspectLabHandler)
			// DELETE /api/v1/labs/{labName}
			labs.DELETE("/:labName", DestroyLabHandler)
			// TODO: Add more lab-specific endpoints if needed (e.g., graph, exec)
		}

		// Topology file listing routes (e.g., /api/v1/topologies)
		topologies := apiV1.Group("/topologies")
		{
			// GET /api/v1/topologies
			topologies.GET("", ListTopologiesHandler)
		}
	}
}
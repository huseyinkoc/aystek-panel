package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func LocalizedContentRoutes(router *gin.Engine) {
	content := router.Group("/content")
	content.Use(middlewares.MaintenanceMiddleware()) // Bakım modu kontrolü
	{
		content.POST("/", controllers.CreateLocalizedContentHandler)
		content.GET("/:id", controllers.GetLocalizedContentHandler)
	}
}

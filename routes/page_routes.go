package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func PageRoutes(router *gin.Engine) {
	pages := router.Group("/admin/pages")
	pages.Use(middlewares.MaintenanceMiddleware())                     // Bakım modu kontrolü
	pages.Use(middlewares.AuthMiddleware())                            // JWT kontrolü
	pages.Use(middlewares.AuthorizeRolesMiddleware("admin", "editor")) // Roller
	{
		pages.POST("/create", middlewares.CSRFMiddleware(), controllers.CreatePageHandler)
		pages.GET("/", controllers.GetAllPagesHandler)
		pages.PUT("/:id", middlewares.CSRFMiddleware(), controllers.UpdatePageHandler)
		pages.DELETE("/:id", middlewares.CSRFMiddleware(), controllers.DeletePageHandler)
	}
}

package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func TagRoutes(router *gin.Engine) {
	tags := router.Group("/admin/tags")
	tags.Use(middlewares.MaintenanceMiddleware()) // Bakım modu kontrolü
	tags.Use(middlewares.AuthMiddleware())
	tags.Use(middlewares.AuthorizeRolesMiddleware("admin", "editor"))
	{
		tags.POST("/create", middlewares.CSRFMiddleware(), controllers.CreateTagHandler)
		tags.GET("/", controllers.GetAllTagsHandler)
		tags.GET("/:id", controllers.GetTagByIDHandler)
		tags.PUT("/:id", controllers.UpdateTagHandler)
		tags.DELETE("/:id", controllers.DeleteTagHandler)
	}
}

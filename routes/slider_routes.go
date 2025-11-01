package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func SliderRoutes(router *gin.Engine) {
	sliders := router.Group("/sliders")
	sliders.Use(middlewares.MaintenanceMiddleware())                     // Bakım modu kontrolü
	sliders.Use(middlewares.AuthMiddleware())                            // JWT Middleware
	sliders.Use(middlewares.AuthorizeRolesMiddleware("admin", "editor")) // Sadece adminler erişebilir
	{
		sliders.POST("/", middlewares.CSRFMiddleware(), controllers.CreateSliderHandler)
		sliders.GET("/", controllers.GetSlidersHandler)
		sliders.PUT("/:id", middlewares.CSRFMiddleware(), controllers.UpdateSliderHandler)
		sliders.DELETE("/:id", middlewares.CSRFMiddleware(), controllers.DeleteSliderHandler)
	}
}

package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func SliderRoutes(router *gin.Engine) {
	sliders := router.Group("/sliders")

	// 🧩 Güvenlik ve sistem kontrolleri
	sliders.Use(
		middlewares.MaintenanceMiddleware(), // Bakım modu
		middlewares.AuthMiddleware(),        // JWT kontrolü
	)

	{
		// 🟢 Slider oluşturma
		sliders.POST("/",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("sliders", "create"),
			controllers.CreateSliderHandler,
		)

		// 🔵 Slider listesi
		sliders.GET("/",
			middlewares.AuthorizePermissionMiddleware("sliders", "read"),
			controllers.GetSlidersHandler,
		)

		// 🟣 Slider güncelleme
		sliders.PUT("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("sliders", "update"),
			controllers.UpdateSliderHandler,
		)

		// 🔴 Slider silme
		sliders.DELETE("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("sliders", "delete"),
			controllers.DeleteSliderHandler,
		)
	}
}

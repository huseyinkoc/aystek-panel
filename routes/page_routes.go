package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func PageRoutes(router *gin.Engine) {
	pages := router.Group("/pages")

	// 🧩 Güvenlik zinciri
	pages.Use(middlewares.MaintenanceMiddleware()) // Bakım modu kontrolü
	pages.Use(middlewares.AuthMiddleware())        // JWT kullanıcı doğrulama

	{
		// 🟢 Sayfa oluşturma
		pages.POST("/create",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("pages", "create"),
			controllers.CreatePageHandler,
		)

		// 🔵 Sayfa listeleme
		pages.GET("/",
			middlewares.AuthorizePermissionMiddleware("pages", "read"),
			controllers.GetAllPagesHandler,
		)

		// 🟣 Sayfa güncelleme
		pages.PUT("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("pages", "update"),
			controllers.UpdatePageHandler,
		)

		// 🔴 Sayfa silme
		pages.DELETE("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("pages", "delete"),
			controllers.DeletePageHandler,
		)
	}
}

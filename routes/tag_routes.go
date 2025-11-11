package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func TagRoutes(router *gin.Engine) {
	tags := router.Group("/tags")

	// 🧩 Ortak güvenlik zinciri
	tags.Use(
		middlewares.MaintenanceMiddleware(), // Bakım modu kontrolü
		middlewares.AuthMiddleware(),        // JWT doğrulama
	)

	{
		// 🟢 Etiket oluşturma
		tags.POST("/create",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("tags", "create"),
			controllers.CreateTagHandler,
		)

		// 🔵 Etiketleri listeleme
		tags.GET("/",
			middlewares.AuthorizePermissionMiddleware("tags", "read"),
			controllers.GetAllTagsHandler,
		)

		// 🔍 Tek bir etiketi getirme
		tags.GET("/:id",
			middlewares.AuthorizePermissionMiddleware("tags", "read"),
			controllers.GetTagByIDHandler,
		)

		// 🟣 Etiket güncelleme
		tags.PUT("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("tags", "update"),
			controllers.UpdateTagHandler,
		)

		// 🔴 Etiket silme
		tags.DELETE("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("tags", "delete"),
			controllers.DeleteTagHandler,
		)
	}
}

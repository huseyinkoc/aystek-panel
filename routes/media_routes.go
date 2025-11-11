package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func MediaRoutes(router *gin.Engine) {
	media := router.Group("/media")

	// 🧩 Genel Middleware zinciri
	media.Use(middlewares.MaintenanceMiddleware()) // Bakım modu kontrolü
	media.Use(middlewares.AuthMiddleware())        // JWT doğrulama

	{
		// 🟢 Yükleme işlemi (create)
		media.POST("/upload",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("media", "create"),
			controllers.UploadMediaHandler,
		)

		// 🔴 Silme işlemi (delete)
		media.DELETE("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("media", "delete"),
			controllers.DeleteMediaHandler,
		)

		// 🔵 Tüm medyaları listeleme (read)
		media.GET("/",
			middlewares.AuthorizePermissionMiddleware("media", "read"),
			controllers.GetAllMediaHandler,
		)

		// 🟣 Medya detayı görüntüleme (read)
		media.GET("/:id",
			middlewares.AuthorizePermissionMiddleware("media", "read"),
			controllers.GetMediaDetailHandler,
		)

		// 🟠 Filtreli medya listesi (read)
		media.GET("/filter",
			middlewares.AuthorizePermissionMiddleware("media", "read"),
			controllers.GetFilteredMediaHandler,
		)
	}
}

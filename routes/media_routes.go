package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func MediaRoutes(router *gin.Engine) {
	media := router.Group("/media")
	media.Use(middlewares.MaintenanceMiddleware())                     // Bakım modu kontrolü
	media.Use(middlewares.AuthMiddleware())                            // JWT doğrulama
	media.Use(middlewares.AuthorizeRolesMiddleware("admin", "editor")) // Yetki kontrolü (admin ve editor)

	{
		// Hassas işlemler için CSRF koruması
		media.POST("/upload", middlewares.CSRFMiddleware(), controllers.UploadMediaHandler)
		media.DELETE("/:id", middlewares.CSRFMiddleware(), controllers.DeleteMediaHandler)

		// GET işlemleri için sadece JWT doğrulama ve yetkilendirme
		media.GET("/", controllers.GetAllMediaHandler)
		media.GET("/:id", controllers.GetMediaDetailHandler)
		media.GET("/filter", controllers.GetFilteredMediaHandler)
	}
}

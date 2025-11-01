package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func PostRoutes(router *gin.Engine) {
	posts := router.Group("/admin/posts")
	posts.Use(middlewares.MaintenanceMiddleware()) // Bakım modu kontrolü
	posts.Use(middlewares.AuthMiddleware())
	posts.Use(middlewares.AuthorizeRolesMiddleware("admin", "editor"))
	posts.Use(middlewares.LanguageMiddleware()) // Dil middleware’i ekle
	{
		posts.POST("/create", middlewares.CSRFMiddleware(), middlewares.ModulePermissionMiddleware("posts", "create"), middlewares.ActivityLogMiddleware("posts", "create"), controllers.CreatePostHandler)
		posts.GET("/", middlewares.ModulePermissionMiddleware("posts", "read"), controllers.GetAllPostsHandler)
		posts.GET("/filter", controllers.GetFilteredPostsHandler)       // Filtrelenmiş postlar
		posts.GET("/lang/:lang", controllers.GetPostsByLanguageHandler) // Dil bazlı içerik listeleme
		// Yeni rota: Dil ve slug üzerinden post getirme
		posts.GET("/:lang/:slug", controllers.GetPostByLangAndSlugHandler)

	}
}

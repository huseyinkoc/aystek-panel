package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func PostRoutes(router *gin.Engine) {
	posts := router.Group("/posts")

	// 🧩 Ortak güvenlik ve sistem kontrolleri
	posts.Use(middlewares.MaintenanceMiddleware()) // Bakım modu kontrolü
	posts.Use(middlewares.AuthMiddleware())        // JWT doğrulama
	posts.Use(middlewares.LanguageMiddleware())    // Dil middleware’i

	{
		// 🟢 Post oluşturma
		posts.POST("/create",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("posts", "create"),
			middlewares.ActivityLogMiddleware("posts", "create"),
			controllers.CreatePostHandler,
		)

		// 🔵 Tüm postları listeleme
		posts.GET("/",
			middlewares.AuthorizePermissionMiddleware("posts", "read"),
			controllers.GetAllPostsHandler,
		)

		// 🟣 Filtreli listeleme (örneğin kategoriye göre)
		posts.GET("/filter",
			middlewares.AuthorizePermissionMiddleware("posts", "read"),
			controllers.GetFilteredPostsHandler,
		)

		// 🌐 Dil bazlı içerik listeleme
		posts.GET("/lang/:lang",
			middlewares.AuthorizePermissionMiddleware("posts", "read"),
			controllers.GetPostsByLanguageHandler,
		)

		// 🔍 Dil + slug üzerinden içerik getirme (örneğin /tr/slug)
		posts.GET("/:lang/:slug",
			middlewares.AuthorizePermissionMiddleware("posts", "read"),
			controllers.GetPostByLangAndSlugHandler,
		)
	}
}

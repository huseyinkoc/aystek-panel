package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

// RegisterCommentRoutes tüm yorum rotalarını ayarlar
func RegisterCommentRoutes(router *gin.Engine) {
	commentGroup := router.Group("/comments")

	// Genel middleware'ler
	commentGroup.Use(middlewares.MaintenanceMiddleware()) // Bakım modu kontrolü
	commentGroup.Use(middlewares.AuthMiddleware())        // JWT kimlik doğrulama

	{
		// 🟢 Yorum oluşturma
		commentGroup.POST("/",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("comments", "create"),
			controllers.CreateCommentHandler,
		)

		// 🟡 Post'a göre yorumları listeleme (herkes görebilir, izin kontrolü yok)
		commentGroup.GET("/post/:postID",
			controllers.GetCommentsByPostIDHandler,
		)

		// 🟢 Yanıt ekleme
		commentGroup.POST("/:commentID/reply",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("comments", "create"),
			controllers.AddReplyHandler,
		)

		// 🟢 Beğenme
		commentGroup.POST("/:commentID/like",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("comments", "update"),
			controllers.LikeCommentHandler,
		)

		// 🟢 Reaksiyon ekleme
		commentGroup.POST("/:commentID/reaction",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("comments", "update"),
			controllers.AddReactionHandler,
		)

		// 🔴 Silme
		commentGroup.DELETE("/:commentID",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("comments", "delete"),
			controllers.DeleteCommentHandler,
		)

		// 🔵 Güncelleme
		commentGroup.PUT("/:commentID",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("comments", "update"),
			controllers.UpdateCommentHandler,
		)
	}
}

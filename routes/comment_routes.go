package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

// RegisterCommentRoutes tüm yorum rotalarını ayarlar
func RegisterCommentRoutes(router *gin.Engine) {

	commentGroup := router.Group("/comments")
	commentGroup.Use(middlewares.MaintenanceMiddleware()) // Bakım modu kontrolü
	commentGroup.Use(middlewares.AuthMiddleware())
	commentGroup.Use(middlewares.AuthorizeRolesMiddleware("admin", "editor"))
	{
		commentGroup.POST("/", middlewares.CSRFMiddleware(), middlewares.ModulePermissionMiddleware("comments", "create"), controllers.CreateCommentHandler)
		commentGroup.GET("/post/:postID", controllers.GetCommentsByPostIDHandler)
		commentGroup.POST("/:commentID/reply", middlewares.CSRFMiddleware(), controllers.AddReplyHandler)
		commentGroup.POST("/:commentID/like", middlewares.CSRFMiddleware(), controllers.LikeCommentHandler)
		commentGroup.POST("/:commentID/reaction", middlewares.CSRFMiddleware(), controllers.AddReactionHandler) // Yeni rota
		commentGroup.DELETE("/:commentID", middlewares.CSRFMiddleware(), controllers.DeleteCommentHandler)      // Silme rotası
		commentGroup.PUT("/:commentID", middlewares.CSRFMiddleware(), controllers.UpdateCommentHandler)         // Güncelleme rotası

	}
}

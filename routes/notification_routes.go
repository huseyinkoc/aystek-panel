package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func RegisterNotificationRoutes(router *gin.Engine) {
	notificationGroup := router.Group("/notifications")
	notificationGroup.Use(middlewares.MaintenanceMiddleware()) // Bakım modu kontrolü
	notificationGroup.Use(middlewares.AuthMiddleware())
	{
		notificationGroup.GET("/", controllers.GetNotificationsHandler)
	}
}

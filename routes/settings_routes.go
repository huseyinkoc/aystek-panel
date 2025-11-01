package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func SettingsRoutes(router *gin.Engine) {
	settings := router.Group("/svc/settings")
	{
		settings.GET("/", middlewares.MaintenanceMiddleware(), controllers.GetSettingsHandler)
		settings.PUT("/", middlewares.AuthMiddleware(), controllers.UpdateSettingsHandler)
	}
	links := router.Group("/svc/settings/social-media")
	{
		links.GET("/", middlewares.MaintenanceMiddleware(), controllers.GetSocialMediaLinksHandler)
		links.PUT("/", middlewares.MaintenanceMiddleware(), middlewares.AuthMiddleware(), controllers.UpdateSocialMediaLinksHandler)
	}
}

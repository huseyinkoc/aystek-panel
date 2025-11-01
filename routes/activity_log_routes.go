package routes

import (
	"admin-panel/controllers"

	"github.com/gin-gonic/gin"
)

func ActivityLogRoutes(router *gin.Engine) {
	logs := router.Group("/activity-logs")
	{
		logs.GET("/", controllers.GetActivityLogsHandler)
	}
}

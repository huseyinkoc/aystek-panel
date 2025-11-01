package routes

import (
	"admin-panel/controllers"

	"github.com/gin-gonic/gin"
)

func LanguageRoutes(router *gin.Engine) {
	languages := router.Group("/languages")
	{
		languages.POST("/", controllers.CreateLanguageHandler)
		languages.GET("/", controllers.GetLanguagesHandler)
		languages.PUT("/:id", controllers.UpdateLanguageHandler)
		languages.DELETE("/:id", controllers.DeleteLanguageHandler)
	}
}

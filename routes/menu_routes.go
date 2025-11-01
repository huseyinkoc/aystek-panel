package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func MenuRoutes(router *gin.Engine) {
	menus := router.Group("/svc/menus")
	menus.Use(middlewares.MaintenanceMiddleware()) // Bakım modu kontrolü
	menus.Use(middlewares.AuthMiddleware())        // Kullanıcı giriş kontrolü
	{
		menus.POST("/", middlewares.CSRFMiddleware(), controllers.CreateMenuHandler) // Menü oluşturma
		menus.GET("/", controllers.GetMenusHandler)                                  // Yetkilere göre menüleri getirme
		menus.PUT("/:id", middlewares.CSRFMiddleware(), controllers.UpdateMenuHandler)
		menus.DELETE("/:id", middlewares.CSRFMiddleware(), controllers.DeleteMenuHandler)
	}
}

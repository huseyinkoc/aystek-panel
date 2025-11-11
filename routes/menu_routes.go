package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func MenuRoutes(router *gin.Engine) {
	menus := router.Group("/menus")

	// 🧩 Genel güvenlik zinciri
	menus.Use(middlewares.MaintenanceMiddleware()) // Bakım modu kontrolü
	menus.Use(middlewares.AuthMiddleware())        // JWT kullanıcı doğrulama

	{
		// 🟢 Menü oluşturma
		menus.POST("/",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("menus", "create"),
			controllers.CreateMenuHandler,
		)

		// 🔵 Menüler listesi (yetkili kullanıcı)
		menus.GET("/",
			middlewares.AuthorizePermissionMiddleware("menus", "read"),
			controllers.GetMenusHandler,
		)

		// 🟣 Menü güncelleme
		menus.PUT("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("menus", "update"),
			controllers.UpdateMenuHandler,
		)

		// 🔴 Menü silme
		menus.DELETE("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("menus", "delete"),
			controllers.DeleteMenuHandler,
		)
	}
}

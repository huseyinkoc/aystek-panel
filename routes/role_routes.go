package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

// 🔹 Role + Permission Routes
func RoleRoutes(router *gin.Engine) {
	roles := router.Group("/svc/roles")
	roles.Use(
		middlewares.MaintenanceMiddleware(), // Bakım modu kontrolü
		middlewares.AuthMiddleware(),        // JWT doğrulama
	)

	{
		// 🔸 Role CRUD işlemleri
		roles.POST("/create", middlewares.AuthorizeRolesMiddleware("admin"), controllers.CreateRoleHandler)
		roles.GET("/", middlewares.AuthorizeRolesMiddleware("admin"), controllers.GetAllRolesHandler)
		roles.PUT("/:id", middlewares.AuthorizeRolesMiddleware("admin"), controllers.UpdateRoleHandler)
		roles.DELETE("/:id", middlewares.AuthorizeRolesMiddleware("admin"), controllers.DeleteRoleHandler)
	}

	// 🔹 Permission modülleri (dinamik olarak MongoDB'den yönetilir)
	permissions := router.Group("/svc/permissions")
	permissions.Use(
		middlewares.MaintenanceMiddleware(),
		middlewares.AuthMiddleware(),
		middlewares.AuthorizeRolesMiddleware("admin"), // Sadece admin izin modüllerini yönetebilir
	)
	{
		permissions.GET("/", controllers.GetPermissionModules)         // Modül listesini getir
		permissions.POST("/", controllers.CreatePermissionModule)      // Yeni modül oluştur
		permissions.PUT("/:id", controllers.UpdatePermissionModule)    // Modül güncelle
		permissions.DELETE("/:id", controllers.DeletePermissionModule) // Modül sil
	}
}

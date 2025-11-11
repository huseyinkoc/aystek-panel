package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

// Role & Permission Routes
func RoleRoutes(router *gin.Engine) {
	// 🔹 Role işlemleri
	roles := router.Group("/roles")
	roles.Use(
		middlewares.MaintenanceMiddleware(), // Bakım modu kontrolü
		middlewares.AuthMiddleware(),        // JWT doğrulama
	)
	{
		// 🟢 Rol oluşturma
		roles.POST("/",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("roles", "create"),
			controllers.CreateRoleHandler,
		)

		// 🔵 Roller listesi
		roles.GET("/",
			middlewares.AuthorizePermissionMiddleware("roles", "read"),
			controllers.GetAllRolesHandler,
		)

		// 🔍 Tekil rol
		roles.GET("/:id",
			middlewares.AuthorizePermissionMiddleware("roles", "read"),
			controllers.GetRoleHandler,
		)

		// 🟣 Rol güncelleme
		roles.PUT("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("roles", "update"),
			controllers.UpdateRoleHandler,
		)

		// 🔴 Rol silme
		roles.DELETE("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("roles", "delete"),
			controllers.DeleteRoleHandler,
		)
	}

	// 🔹 Permission işlemleri
	permissions := router.Group("/permissions")
	permissions.Use(
		middlewares.MaintenanceMiddleware(),
		middlewares.AuthMiddleware(),
	)
	{
		permissions.GET("/",
			middlewares.AuthorizePermissionMiddleware("permissions", "read"),
			controllers.GetAllPermissionsHandler,
		)

		permissions.GET("/:id",
			middlewares.AuthorizePermissionMiddleware("permissions", "read"),
			controllers.GetPermissionHandler,
		)

		permissions.POST("/",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("permissions", "create"),
			controllers.CreatePermissionHandler,
		)

		permissions.PUT("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("permissions", "update"),
			controllers.UpdatePermissionHandler,
		)

		permissions.DELETE("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("permissions", "delete"),
			controllers.DeletePermissionHandler,
		)
	}
}

package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

// Role & Permission Routes
func RoleRoutes(router *gin.Engine) {
	// 🔹 Role işlemleri
	roles := router.Group("/svc/roles")
	roles.Use(
		middlewares.MaintenanceMiddleware(),
		middlewares.AuthMiddleware(),
	)
	{
		roles.POST("/", middlewares.AuthorizeRolesMiddleware("admin"), controllers.CreateRoleHandler)
		roles.GET("/", middlewares.AuthorizeRolesMiddleware("admin"), controllers.GetAllRolesHandler)
		roles.GET("/:id", middlewares.AuthorizeRolesMiddleware("admin"), controllers.GetRoleHandler)
		roles.PUT("/:id", middlewares.AuthorizeRolesMiddleware("admin"), controllers.UpdateRoleHandler)
		roles.DELETE("/:id", middlewares.AuthorizeRolesMiddleware("admin"), controllers.DeleteRoleHandler)
	}

	// 🔹 Permission işlemleri
	permissions := router.Group("/svc/permissions")
	permissions.Use(
		middlewares.MaintenanceMiddleware(),
		middlewares.AuthMiddleware(),
		middlewares.AuthorizeRolesMiddleware("admin"),
	)
	{
		permissions.GET("/", controllers.GetAllPermissionsHandler)
		permissions.GET("/:id", controllers.GetPermissionHandler)
		permissions.POST("/", controllers.CreatePermissionHandler)
		permissions.PUT("/:id", controllers.UpdatePermissionHandler)
		permissions.DELETE("/:id", controllers.DeletePermissionHandler)
	}
}

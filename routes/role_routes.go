package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func RoleRoutes(router *gin.Engine) {
	roles := router.Group("/admin/roles")
	roles.Use(middlewares.MaintenanceMiddleware()) // Bakım modu kontrolü
	// Yetkilendirme middleware'i
	roles.Use(middlewares.AuthMiddleware())
	roles.Use(middlewares.AuthorizeRolesMiddleware("admin")) // Rolleri yalnızca admin yönetebilir
	{
		// Rollere yönelik CRUD işlemleri
		roles.POST("/create", middlewares.CSRFMiddleware(), controllers.CreateRoleHandler) // Yeni rol oluşturma
		roles.GET("/", controllers.GetAllRolesHandler)                                     // Tüm rolleri listeleme
		roles.PUT("/:id", middlewares.CSRFMiddleware(), controllers.UpdateRoleHandler)     // Rol güncelleme
		roles.DELETE("/:id", middlewares.CSRFMiddleware(), controllers.DeleteRoleHandler)  // Rol silme
	}
}

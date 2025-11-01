package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func UserRoutes(router *gin.Engine) {
	users := router.Group("/admin/users")
	users.Use(middlewares.MaintenanceMiddleware())           // Bakım modu kontrolü
	users.Use(middlewares.AuthMiddleware())                  // JWT Middleware
	users.Use(middlewares.AuthorizeRolesMiddleware("admin")) // Sadece adminler erişebilir
	{
		users.POST("/create", middlewares.CSRFMiddleware(), controllers.CreateUserHandler)
		users.GET("/", controllers.GetAllUsersHandler)
		users.PUT("/:id", middlewares.CSRFMiddleware(), controllers.UpdateUserHandler)
		users.DELETE("/:id", middlewares.CSRFMiddleware(), controllers.DeleteUserHandler)
		users.PUT("/preferred-language", controllers.UpdatePreferredLanguageHandler) // Kullanıcı dil tercihi
	}
}

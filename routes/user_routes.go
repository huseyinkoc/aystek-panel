package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func UserRoutes(router *gin.Engine) {
	users := router.Group("/svc/users")
	users.Use(middlewares.MaintenanceMiddleware(), middlewares.AuthMiddleware())
	{
		// Tüm form işlemleri CSRF korumalı
		users.POST("/create",
			middlewares.AuthorizeRolesMiddleware("admin"),
			middlewares.CSRFMiddleware(),
			controllers.CreateUserHandler,
		)
		users.GET("/",
			middlewares.AuthorizeRolesMiddleware("admin"),
			controllers.GetAllUsersHandler,
		)
		users.PUT("/:id",
			middlewares.AuthorizeRolesMiddleware("admin"),
			middlewares.CSRFMiddleware(),
			controllers.UpdateUserHandler,
		)
		users.DELETE("/:id",
			middlewares.AuthorizeRolesMiddleware("admin"),
			middlewares.CSRFMiddleware(),
			controllers.DeleteUserHandler,
		)
		users.PATCH("/:id/approve",
			middlewares.AuthorizeRolesMiddleware("admin"),
			middlewares.CSRFMiddleware(),
			controllers.ApproveUserHandler,
		)
		users.PATCH("/:id/roles",
			middlewares.AuthorizeRolesMiddleware("admin"),
			middlewares.CSRFMiddleware(),
			controllers.AssignRolesHandler,
		)

		// Dil güncelleme CSRF korumalı
		users.PUT("/preferred-language",
			middlewares.CSRFMiddleware(),
			controllers.UpdatePreferredLanguageHandler,
		)
	}
}

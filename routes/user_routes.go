package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func UserRoutes(router *gin.Engine) {
	users := router.Group("/users")

	// 🧩 Ortak güvenlik zinciri
	users.Use(
		middlewares.MaintenanceMiddleware(), // Bakım modu kontrolü
		middlewares.AuthMiddleware(),        // JWT doğrulama
	)

	{
		// 🟢 Kullanıcı oluşturma
		users.POST("/create",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("users", "create"),
			controllers.CreateUserHandler,
		)

		// 🔵 Kullanıcıları listeleme
		users.GET("/",
			middlewares.AuthorizePermissionMiddleware("users", "read"),
			controllers.GetAllUsersHandler,
		)

		// 🔍 Tekil kullanıcı görüntüleme
		users.GET("/:id",
			middlewares.AuthorizePermissionMiddleware("users", "read"),
			controllers.GetUserByIDHandler,
		)

		// 🟣 Kullanıcı güncelleme
		users.PUT("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("users", "update"),
			controllers.UpdateUserHandler,
		)

		// 🔴 Kullanıcı silme
		users.DELETE("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("users", "delete"),
			controllers.DeleteUserHandler,
		)

		// 🟢 Kullanıcı onaylama
		users.PATCH("/:id/approve",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("users", "approve"),
			controllers.ApproveUserHandler,
		)

		// 🟣 Kullanıcıya rol atama
		users.PATCH("/:id/roles",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("users", "assign_roles"),
			controllers.AssignRolesHandler,
		)

		// 🌐 Dil tercihi güncelleme (kullanıcı kendi hesabında)
		users.PUT("/preferred-language",
			middlewares.CSRFMiddleware(),
			controllers.UpdatePreferredLanguageHandler,
		)
	}
}

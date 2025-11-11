package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func CategoryRoutes(router *gin.Engine) {
	categories := router.Group("/categories")
	categories.Use(middlewares.MaintenanceMiddleware()) // Bakım modu kontrolü
	categories.Use(middlewares.AuthMiddleware())
	//categories.Use(middlewares.AuthorizeRolesMiddleware("admin", "editor"))
	{
		categories.POST("/create",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("categories", "create"),
			controllers.CreateCategoryHandler)

		categories.GET("/",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("categories", "read"),
			controllers.GetAllCategoriesHandler)

		categories.GET("/:id",
			middlewares.AuthorizePermissionMiddleware("categories", "read"),
			controllers.GetCategoryByIDHandler)

		categories.PUT("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("categories", "update"),
			controllers.UpdateCategoryHandler)

		categories.DELETE("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("categories", "delete"),
			controllers.DeleteCategoryHandler)
	}
}

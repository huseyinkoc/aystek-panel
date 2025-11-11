package routes

import (
	"admin-panel/controllers"
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
)

func ContactRoutes(router *gin.Engine) {
	contacts := router.Group("/contact")

	// Genel middleware'ler
	contacts.Use(middlewares.MaintenanceMiddleware()) // Bakım modu kontrolü
	contacts.Use(middlewares.AuthMiddleware())        // JWT kimlik doğrulama

	{
		// 🟢 Yeni ileti oluşturma (kullanıcı form gönderir)
		contacts.POST("/",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("contacts", "create"),
			controllers.CreateContactMessageHandler,
		)

		// 🔵 Tüm iletileri listeleme (sadece yetkili kullanıcılar)
		contacts.GET("/",
			middlewares.AuthorizePermissionMiddleware("contacts", "read"),
			controllers.GetAllContactMessagesHandler,
		)

		// 🟣 Tek ileti görüntüleme
		contacts.GET("/:id",
			middlewares.AuthorizePermissionMiddleware("contacts", "read"),
			controllers.GetContactByIDHandler,
		)

		// 🟡 İleti durumunu güncelleme
		contacts.PUT("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("contacts", "update"),
			controllers.UpdateContactMessageStatusHandler,
		)

		// 🔴 İleti silme
		contacts.DELETE("/:id",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("contacts", "delete"),
			controllers.DeleteContactMessageHandler,
		)
	}
}

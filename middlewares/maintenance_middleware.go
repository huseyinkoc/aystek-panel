package middlewares

import (
	"admin-panel/services"
	"net/http"

	"github.com/gin-gonic/gin"
)

func MaintenanceMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Settings'ten bakım modu durumunu kontrol et
		settings, err := services.GetSettings()
		if err != nil || !settings.MaintenanceMode {
			// Eğer hata varsa veya bakım modu kapalıysa, devam et
			c.Next()
			return
		}

		// Dil parametresini kontrol et
		lang := c.DefaultQuery("lang", settings.DefaultLang)

		// Mesajı belirtilen dile göre döndür
		message := settings.MaintenanceMsg[lang]
		if message == "" {
			message = settings.MaintenanceMsg[settings.DefaultLang] // Varsayılan dil
		}

		c.JSON(http.StatusServiceUnavailable, gin.H{
			"message": message,
		})
		c.Abort()
	}
}

package middlewares

import (
	"admin-panel/services"
	"log"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func ErrorLoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Hata detaylarını alın
				logMessage := map[string]interface{}{
					"error":  err,
					"stack":  string(debug.Stack()),
					"path":   c.Request.URL.Path,
					"method": c.Request.Method,
				}

				// Hata detaylarını loglayın
				log.Printf("Panic occurred: %+v\n", logMessage)

				// Aktivite loglama (program hatalarını kaydetme)
				if err := services.LogActivity(
					primitive.NilObjectID,        // Kullanıcı kimliği yok, sistem hatası
					"system",                     // Sistem tarafından oluşturulan hata
					"error",                      // Modül
					"panic",                      // Eylem
					logMessage["error"].(string), // Hata detayı
				); err != nil {
					log.Printf("Failed to log activity: %v", err)
				}

				// Kullanıcıya uygun bir yanıt gönderin
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "An internal server error occurred",
				})
				c.Abort()
			}
		}()

		c.Next()
	}
}

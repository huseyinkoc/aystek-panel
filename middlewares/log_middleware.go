package middlewares

import (
	"admin-panel/services"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func ActivityLogMiddleware(module string, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Kullanıcı bilgilerini al
		userID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		username, _ := c.Get("username")

		// userID'yi ObjectID'ye çevir
		objectID, err := primitive.ObjectIDFromHex(userID.(string))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
			c.Abort()
			return
		}

		// Request işlemini ilerlet
		c.Next()

		// Aktiviteyi logla
		details := c.Request.Method + " " + c.Request.URL.Path
		if err := services.LogActivity(
			objectID,
			username.(string),
			module,
			action,
			details,
		); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to log activity"})
		}
	}
}

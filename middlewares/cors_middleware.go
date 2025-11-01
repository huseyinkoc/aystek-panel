package middlewares

import (
	"log"

	"github.com/gin-gonic/gin"
)

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Tarayıcıdan gelen Origin başlığını al
		origin := c.Request.Header.Get("Origin")
		log.Println(origin)
		// Eğer istek localhost:5173'ten geliyorsa izin ver
		if origin == "http://localhost:5173" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)                             // Gelen origin'e izin ver
			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS") // İzin verilen HTTP metotları
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")     // İzin verilen başlıklar
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")                        // Kimlik bilgilerine izin ver
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}

		c.Next()
	}
}

func NoCacheMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		c.Writer.Header().Set("Pragma", "no-cache")
		c.Writer.Header().Set("Expires", "0")
		c.Next()
	}
}

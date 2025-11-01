package middlewares

import (
	"github.com/gin-gonic/gin"
)

func LanguageMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		lang := c.Query("lang")
		if lang == "" {
			lang = "en" // Varsayılan dil
		}
		c.Set("lang", lang)
		c.Next()
	}
}

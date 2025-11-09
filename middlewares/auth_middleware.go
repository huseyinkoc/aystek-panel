package middlewares

import (
	"admin-panel/configs"
	"errors"
	"net/http"
	"strings"

	"github.com/didip/tollbooth/v7"
	"github.com/didip/tollbooth_gin"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Claims yapısı (JWT payload)
type Claims struct {
	UserID            string   `json:"userID"`
	Username          string   `json:"username"`
	Email             string   `json:"email"`
	PreferredLanguage string   `json:"preferred_language"`
	Roles             []string `json:"roles"`
	jwt.RegisteredClaims
}

// AuthMiddleware — env’den gelen JWT_SECRET ile token doğrulama
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization header eksik"})
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz Authorization formatı"})
			return
		}
		tokenString := parts[1]

		// Token'ı çözümle ve doğrula
		claims := &Claims{}
		_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return configs.GetJWTSecret(), nil
		})

		if err != nil {
			// JWT v5 hata yönetimi
			switch {
			case errors.Is(err, jwt.ErrTokenExpired):
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			case errors.Is(err, jwt.ErrTokenNotValidYet):
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token not valid yet"})
			case errors.Is(err, jwt.ErrTokenMalformed):
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Malformed token"})
			default:
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			}
			return
		}

		// Kullanıcı bilgilerini context'e ekle
		c.Set("claims", claims)
		c.Set("userID", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("email", claims.Email)
		c.Set("preferred_language", claims.PreferredLanguage)
		c.Set("roles", claims.Roles)

		c.Next()
	}
}

// RateLimitMiddleware — istek oranını sınırlama
func RateLimitMiddleware() gin.HandlerFunc {
	limiter := tollbooth.NewLimiter(3, nil) // saniyede 3 istek
	return tollbooth_gin.LimitHandler(limiter)
}

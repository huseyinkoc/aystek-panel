package middlewares

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
)

// CSRF token'leri saklamak için eşzamanlı map
var csrfTokens sync.Map // username -> csrfToken

// CSRF token oluşturma
func GenerateCSRFToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// CSRF token doğrulama ve geçerliyse yenisini oluşturma
func ValidateCSRFToken(username, csrfToken string) bool {
	value, ok := csrfTokens.Load(username)
	if !ok || value != csrfToken {
		return false
	}

	// Doğrulama başarılıysa yeni bir token oluştur ve sakla
	newToken, err := GenerateCSRFToken()
	if err == nil {
		csrfTokens.Store(username, newToken)
	}

	return true
}

// CSRF token saklama
func StoreCSRFToken(username, csrfToken string) {
	csrfTokens.Store(username, csrfToken)
}

// CSRF token getir
func GetStoredCSRFToken(username string) string {
	value, ok := csrfTokens.Load(username)
	if !ok {
		return ""
	}
	return value.(string)
}

// CSRF token sil (logout veya oturum kapama sırasında çağrılır)
func DeleteCSRFToken(username string) {
	csrfTokens.Delete(username)
}

// CSRF middleware — her POST/PUT/DELETE isteğinde token kontrolü yapar
func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodPost ||
			c.Request.Method == http.MethodPut ||
			c.Request.Method == http.MethodDelete {

			username := c.GetString("username") // Kullanıcı bilgisi middleware’den alınır
			csrfToken := c.GetHeader("X-CSRF-Token")

			if csrfToken == "" || !ValidateCSRFToken(username, csrfToken) {
				c.JSON(http.StatusForbidden, gin.H{"error": "Invalid or missing CSRF token"})
				c.Abort()
				return
			}

			// Doğrulama başarılıysa yeni token'ı header'a ekle
			if newToken, ok := csrfTokens.Load(username); ok {
				c.Writer.Header().Set("X-CSRF-Token", newToken.(string))
			}
		}

		c.Next()
	}
}

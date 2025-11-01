package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// setupRouter fonksiyonunu yalnızca testler için kullanın
func setupRouter() *gin.Engine {
	router := gin.Default()
	router.GET("/:lang/:slug", func(c *gin.Context) {
		lang := c.Param("lang")
		slug := c.Param("slug")
		c.JSON(http.StatusOK, gin.H{
			"language": lang,
			"slug":     slug,
		})
	})
	return router
}

// Test fonksiyonu
func TestGetContentByLangAndSlug(t *testing.T) {
	router := setupRouter()

	// HTTP isteği oluşturun
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/en/sample-slug", nil)
	router.ServeHTTP(w, req)

	// Yanıtları kontrol edin
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "en")
	assert.Contains(t, w.Body.String(), "sample-slug")
}

package controllers

import (
	"admin-panel/models"
	"admin-panel/services"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// CreateLocalizedContentHandler creates a new localized content entry
// @Summary Create localized content
// @Description Add new localized content with translations
// @Tags Localized Content
// @Accept json
// @Produce json
// @Param content body models.LocalizedContent true "Localized content details"
// @Success 200 {object} map[string]interface{} "Content created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request payload"
// @Failure 500 {object} map[string]interface{} "Failed to create content"
// @Router /localized-content [post]
func CreateLocalizedContentHandler(c *gin.Context) {
	var input models.LocalizedContent
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := services.CreateLocalizedContent(c.Request.Context(), &input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create content"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Content created successfully"})
}

// GetLocalizedContentHandler retrieves localized content by ID and language
// @Summary Get localized content by ID
// @Description Retrieve localized content in a specific language
// @Tags Localized Content
// @Produce json
// @Param id path string true "Localized Content ID"
// @Param lang query string false "Language code (e.g., 'en', 'tr')"
// @Success 200 {object} models.LocalizedField "Localized content details"
// @Failure 400 {object} map[string]interface{} "Invalid content ID"
// @Failure 404 {object} map[string]interface{} "Content not found"
// @Failure 500 {object} map[string]interface{} "Failed to fetch content"
// @Router /localized-content/{id} [get]
func GetLocalizedContentHandler(c *gin.Context) {
	id := c.Param("id")
	lang := c.DefaultQuery("lang", "en")

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid content ID"})
		return
	}

	content, err := services.GetLocalizedContent(c.Request.Context(), objectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch content"})
		return
	}

	translation := content.Translations[lang]
	c.JSON(http.StatusOK, gin.H{"content": translation})
}

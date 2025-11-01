package controllers

import (
	"admin-panel/configs"
	"admin-panel/models"
	"admin-panel/services"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// CreateLanguageHandler creates a new language
// @Summary Create a new language
// @Description Add a new language configuration
// @Tags Languages
// @Accept json
// @Produce json
// @Param language body models.Language true "Language configuration"
// @Success 200 {object} map[string]interface{} "Language created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request payload"
// @Failure 500 {object} map[string]interface{} "Failed to create language"
// @Router /languages [post]
func CreateLanguageHandler(c *gin.Context) {
	var language models.Language
	if err := c.ShouldBindJSON(&language); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := services.CreateLanguage(&language); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create language"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Language created successfully"})
}

// GetLanguagesHandler retrieves all languages with active and default settings
// @Summary Get all languages
// @Description Retrieve all languages, including active and default configurations
// @Tags Languages
// @Produce json
// @Param lang query string false "Active language code (e.g., 'en', 'tr')"
// @Success 200 {object} map[string]interface{} "List of languages with active and default settings"
// @Failure 500 {object} map[string]interface{} "Failed to retrieve languages"
// @Router /languages [get]
func GetLanguagesHandler(c *gin.Context) {
	// Aktif dil parametresini al
	activeLang := c.DefaultQuery("lang", "en") // Varsayılan dil "en"

	// Tüm dilleri al
	languages, err := services.GetLanguagesWithActiveAndDefault(activeLang)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve languages"})
		return
	}

	// Varsayılan ve aktif dil bilgilerini ekle
	response := gin.H{
		"active_language":  activeLang,
		"default_language": configs.LanguageConfig.DefaultLanguage, // Varsayılan dili config'den çek
		"languages":        languages,
	}

	// Yanıt döndür
	c.JSON(http.StatusOK, response)
}

// UpdateLanguageHandler updates a language configuration
// @Summary Update a language
// @Description Update an existing language configuration by its ID
// @Tags Languages
// @Accept json
// @Produce json
// @Param id path string true "Language ID"
// @Param update body map[string]interface{} true "Updated language fields"
// @Success 200 {object} map[string]interface{} "Language updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid language ID or request payload"
// @Failure 500 {object} map[string]interface{} "Failed to update language"
// @Router /languages/{id} [put]
func UpdateLanguageHandler(c *gin.Context) {
	id := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid language ID"})
		return
	}

	var update map[string]interface{}
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := services.UpdateLanguage(objectID, update); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update language"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Language updated successfully"})
}

// DeleteLanguageHandler deletes a language configuration
// @Summary Delete a language
// @Description Remove a language configuration by its ID
// @Tags Languages
// @Param id path string true "Language ID"
// @Success 200 {object} map[string]interface{} "Language deleted successfully"
// @Failure 400 {object} map[string]interface{} "Invalid language ID"
// @Failure 500 {object} map[string]interface{} "Failed to delete language"
// @Router /languages/{id} [delete]
func DeleteLanguageHandler(c *gin.Context) {
	id := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid language ID"})
		return
	}

	if err := services.DeleteLanguage(objectID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete language"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Language deleted successfully"})
}

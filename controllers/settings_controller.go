package controllers

import (
	"admin-panel/models"
	"admin-panel/services"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetSettingsHandler retrieves application settings
// @Summary Get application settings
// @Description Retrieve all application settings including general settings and configurations
// @Tags Settings
// @Produce json
// @Success 200 {object} models.ApplicationSettings "Application settings"
// @Failure 500 {object} map[string]interface{} "Failed to retrieve settings"
// @Router /svc/settings [get]
func GetSettingsHandler(c *gin.Context) {
	settings, err := services.GetSettings()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve settings"})
		return
	}
	c.JSON(http.StatusOK, settings)
}

// UpdateSettingsHandler updates application settings
// @Summary Update application settings
// @Description Update application settings with new values
// @Tags Settings
// @Accept json
// @Produce json
// @Param update body map[string]interface{} true "Updated settings data"
// @Success 200 {object} map[string]interface{} "Settings updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request payload"
// @Failure 500 {object} map[string]interface{} "Failed to update settings"
// @Router /svc/settings [put]
func UpdateSettingsHandler(c *gin.Context) {
	var update map[string]interface{}
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updatedBy := c.GetString("username") // Kullanıcı bilgisi JWT'den alınabilir
	if err := services.UpdateSettings(update, updatedBy); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update settings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Settings updated successfully"})
}

// GetSocialMediaLinksHandler retrieves social media links
// @Summary Get social media links
// @Description Retrieve all social media links configured for the application
// @Tags Social Media
// @Produce json
// @Success 200 {object} map[string]interface{} "List of social media links"
// @Failure 500 {object} map[string]interface{} "Failed to retrieve social media links"
// @Router /svc/settings/social-media [get]
func GetSocialMediaLinksHandler(c *gin.Context) {
	links, err := services.GetSocialMediaLinks()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve social media links"})
		return
	}

	c.JSON(http.StatusOK, links)
}

// UpdateSocialMediaLinksHandler updates social media links
// @Summary Update social media links
// @Description Update the social media links for the application
// @Tags Social Media
// @Accept json
// @Produce json
// @Param links body map[string]models.SocialMedia true "Updated social media links"
// @Success 200 {object} map[string]interface{} "Social media links updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request payload"
// @Failure 500 {object} map[string]interface{} "Failed to update social media links"
// @Router /svc/settings/social-media [put]
func UpdateSocialMediaLinksHandler(c *gin.Context) {
	var links map[string]models.SocialMedia
	if err := c.ShouldBindJSON(&links); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updatedBy := c.GetString("username") // Kullanıcı bilgisi
	if err := services.UpdateSocialMediaLinks(links, updatedBy); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update social media links"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Social media links updated successfully"})
}

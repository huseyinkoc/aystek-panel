package controllers

import (
	"admin-panel/models"
	"admin-panel/services"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// CreatePluginHandler creates a new plugin
// @Summary Create a new plugin
// @Description Add a new plugin to the system
// @Tags Plugins
// @Accept json
// @Produce json
// @Param plugin body models.Plugin true "Plugin details"
// @Success 201 {object} models.Plugin "Plugin created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request payload"
// @Failure 500 {object} map[string]interface{} "Failed to create plugin"
// @Router /plugins [post]
func CreatePluginHandler(c *gin.Context) {
	var plugin models.Plugin
	if err := c.ShouldBindJSON(&plugin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := services.CreatePlugin(&plugin); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create plugin"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Plugin created successfully"})
}

// GetAllPluginsHandler retrieves all plugins
// @Summary Get all plugins
// @Description Retrieve all plugins available in the system
// @Tags Plugins
// @Produce json
// @Success 200 {array} models.Plugin "List of plugins"
// @Failure 500 {object} map[string]interface{} "Failed to retrieve plugins"
// @Router /plugins [get]
func GetAllPluginsHandler(c *gin.Context) {
	plugins, err := services.GetAllPlugins()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve plugins"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"plugins": plugins})
}

// UpdatePluginHandler updates an existing plugin
// @Summary Update a plugin
// @Description Update plugin details by its ID
// @Tags Plugins
// @Accept json
// @Produce json
// @Param id path string true "Plugin ID"
// @Param update body map[string]interface{} true "Updated plugin details"
// @Success 200 {object} map[string]interface{} "Plugin updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid plugin ID or request payload"
// @Failure 404 {object} map[string]interface{} "Plugin not found"
// @Failure 500 {object} map[string]interface{} "Failed to update plugin"
// @Router /plugins/{id} [put]
func UpdatePluginHandler(c *gin.Context) {
	id := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plugin ID"})
		return
	}

	var update map[string]interface{}
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := services.UpdatePlugin(objectID, update); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update plugin"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Plugin updated successfully"})
}

// DeletePluginHandler deletes a plugin by ID
// @Summary Delete a plugin
// @Description Remove a plugin by its unique identifier
// @Tags Plugins
// @Param id path string true "Plugin ID"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]interface{} "Invalid plugin ID"
// @Failure 404 {object} map[string]interface{} "Plugin not found"
// @Failure 500 {object} map[string]interface{} "Failed to delete plugin"
// @Router /plugins/{id} [delete]
func DeletePluginHandler(c *gin.Context) {
	id := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plugin ID"})
		return
	}

	if err := services.DeletePlugin(objectID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete plugin"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Plugin deleted successfully"})
}

// UploadPluginHandler uploads a new plugin file
// @Summary Upload a new plugin
// @Description Upload a plugin file (.so) to the system
// @Tags Plugins
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "Plugin file (.so format)"
// @Success 201 {object} map[string]interface{} "Plugin uploaded successfully"
// @Failure 400 {object} map[string]interface{} "Invalid file format or no file uploaded"
// @Failure 500 {object} map[string]interface{} "Failed to upload plugin file"
// @Router /plugins/upload [post]
func UploadPluginHandler(c *gin.Context) {
	// Dosya yükleme
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to get the file"})
		return
	}

	// Dosya adını kontrol et
	if !strings.HasSuffix(file.Filename, ".so") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file format. Only .so files are allowed"})
		return
	}

	// Yükleme dizini
	uploadPath := "./plugins/"
	if err := c.SaveUploadedFile(file, uploadPath+file.Filename); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save the file"})
		return
	}

	pluginPath := uploadPath + file.Filename
	expectedHash := "expected_sha256_hash_value"
	isValid, err := services.VerifyPluginIntegrity(pluginPath, expectedHash)
	if err != nil || !isValid {
		log.Println("Plugin integrity check failed")
		return
	}
	log.Println("Plugin is valid")

	c.JSON(http.StatusOK, gin.H{"message": "Plugin uploaded successfully", "file": file.Filename})
}

// ListUploadedPluginsHandler lists all uploaded plugin files
// @Summary List uploaded plugins
// @Description Retrieve a list of all uploaded plugin files in the system
// @Tags Plugins
// @Produce json
// @Success 200 {array} map[string]interface{} "List of uploaded plugins"
// @Failure 500 {object} map[string]interface{} "Failed to retrieve uploaded plugins"
// @Router /plugins/uploaded [get]
func ListUploadedPluginsHandler(c *gin.Context) {
	plugins, err := services.ListUploadedPlugins()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list plugins"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"plugins": plugins})
}

// EnablePluginHandler enables a plugin
// @Summary Enable a plugin
// @Description Enable a specific plugin by its ID
// @Tags Plugins
// @Param id path string true "Plugin ID"
// @Success 200 {object} map[string]interface{} "Plugin enabled successfully"
// @Failure 400 {object} map[string]interface{} "Invalid plugin ID"
// @Failure 404 {object} map[string]interface{} "Plugin not found"
// @Failure 500 {object} map[string]interface{} "Failed to enable plugin"
// @Router /plugins/{id}/enable [patch]
func EnablePluginHandler(c *gin.Context) {
	id := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plugin ID"})
		return
	}

	if err := services.EnablePlugin(objectID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enable plugin"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Plugin enabled successfully"})
}

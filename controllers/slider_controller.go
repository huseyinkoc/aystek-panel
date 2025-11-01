package controllers

import (
	"admin-panel/models"
	"admin-panel/services"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// CreateSliderHandler creates a new slider
// @Summary Create a new slider
// @Description Add a new slider with its details
// @Tags Sliders
// @Accept json
// @Produce json
// @Param slider body models.Slider true "Slider details"
// @Success 201 {object} map[string]interface{} "Slider created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request payload"
// @Failure 500 {object} map[string]interface{} "Failed to create slider"
// @Router /sliders [post]
func CreateSliderHandler(c *gin.Context) {
	var slider models.Slider
	if err := c.ShouldBindJSON(&slider); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := services.CreateSlider(&slider); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create slider"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Slider created successfully"})
}

// GetSlidersHandler retrieves all sliders
// @Summary Get all sliders
// @Description Retrieve all sliders with their details
// @Tags Sliders
// @Produce json
// @Success 200 {array} models.Slider "List of sliders"
// @Failure 500 {object} map[string]interface{} "Failed to retrieve sliders"
// @Router /sliders [get]
func GetSlidersHandler(c *gin.Context) {
	sliders, err := services.GetSliders()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve sliders"})
		return
	}

	c.JSON(http.StatusOK, sliders)
}

// UpdateSliderHandler updates an existing slider
// @Summary Update a slider
// @Description Update the details of a specific slider by its ID
// @Tags Sliders
// @Accept json
// @Produce json
// @Param id path string true "Slider ID"
// @Param update body map[string]interface{} true "Updated slider details"
// @Success 200 {object} map[string]interface{} "Slider updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid slider ID or request payload"
// @Failure 500 {object} map[string]interface{} "Failed to update slider"
// @Router /sliders/{id} [put]
func UpdateSliderHandler(c *gin.Context) {
	id := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid slider ID"})
		return
	}

	var update map[string]interface{}
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := services.UpdateSlider(objectID, update); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update slider"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Slider updated successfully"})
}

// DeleteSliderHandler deletes a slider by ID
// @Summary Delete a slider
// @Description Remove a slider by its unique identifier
// @Tags Sliders
// @Param id path string true "Slider ID"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]interface{} "Invalid slider ID"
// @Failure 500 {object} map[string]interface{} "Failed to delete slider"
// @Router /sliders/{id} [delete]
func DeleteSliderHandler(c *gin.Context) {
	id := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid slider ID"})
		return
	}

	if err := services.DeleteSlider(objectID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete slider"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Slider deleted successfully"})
}

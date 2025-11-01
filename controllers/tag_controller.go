package controllers

import (
	"admin-panel/models"
	"admin-panel/services"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// CreateTagHandler creates a new tag
// @Summary Create a new tag
// @Description Add a new tag with its details
// @Tags Tags
// @Accept json
// @Produce json
// @Param tag body models.Tag true "Tag details"
// @Success 201 {object} models.Tag "Tag created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request payload"
// @Failure 500 {object} map[string]interface{} "Failed to create tag"
// @Router /tags [post]
func CreateTagHandler(c *gin.Context) {
	var tag models.Tag
	if err := c.ShouldBindJSON(&tag); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := services.CreateTag(tag)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tag"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Tag created successfully"})
}

// GetAllTagsHandler retrieves all tags
// @Summary Get all tags
// @Description Retrieve all tags with their details
// @Tags Tags
// @Produce json
// @Success 200 {array} models.Tag "List of tags"
// @Failure 500 {object} map[string]interface{} "Failed to retrieve tags"
// @Router /tags [get]
func GetAllTagsHandler(c *gin.Context) {
	tags, err := services.GetAllTags()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve tags"})
		return
	}

	c.JSON(http.StatusOK, tags)
}

// GetTagByIDHandler retrieves a tag by ID
// @Summary Get a tag by ID
// @Description Retrieve a single tag by its unique identifier
// @Tags Tags
// @Produce json
// @Param id path string true "Tag ID"
// @Success 200 {object} models.Tag "Tag details"
// @Failure 400 {object} map[string]interface{} "Invalid tag ID"
// @Failure 404 {object} map[string]interface{} "Tag not found"
// @Failure 500 {object} map[string]interface{} "Failed to retrieve tag"
// @Router /tags/{id} [get]
func GetTagByIDHandler(c *gin.Context) {
	id := c.Param("id")

	// ObjectID dönüşümü
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tag ID"})
		return
	}

	// Servisi çağır
	tag, err := services.GetTagByID(c.Request.Context(), objectID)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tag not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve tag"})
		return
	}

	c.JSON(http.StatusOK, tag)
}

// UpdateTagHandler updates an existing tag
// @Summary Update a tag
// @Description Update the details of a specific tag by its ID
// @Tags Tags
// @Accept json
// @Produce json
// @Param id path string true "Tag ID"
// @Param tag body models.Tag true "Updated tag details"
// @Success 200 {object} models.Tag "Tag updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid tag ID or request payload"
// @Failure 404 {object} map[string]interface{} "Tag not found"
// @Failure 500 {object} map[string]interface{} "Failed to update tag"
// @Router /tags/{id} [put]
func UpdateTagHandler(c *gin.Context) {
	id := c.Param("id")

	// ObjectID dönüşümü
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tag ID"})
		return
	}

	// JSON bind
	var updatedTag models.Tag
	if err := c.ShouldBindJSON(&updatedTag); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	// Güncellemeyi servise gönder
	err = services.UpdateTag(c.Request.Context(), objectID, &updatedTag)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tag not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tag"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Tag updated successfully", "tag": updatedTag})
}

// DeleteTagHandler deletes a tag by ID
// @Summary Delete a tag
// @Description Remove a tag by its unique identifier
// @Tags Tags
// @Param id path string true "Tag ID"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]interface{} "Invalid tag ID"
// @Failure 404 {object} map[string]interface{} "Tag not found"
// @Failure 500 {object} map[string]interface{} "Failed to delete tag"
// @Router /tags/{id} [delete]
func DeleteTagHandler(c *gin.Context) {
	id := c.Param("id")

	// ObjectID dönüşümü
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tag ID"})
		return
	}

	// Silme işlemini servise gönder
	err = services.DeleteTag(c.Request.Context(), objectID)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tag not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete tag"})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

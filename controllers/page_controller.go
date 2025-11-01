package controllers

import (
	"admin-panel/models"
	"admin-panel/services"
	"admin-panel/utils"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// CreatePageHandler creates a new page
// @Summary Create a new page
// @Description Add a new page with its details
// @Tags Pages
// @Accept json
// @Produce json
// @Param page body models.Page true "Page details"
// @Success 201 {object} models.Page
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /pages [post]
func CreatePageHandler(c *gin.Context) {
	var page models.Page

	if err := c.ShouldBindJSON(&page); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := services.CreatePage(page)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create page"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Page created successfully"})
}

// GetAllPagesHandler retrieves all pages
// @Summary Get all pages
// @Description Retrieve all pages with their details
// @Tags Pages
// @Produce json
// @Success 200 {array} models.Page
// @Failure 500 {object} map[string]string
// @Router /pages [get]
func GetAllPagesHandler(c *gin.Context) {
	pages, err := services.GetAllPages()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve pages"})
		return
	}

	c.JSON(http.StatusOK, pages)
}

// GetPageByIDHandler retrieves a page by ID
// @Summary Get a page by ID
// @Description Retrieve a single page by its unique identifier
// @Tags Pages
// @Produce json
// @Param id path string true "Page ID"
// @Success 200 {object} models.Page
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /pages/{id} [get]
func GetPageByIDHandler(c *gin.Context) {
	id := c.Param("id")

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid page ID"})
		return
	}

	page, err := services.GetPageByID(c.Request.Context(), objectID)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "Page not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch page", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, page)
}

// UpdatePageHandler updates an existing page
// @Summary Update a page
// @Description Update a page's details
// @Tags Pages
// @Accept json
// @Produce json
// @Param id path string true "Page ID"
// @Param page body models.Page true "Updated page details"
// @Success 200 {object} models.Page
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /pages/{id} [put]
func UpdatePageHandler(c *gin.Context) {
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid page ID"})
		return
	}

	var update map[string]interface{}
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Slug kontrolü
	if title, ok := update["title"].(string); ok {
		update["slug"] = utils.GenerateSlug(title)
	}

	_, err = services.UpdatePage(id, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update page"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Page updated successfully"})
}

// DeletePageHandler deletes a page by ID
// @Summary Delete a page
// @Description Remove a page by its unique identifier
// @Tags Pages
// @Param id path string true "Page ID"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /pages/{id} [delete]
func DeletePageHandler(c *gin.Context) {
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid page ID"})
		return
	}

	_, err = services.DeletePage(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete page"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Page deleted successfully"})
}

package controllers

import (
	"admin-panel/models"
	"admin-panel/services"
	"admin-panel/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// CreateCategoryHandler creates a new category
// @Summary Create a new category
// @Description Add a new category with its details
// @Tags Categories
// @Accept json
// @Produce json
// @Param category body models.Category true "Category details"
// @Success 201 {object} models.Category
// @Failure 400 {object} map[string]interface{} "Invalid request payload"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /categories [post]
func CreateCategoryHandler(c *gin.Context) {
	var category models.Category
	if err := c.ShouldBindJSON(&category); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Slug kontrolü
	if category.Slug == nil {
		category.Slug = make(map[string]string) // Slug map'ini başlat
	}

	for lang, localization := range category.Localizations {
		if localization.Title != "" {
			category.Slug[lang] = utils.GenerateSlug(localization.Title) // Her dil için slug oluştur
		} else if lang == "en" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "English title is required for slug generation"})
			return
		}
	}

	_, err := services.CreateCategory(category)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create category"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Category created successfully"})
}

// GetAllCategoriesHandler retrieves all categories
// @Summary Get all categories
// @Description Retrieve all categories with their details
// @Tags Categories
// @Produce json
// @Success 200 {array} models.Category
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /categories [get]
func GetAllCategoriesHandler(c *gin.Context) {
	categories, err := services.GetAllCategories()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve categories"})
		return
	}

	c.JSON(http.StatusOK, categories)
}

// GetCategoryByIDHandler retrieves a category by ID
// @Summary Get a category by ID
// @Description Retrieve a single category by its unique identifier
// @Tags Categories
// @Produce json
// @Param id path string true "Category ID"
// @Success 200 {object} models.Category
// @Failure 400 {object} map[string]interface{} "Invalid category ID"
// @Failure 404 {object} map[string]interface{} "Category not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /categories/{id} [get]
func GetCategoryByIDHandler(c *gin.Context) {
	id := c.Param("id")

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid category ID"})
		return
	}

	category, err := services.GetCategoryByID(c.Request.Context(), objectID)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "Category not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve category"})
		return
	}

	c.JSON(http.StatusOK, category)
}

// UpdateCategoryHandler updates an existing category
// @Summary Update a category
// @Description Update a category's details
// @Tags Categories
// @Accept json
// @Produce json
// @Param id path string true "Category ID"
// @Param category body models.Category true "Updated category details"
// @Success 200 {object} models.Category
// @Failure 400 {object} map[string]interface{} "Invalid request payload or category ID"
// @Failure 404 {object} map[string]interface{} "Category not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /categories/{id} [put]
func UpdateCategoryHandler(c *gin.Context) {
	id := c.Param("id")

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid category ID"})
		return
	}

	var updatedCategory models.Category
	if err := c.ShouldBindJSON(&updatedCategory); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	updatedCategory.UpdatedAt = primitive.NewDateTimeFromTime(time.Now())

	if err := services.UpdateCategory(c.Request.Context(), objectID, &updatedCategory); err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "Category not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update category"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Category updated successfully", "category": updatedCategory})
}

// DeleteCategoryHandler deletes a category by ID
// @Summary Delete a category
// @Description Remove a category by its unique identifier
// @Tags Categories
// @Param id path string true "Category ID"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]interface{} "Invalid category ID"
// @Failure 404 {object} map[string]interface{} "Category not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /categories/{id} [delete]
func DeleteCategoryHandler(c *gin.Context) {
	id := c.Param("id")

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid category ID"})
		return
	}

	if err := services.DeleteCategory(c.Request.Context(), objectID); err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "Category not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete category"})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

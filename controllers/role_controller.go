package controllers

import (
	"admin-panel/models"
	"admin-panel/services"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// CreateRoleHandler creates a new role
// @Summary Create a new role
// @Description Add a new role with its permissions and details
// @Tags Roles
// @Accept json
// @Produce json
// @Param role body models.Role true "Role details"
// @Success 201 {object} models.Role "Role created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request payload"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Failed to create role"
// @Router /roles [post]
func CreateRoleHandler(c *gin.Context) {
	var role models.Role

	if err := c.ShouldBindJSON(&role); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Kimin oluşturduğunu al
	createdBy, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized A2"})
		return
	}
	role.CreatedBy = createdBy.(string)
	role.UpdatedBy = createdBy.(string)
	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()

	// Veritabanına ekle
	_, err := services.CreateRole(c.Request.Context(), role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create role"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Role created successfully", "role": role})
}

// GetAllRolesHandler retrieves all roles
// @Summary Get all roles
// @Description Retrieve all roles with their permissions and details
// @Tags Roles
// @Produce json
// @Success 200 {array} models.Role "List of roles"
// @Failure 500 {object} map[string]interface{} "Failed to retrieve roles"
// @Router /roles [get]
func GetAllRolesHandler(c *gin.Context) {
	roles, err := services.GetAllRoles(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve roles"})
		fmt.Println("Database error during role retrieval:", err)
		return
	}

	c.JSON(http.StatusOK, roles)
}

// UpdateRoleHandler updates an existing role
// @Summary Update a role
// @Description Update role details, including permissions
// @Tags Roles
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Param update body map[string]interface{} true "Updated role details"
// @Success 200 {object} map[string]interface{} "Role updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid role ID or request payload"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Role not found"
// @Failure 500 {object} map[string]interface{} "Failed to update role"
// @Router /roles/{id} [put]
func UpdateRoleHandler(c *gin.Context) {
	id := c.Param("id")

	var update map[string]interface{}
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	updatedBy, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	update["updated_by"] = updatedBy.(string)
	update["updated_at"] = time.Now()

	updatedCount, err := services.UpdateRole(c.Request.Context(), id, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update role"})
		return
	}

	if updatedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Role updated successfully"})
}

// DeleteRoleHandler deletes a role by ID
// @Summary Delete a role
// @Description Remove a role by its unique identifier
// @Tags Roles
// @Param id path string true "Role ID"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]interface{} "Invalid role ID"
// @Failure 404 {object} map[string]interface{} "Role not found"
// @Failure 500 {object} map[string]interface{} "Failed to delete role"
// @Router /roles/{id} [delete]
func DeleteRoleHandler(c *gin.Context) {
	id := c.Param("id")

	deletedCount, err := services.DeleteRole(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete role"})
		return
	}

	if deletedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Role deleted successfully"})
}

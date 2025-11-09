package controllers

import (
	"admin-panel/models"
	"admin-panel/services"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
		return
	}

	role.ID = primitive.NewObjectID()
	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()

	// Role içindeki izinlerin ID olarak geldiğini varsay
	if len(role.Permissions) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Permissions required"})
		return
	}

	if _, err := rolesCollection.InsertOne(c, role); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save role"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Role created successfully",
		"id":      role.ID.Hex(),
	})
}

// GetAllRolesHandler retrieves all roles
// @Summary Get all roles
// @Description Retrieve all roles with their permissions and details
// @Tags Roles
// @Produce json
// @Success 200 {array} models.Role "List of roles"
// @Failure 500 {object} map[string]interface{} "Failed to retrieve roles"
// @Router /svc/roles [get]
func GetAllRolesHandler(c *gin.Context) {
	roles, err := services.GetAllRoles(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve roles"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"roles": roles})
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
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	var role models.Role
	if err := c.ShouldBindJSON(&role); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
		return
	}

	username, _ := c.Get("username")
	role.UpdatedBy = username.(string)
	role.UpdatedAt = time.Now()

	if err := services.UpdateRole(c.Request.Context(), oid, role); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update role"})
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
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	if err := services.DeleteRole(c.Request.Context(), oid); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete role"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Role deleted successfully"})
}

// GetRoleHandler retrieves a role by its ID
// @Summary Get a role by ID
// @Description Retrieve a role with its permissions and details by its unique identifier
// @Tags Roles
// @Produce json
// @Success 200 {object} models.Role "Role details"
// @Failure 400 {object} map[string]interface{} "Invalid role ID"
// @Failure 404 {object} map[string]interface{} "Role not found"
// @Failure 500 {object} map[string]interface{} "Failed to retrieve role"
// @Router /roles/{id} [get]
func GetRoleHandler(c *gin.Context) {
	id := c.Param("id")
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role ID"})
		return
	}

	role, err := services.GetRoleByID(c.Request.Context(), oid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"role": role})
}

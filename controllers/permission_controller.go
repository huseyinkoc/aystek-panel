package controllers

import (
	"admin-panel/models"
	"admin-panel/services"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// CreatePermissionHandler — Yeni modül/permission oluştur
// @Summary Create a permission module
// @Tags Permissions
// @Accept json
// @Produce json
// @Param body body models.Permission true "Permission module"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Router /svc/permissions [post]
func CreatePermissionHandler(c *gin.Context) {
	var module models.Permission
	if err := c.ShouldBindJSON(&module); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
		return
	}

	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	module.CreatedBy = username.(string)
	module.UpdatedBy = username.(string)
	module.CreatedAt = time.Now()
	module.UpdatedAt = time.Now()

	result, err := services.CreatePermission(c.Request.Context(), module)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Permission created successfully", "id": result.InsertedID})
}

// GetAllPermissionsHandler — tüm modülleri getir
// @Summary Get all permission modules
// @Tags Permissions
// @Produce json
// @Success 200 {array} models.Permission
// @Router /svc/permissions [get]
func GetAllPermissionsHandler(c *gin.Context) {
	perms, err := services.GetAllPermissions(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve permissions"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"count": len(perms), "permissions": perms})
}

// GetPermissionHandler — tek modül getir
// @Summary Get permission module by ID
// @Tags Permissions
// @Produce json
// @Param id path string true "Permission ID"
// @Router /svc/permissions/{id} [get]
func GetPermissionHandler(c *gin.Context) {
	id := c.Param("id")
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	module, err := services.GetPermissionByID(c.Request.Context(), oid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Permission not found"})
		return
	}
	c.JSON(http.StatusOK, module)
}

// UpdatePermissionHandler — modül güncelle
// @Summary Update permission module
// @Tags Permissions
// @Accept json
// @Produce json
// @Param id path string true "Permission ID"
// @Param body body models.Permission true "Updated data"
// @Router /svc/permissions/{id} [put]
func UpdatePermissionHandler(c *gin.Context) {
	id := c.Param("id")
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	var module models.Permission
	if err := c.ShouldBindJSON(&module); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
		return
	}

	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	module.UpdatedBy = username.(string)
	if err := services.UpdatePermission(c.Request.Context(), oid, module); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update permission"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Permission updated successfully"})
}

// DeletePermissionHandler — modül sil
// @Summary Delete permission module
// @Tags Permissions
// @Param id path string true "Permission ID"
// @Router /svc/permissions/{id} [delete]
func DeletePermissionHandler(c *gin.Context) {
	id := c.Param("id")
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	if err := services.DeletePermission(c.Request.Context(), oid); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete permission"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Permission deleted successfully"})
}

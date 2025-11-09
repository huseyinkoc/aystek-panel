package controllers

import (
	"admin-panel/models"
	"admin-panel/services"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ✅ Tüm modülleri getir
func GetPermissionModules(c *gin.Context) {
	modules, err := services.GetAllPermissionModules(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve modules"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"modules": modules})
}

// ✅ Yeni modül oluştur
func CreatePermissionModule(c *gin.Context) {
	var module models.PermissionModule
	if err := c.ShouldBindJSON(&module); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})
		return
	}

	username, _ := c.Get("username")
	if uname, ok := username.(string); ok {
		module.CreatedBy = uname
		module.UpdatedBy = uname
	}
	module.CreatedAt = time.Now()
	module.UpdatedAt = time.Now()

	res, err := services.CreatePermissionModule(c.Request.Context(), module)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Permission module created successfully",
		"id":      res.InsertedID,
		"module":  module,
	})
}

// ✅ Güncelle
func UpdatePermissionModule(c *gin.Context) {
	id := c.Param("id")
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	var module models.PermissionModule
	if err := c.ShouldBindJSON(&module); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})
		return
	}

	username, _ := c.Get("username")
	if uname, ok := username.(string); ok {
		module.UpdatedBy = uname
	}
	module.UpdatedAt = time.Now()

	if err := services.UpdatePermissionModule(c.Request.Context(), oid, module); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update module"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Module updated successfully"})
}

// ✅ Sil
func DeletePermissionModule(c *gin.Context) {
	id := c.Param("id")
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	if err := services.DeletePermissionModule(c.Request.Context(), oid); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete module"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Module deleted successfully"})
}

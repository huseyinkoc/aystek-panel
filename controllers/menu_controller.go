package controllers

import (
	"admin-panel/models"
	"admin-panel/services"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"log"
)

// @Summary Create a new menu
// @Description Add a new menu with its details
// @Tags Menus
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer Token"
// @Param menu body models.Menu true "Menu details"
// @Success 201 {object} models.Menu "Menu created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request payload"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Failed to create menu"
// @Router /menus [post]
func CreateMenuHandler(c *gin.Context) {
	var menu models.Menu

	// Bind JSON payload to menu model
	if err := c.ShouldBindJSON(&menu); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set metadata
	createdBy, exists := c.Get("username")
	if exists {
		menu.CreatedBy = createdBy.(string)
		menu.UpdatedBy = createdBy.(string)
	}

	menu.CreatedAt = time.Now()
	menu.UpdatedAt = time.Now()

	// Create menu in database
	createdMenu, err := services.CreateMenu(c.Request.Context(), &menu)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create menu"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Menu created successfully", "menu": createdMenu})
}

// @Summary Get all menus
// @Description Retrieve all menus, including frontend and backend menus
// @Tags Menus
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer Token"
// @Param type query string false "Menu type (frontend or backend)"
// @Success 200 {array} models.Menu "List of menus"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Failed to retrieve menus"
// @Router /menus [get]
func GetMenusHandler(c *gin.Context) {
    menuType := c.Query("type") // frontend or backend
    if menuType == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Menu type is required"})
        return
    }

    // Retrieve user roles from context
    rawRoles, exists := c.Get("roles")
    if !exists || rawRoles == nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }

    // Normalize/resolve roles to role names
    var roleNames []string
    switch v := rawRoles.(type) {
    case []string:
        for _, it := range v {
            it = strings.TrimSpace(it)
            if it == "" {
                continue
            }
            // if looks like ObjectID, resolve to name
            if oid, err := primitive.ObjectIDFromHex(it); err == nil {
                if role, err := services.ReadRole(c.Request.Context(), oid.Hex()); err == nil && role != nil {
                    roleNames = append(roleNames, role.Name)
                    continue
                } else {
                    log.Printf("GetMenusHandler: failed to resolve role id %s: %v", it, err)
                }
            }
            roleNames = append(roleNames, strings.ToLower(it))
        }
    case []interface{}:
        for _, itf := range v {
            if s, ok := itf.(string); ok {
                s = strings.TrimSpace(s)
                if s == "" {
                    continue
                }
                if oid, err := primitive.ObjectIDFromHex(s); err == nil {
                    if role, err := services.ReadRole(c.Request.Context(), oid.Hex()); err == nil && role != nil {
                        roleNames = append(roleNames, role.Name)
                        continue
                    } else {
                        log.Printf("GetMenusHandler: failed to resolve role id %s: %v", s, err)
                    }
                }
                roleNames = append(roleNames, strings.ToLower(s))
            }
        }
    case string:
        s := strings.TrimSpace(v)
        if s != "" {
            // comma separated or single
            parts := strings.Split(s, ",")
            for _, p := range parts {
                p = strings.TrimSpace(p)
                if p == "" {
                    continue
                }
                if oid, err := primitive.ObjectIDFromHex(p); err == nil {
                    if role, err := services.ReadRole(c.Request.Context(), oid.Hex()); err == nil && role != nil {
                        roleNames = append(roleNames, role.Name)
                        continue
                    } else {
                        log.Printf("GetMenusHandler: failed to resolve role id %s: %v", p, err)
                    }
                }
                roleNames = append(roleNames, strings.ToLower(p))
            }
        }
    default:
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid roles format"})
        return
    }

    if len(roleNames) == 0 {
        c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions (no roles) to view menus for this type"})
        return
    }

    // Fetch menus based on resolved role names and type
    menus, err := services.GetMenusByRoles(c.Request.Context(), menuType, roleNames)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch menus", "details": err.Error()})
        return
    }

    // Eğer halen boş dönüyorsa, logla ve detay ver
    if len(menus) == 0 {
        log.Printf("GetMenusHandler: no menus for type=%s roles=%v", menuType, roleNames)
        c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions to view menus for this type"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"menus": menus})
}

// @Summary Update a menu
// @Description Update menu details by its ID
// @Tags Menus
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer Token"
// @Param id path string true "Menu ID"
// @Param menu body models.Menu true "Updated menu details"
// @Success 200 {object} models.Menu "Menu updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request payload or menu ID"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Menu not found"
// @Failure 500 {object} map[string]interface{} "Failed to update menu"
// @Router /menus/{id} [put]
func UpdateMenuHandler(c *gin.Context) {
	id := c.Param("id")

	var update bson.M
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set updated metadata
	updatedBy, exists := c.Get("username")
	if exists {
		update["updated_by"] = updatedBy.(string)
	}
	update["updated_at"] = time.Now()

	// Update menu in database
	updatedMenu, err := services.UpdateMenu(c.Request.Context(), id, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update menu", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Menu updated successfully", "menu": updatedMenu})
}

// @Summary Delete a menu
// @Description Remove a menu by its unique identifier
// @Tags Menus
// @Security BearerAuth
// @Param Authorization header string true "Bearer Token"
// @Param id path string true "Menu ID"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]interface{} "Invalid menu ID"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Menu not found"
// @Failure 500 {object} map[string]interface{} "Failed to delete menu"
// @Router /menus/{id} [delete]
func DeleteMenuHandler(c *gin.Context) {
	id := c.Param("id")

	// Delete menu from database
	if err := services.DeleteMenu(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete menu", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Menu deleted successfully"})
}

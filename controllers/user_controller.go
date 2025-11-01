package controllers

import (
	"admin-panel/models"
	"admin-panel/services"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// CreateUserHandler creates a new user
// @Summary Create a new user
// @Description Add a new user with roles and hashed password
// @Tags Users
// @Accept json
// @Produce json
// @Param user body models.User true "User details"
// @Success 200 {object} map[string]interface{} "User created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request payload"
// @Failure 500 {object} map[string]interface{} "Failed to create user"
// @Router /users [post]
func CreateUserHandler(c *gin.Context) {
	var user models.User

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Şifre kontrolü
	if user.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password cannot be empty"})
		return
	}

	// Rolleri kontrol et
	if len(user.Roles) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Roles cannot be empty"})
		return
	}

	// Şifreyi hashle
	hashedPassword, err := services.HashPassword(user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	user.Password = hashedPassword

	// FullName oluştur
	user.FullName = fmt.Sprintf("%s %s", user.Name, user.Surname)

	// Veritabanına ekle
	_, err = services.CreateUser(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User created successfully", "user": user})
}

// GetAllUsersHandler retrieves all users
// @Summary Get all users
// @Description Retrieve all users with their details
// @Tags Users
// @Produce json
// @Success 200 {array} models.User "List of users"
// @Failure 500 {object} map[string]interface{} "Failed to retrieve users"
// @Router /users [get]
func GetAllUsersHandler(c *gin.Context) {
	users, err := services.GetAllUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve users"})
		fmt.Println("Database error during user retrieval:", err)
		return
	}

	c.JSON(http.StatusOK, users)
}

// UpdateUserHandler updates an existing user
// @Summary Update a user
// @Description Update user details including name, roles, and password
// @Tags Users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param user body map[string]interface{} true "Updated user details"
// @Success 200 {object} map[string]interface{} "User updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request payload or user ID"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Failure 500 {object} map[string]interface{} "Failed to update user"
// @Router /users/{id} [put]
func UpdateUserHandler(c *gin.Context) {
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var update map[string]interface{}
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Şifre güncelleniyorsa hashle
	if password, ok := update["password"].(string); ok && password != "" {
		hashedPassword, err := services.HashPassword(password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		update["password"] = hashedPassword
	} else {
		delete(update, "password")
	}

	// Roller güncelleniyorsa kontrol et
	if roles, ok := update["roles"]; ok {
		userRole, _ := c.Get("role")
		if userRole != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to change roles"})
			return
		}
		update["roles"] = roles
	}

	// FullName güncelleniyorsa
	if name, ok := update["name"].(string); ok {
		update["name"] = name
	}
	if surname, ok := update["surname"].(string); ok {
		update["surname"] = surname
	}
	if name, nameOk := update["name"].(string); nameOk {
		if surname, surnameOk := update["surname"].(string); surnameOk {
			update["full_name"] = fmt.Sprintf("%s %s", name, surname)
		}
	}

	_, err = services.UpdateUser(id, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

// DeleteUserHandler deletes a user by ID
// @Summary Delete a user
// @Description Remove a user by its unique identifier
// @Tags Users
// @Param id path string true "User ID"
// @Success 200 {object} map[string]interface{} "User deleted successfully"
// @Failure 400 {object} map[string]interface{} "Invalid user ID"
// @Failure 500 {object} map[string]interface{} "Failed to delete user"
// @Router /users/{id} [delete]
func DeleteUserHandler(c *gin.Context) {
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		fmt.Println("Invalid ID format:", err)
		return
	}

	_, err = services.DeleteUser(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		fmt.Println("Database error during deletion:", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// UpdatePreferredLanguageHandler updates the preferred language for a user
// @Summary Update preferred language
// @Description Update the preferred language of the current user
// @Tags Users
// @Accept json
// @Produce json
// @Param request body models.PreferredLanguageRequest true "Preferred language request"
// @Success 200 {object} map[string]interface{} "Preferred language updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid language code or disabled language"
// @Failure 500 {object} map[string]interface{} "Failed to update preferred language"
// @Router /users/language [put]
func UpdatePreferredLanguageHandler(c *gin.Context) {
	userID := c.GetString("userID") // Kullanıcı kimliği JWT'den alınır

	var input struct {
		LanguageCode string `json:"language_code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verilen dil aktif mi kontrol et
	enabled, err := services.IsLanguageEnabled(input.LanguageCode)
	if err != nil || !enabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or disabled language"})
		return
	}

	// Kullanıcının dil tercihini güncelle
	if err := services.UpdateUserPreferredLanguage(userID, input.LanguageCode); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update preferred language"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Preferred language updated successfully"})
}

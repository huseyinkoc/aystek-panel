package controllers

import (
	"admin-panel/models"
	"admin-panel/services"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// CreateContactHandler creates a new contact message
// @Summary Create a new contact message
// @Description Add a new contact message sent by a user
// @Tags Contacts
// @Accept json
// @Produce json
// @Param contact body models.ContactMessage true "Contact message details"
// @Success 201 {object} models.ContactMessage
// @Failure 400 {object} map[string]interface{} "Invalid request payload"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /contacts [post]
func CreateContactMessageHandler(c *gin.Context) {
	var message models.ContactMessage
	if err := c.ShouldBindJSON(&message); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	createdMessage, err := services.CreateContactMessage(c.Request.Context(), &message)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save contact message", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Contact message sent successfully", "data": createdMessage})
}

// GetAllContactsHandler retrieves all contact messages
// @Summary Get all contact messages
// @Description Retrieve all contact messages sent by users
// @Tags Contacts
// @Produce json
// @Success 200 {array} models.ContactMessage
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /contacts [get]
func GetAllContactMessagesHandler(c *gin.Context) {
	messages, err := services.GetAllContactMessages(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch contact messages", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": messages})
}

// GetContactByIDHandler retrieves a contact message by ID
// @Summary Get a contact message by ID
// @Description Retrieve a single contact message by its unique identifier
// @Tags Contacts
// @Produce json
// @Param id path string true "Contact Message ID"
// @Success 200 {object} models.ContactMessage
// @Failure 400 {object} map[string]interface{} "Invalid contact ID"
// @Failure 404 {object} map[string]interface{} "Contact message not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /contacts/{id} [get]
func GetContactByIDHandler(c *gin.Context) {
	id := c.Param("id")

	// MongoDB ObjectID dönüşümü
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid contact ID"})
		return
	}

	// Servis çağrısı
	contact, err := services.GetContactByID(c.Request.Context(), objectID)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "Contact message not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve contact message", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, contact)
}

func UpdateContactMessageStatusHandler(c *gin.Context) {
	id := c.Param("id")
	status := c.Query("status")

	if status == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Status is required"})
		return
	}

	resolvedBy, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	err := services.UpdateContactMessageStatus(c.Request.Context(), id, status, resolvedBy.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update contact message status", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Contact message status updated successfully"})
}

// DeleteContactHandler deletes a contact message by ID
// @Summary Delete a contact message
// @Description Remove a contact message by its unique identifier
// @Tags Contacts
// @Param id path string true "Contact ID"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]interface{} "Invalid contact ID"
// @Failure 404 {object} map[string]interface{} "Contact message not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /contacts/{id} [delete]
func DeleteContactMessageHandler(c *gin.Context) {
	id := c.Param("id")

	err := services.DeleteContactMessage(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete contact message", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Contact message deleted successfully"})
}

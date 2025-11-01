package controllers

import (
	"admin-panel/services"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// CreateNotificationHandler creates a new notification
// @Summary Create a new notification
// @Description Add a notification for a specific user or action
// @Tags Notifications
// @Accept json
// @Produce json
// @Param notification body models.Notification true "Notification details"
// @Success 201 {object} models.Notification "Notification created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request payload"
// @Failure 500 {object} map[string]interface{} "Failed to create notification"
// @Router /notifications [post]
func GetNotificationsHandler(c *gin.Context) {
	// Context'ten userID al
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// userID'yi ObjectID'ye çevir
	userObjectID, err := primitive.ObjectIDFromHex(userID.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	// Bildirimleri getir
	notifications, err := services.FetchNotificationsByUserID(c.Request.Context(), userObjectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch notifications", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"notifications": notifications})
}

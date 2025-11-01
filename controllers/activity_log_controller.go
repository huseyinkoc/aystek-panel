package controllers

import (
	"admin-panel/services"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetAllActivityLogsHandler retrieves all activity logs
// @Summary Get all activity logs
// @Description Retrieve all activity logs with their details
// @Tags Activity Logs
// @Produce json
// @Success 200 {array} models.ActivityLog "List of activity logs"
// @Failure 500 {object} map[string]interface{} "Failed to retrieve activity logs"
// @Router /activity-logs [get]
func GetActivityLogsHandler(c *gin.Context) {
	// Filtreleme ve limit parametrelerini al
	limit := 100
	filter := map[string]interface{}{}

	logs, err := services.GetActivityLogs(filter, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve activity logs"})
		return
	}

	c.JSON(http.StatusOK, logs)
}

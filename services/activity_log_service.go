package services

import (
	"admin-panel/models"
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var activityLogCollection *mongo.Collection

func InitActivityLogService(client *mongo.Client) {
	activityLogCollection = client.Database("admin_panel").Collection("activity_logs")
}

// LogActivity logs a user activity
func LogActivity(userID primitive.ObjectID, username, module, action, details string) error {
	log := models.ActivityLog{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		Username:  username,
		Module:    module,
		Action:    action,
		Details:   details,
		Timestamp: time.Now(),
	}

	_, err := activityLogCollection.InsertOne(context.Background(), log)
	return err
}

// GetActivityLogs retrieves activity logs with optional filters
func GetActivityLogs(filter bson.M, limit int) ([]models.ActivityLog, error) {
	var logs []models.ActivityLog

	opts := options.Find().SetLimit(int64(limit)).SetSort(bson.M{"timestamp": -1})
	cursor, err := activityLogCollection.Find(context.Background(), filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var log models.ActivityLog
		if err := cursor.Decode(&log); err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}

	return logs, nil
}

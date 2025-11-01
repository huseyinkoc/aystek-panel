package services

import (
	"context"
	"time"

	"admin-panel/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var notificationCollection *mongo.Collection

// InitNotificationService initializes the notification collection
func InitNotificationService(client *mongo.Client) {
	notificationCollection = client.Database("admin_panel").Collection("notifications")
}

// InsertNotification inserts a new notification into the database
func InsertNotification(ctx context.Context, notification *models.Notification) (*mongo.InsertOneResult, error) {
	notification.ID = primitive.NewObjectID()
	notification.CreatedAt = time.Now()
	result, err := notificationCollection.InsertOne(ctx, notification)
	return result, err
}

// CreateNotification creates a new notification for a user
func CreateNotification(ctx context.Context, userID primitive.ObjectID, message string) error {
	notification := models.Notification{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		Message:   message,
		IsRead:    false,
		CreatedAt: time.Now(),
	}
	_, err := notificationCollection.InsertOne(ctx, notification)
	return err
}

// FetchNotificationsByUserID retrieves notifications for a specific user
func FetchNotificationsByUserID(ctx context.Context, userID primitive.ObjectID) ([]models.Notification, error) {
	filter := bson.M{"user_id": userID}
	cursor, err := notificationCollection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var notifications []models.Notification
	for cursor.Next(ctx) {
		var notification models.Notification
		if err := cursor.Decode(&notification); err != nil {
			return nil, err
		}
		notifications = append(notifications, notification)
	}
	return notifications, nil
}

// UpdateNotificationAsRead updates a notification to mark it as read
func UpdateNotificationAsRead(ctx context.Context, notificationID primitive.ObjectID) error {
	filter := bson.M{"_id": notificationID}
	update := bson.M{
		"$set": bson.M{"is_read": true},
	}
	_, err := notificationCollection.UpdateOne(ctx, filter, update)
	return err
}

// FetchNotificationByID retrieves a specific notification by its ID
func FetchNotificationByID(ctx context.Context, notificationID primitive.ObjectID) (*models.Notification, error) {
	filter := bson.M{"_id": notificationID}
	var notification models.Notification
	err := notificationCollection.FindOne(ctx, filter).Decode(&notification)
	if err != nil {
		return nil, err
	}
	return &notification, nil
}

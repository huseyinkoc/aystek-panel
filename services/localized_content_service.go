package services

import (
	"admin-panel/models"
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var localizedContentCollection *mongo.Collection

// InitLocalizedContentService initializes the localized content collection
func InitLocalizedContentService(client *mongo.Client) {
	localizedContentCollection = client.Database("admin_panel").Collection("localized_contents")
}

// CreateLocalizedContent inserts a new localized content into the database
func CreateLocalizedContent(ctx context.Context, content *models.LocalizedContent) error {
	content.ID = primitive.NewObjectID()
	content.CreatedAt = primitive.NewDateTimeFromTime(time.Now())
	content.UpdatedAt = primitive.NewDateTimeFromTime(time.Now())

	_, err := localizedContentCollection.InsertOne(ctx, content)
	return err
}

// GetLocalizedContent retrieves localized content by ID
func GetLocalizedContent(ctx context.Context, id primitive.ObjectID) (*models.LocalizedContent, error) {
	var content models.LocalizedContent
	err := localizedContentCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&content)
	return &content, err
}

// UpdateLocalizedContent updates localized content by ID
func UpdateLocalizedContent(ctx context.Context, id primitive.ObjectID, updates map[string]interface{}) error {
	updates["updated_at"] = primitive.NewDateTimeFromTime(time.Now())

	_, err := localizedContentCollection.UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.M{"$set": updates},
	)
	return err
}

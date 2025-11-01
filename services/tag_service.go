package services

import (
	"admin-panel/models"
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var tagCollection *mongo.Collection

func InitTagService(client *mongo.Client) {
	tagCollection = client.Database("admin_panel").Collection("tags")
}

func CreateTag(tag models.Tag) (*mongo.InsertOneResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tag.CreatedAt = time.Now().Unix()
	return tagCollection.InsertOne(ctx, tag)
}

func GetAllTags() ([]models.Tag, error) {
	var tags []models.Tag
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := tagCollection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var tag models.Tag
		if err := cursor.Decode(&tag); err != nil {
			return nil, err
		}
		tags = append(tags, tag)
	}
	return tags, nil
}
func GetTagByID(ctx context.Context, tagID primitive.ObjectID) (*models.Tag, error) {
	var tag models.Tag
	err := tagCollection.FindOne(ctx, bson.M{"_id": tagID}).Decode(&tag)
	return &tag, err
}

func UpdateTag(ctx context.Context, tagID primitive.ObjectID, updatedTag *models.Tag) error {
	_, err := tagCollection.UpdateOne(
		ctx,
		bson.M{"_id": tagID},
		bson.M{"$set": updatedTag},
	)
	return err
}

func DeleteTag(ctx context.Context, tagID primitive.ObjectID) error {
	_, err := tagCollection.DeleteOne(ctx, bson.M{"_id": tagID})
	return err
}

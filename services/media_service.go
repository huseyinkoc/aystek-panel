package services

import (
	"admin-panel/models"
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var mediaCollection *mongo.Collection

func InitMediaService(client *mongo.Client) {
	mediaCollection = client.Database("admin_panel").Collection("media")
}

func SaveMediaRecord(media models.Media) (*mongo.InsertOneResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	media.UploadedAt = time.Now().Unix()
	return mediaCollection.InsertOne(ctx, media)
}

func GetAllMedia() ([]models.Media, error) {
	var media []models.Media
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := mediaCollection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var m models.Media
		if err := cursor.Decode(&m); err != nil {
			return nil, err
		}
		media = append(media, m)
	}

	return media, nil
}

func DeleteMedia(id primitive.ObjectID) (*mongo.DeleteResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return mediaCollection.DeleteOne(ctx, bson.M{"_id": id})
}

func GetMediaByID(id primitive.ObjectID) (*models.Media, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var media models.Media
	err := mediaCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&media)
	if err != nil {
		return nil, err
	}
	return &media, nil
}

func GetFilteredMedia(filter bson.M) ([]models.Media, error) {
	var media []models.Media
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := mediaCollection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var m models.Media
		if err := cursor.Decode(&m); err != nil {
			return nil, err
		}
		media = append(media, m)
	}

	return media, nil
}

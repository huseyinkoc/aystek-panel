package services

import (
	"admin-panel/models"
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var settingsCollection *mongo.Collection

func InitSettingsService(client *mongo.Client) {
	settingsCollection = client.Database("admin_panel").Collection("settings")
}

func GetSettings() (*models.ApplicationSettings, error) {
	var settings models.ApplicationSettings
	err := settingsCollection.FindOne(context.Background(), bson.M{}).Decode(&settings)
	if err != nil {
		return nil, err
	}
	return &settings, nil
}

func UpdateSettings(update bson.M, updatedBy string) error {
	update["updated_at"] = time.Now()
	update["updated_by"] = updatedBy

	opts := options.Update().SetUpsert(true) // Upsert seçeneğini etkinleştir
	_, err := settingsCollection.UpdateOne(context.Background(), bson.M{}, bson.M{"$set": update}, opts)
	return err
}

func GetSocialMediaLinks() (map[string]models.SocialMedia, error) {
	settings, err := GetSettings()
	if err != nil {
		return nil, err
	}
	return settings.SocialMedia, nil
}

func UpdateSocialMediaLinks(links map[string]models.SocialMedia, updatedBy string) error {
	update := bson.M{
		"social_media": links,
		"updated_at":   time.Now(),
		"updated_by":   updatedBy,
	}
	return UpdateSettings(update, updatedBy)
}

package services

import (
	"admin-panel/configs"
	"admin-panel/models"
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var languageCollection *mongo.Collection

func InitLanguageService(client *mongo.Client) {
	languageCollection = client.Database("admin_panel").Collection("languages")
}

func CreateLanguage(language *models.Language) error {
	language.ID = primitive.NewObjectID()
	language.CreatedAt = primitive.NewDateTimeFromTime(time.Now())
	language.UpdatedAt = primitive.NewDateTimeFromTime(time.Now())

	_, err := languageCollection.InsertOne(context.Background(), language)
	return err
}

func GetLanguages() ([]models.Language, error) {
	var languages []models.Language

	cursor, err := languageCollection.Find(context.Background(), bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var lang models.Language
		if err := cursor.Decode(&lang); err != nil {
			return nil, err
		}
		languages = append(languages, lang)
	}

	return languages, nil
}

func UpdateLanguage(id primitive.ObjectID, update bson.M) error {
	update["updated_at"] = primitive.NewDateTimeFromTime(time.Now())
	_, err := languageCollection.UpdateOne(
		context.Background(),
		bson.M{"_id": id},
		bson.M{"$set": update},
	)
	return err
}

func DeleteLanguage(id primitive.ObjectID) error {
	_, err := languageCollection.DeleteOne(context.Background(), bson.M{"_id": id})
	return err
}

// GetLanguagesWithActiveAndDefault fetches all enabled languages with active and default flags
func GetLanguagesWithActiveAndDefault(activeLang string) ([]map[string]interface{}, error) {
	//var languages []models.Language
	var localizedLanguages []map[string]interface{}

	cursor, err := languageCollection.Find(context.Background(), bson.M{"enabled": true})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var lang models.Language
		if err := cursor.Decode(&lang); err != nil {
			return nil, err
		}

		name, exists := lang.LocalizedNames[activeLang]
		if !exists {
			name = lang.LocalizedNames[configs.LanguageConfig.DefaultLanguage] // Varsayılan dil
		}

		localizedLanguages = append(localizedLanguages, map[string]interface{}{
			"code":       lang.Code,
			"name":       name,
			"is_active":  lang.Code == activeLang,
			"is_default": lang.IsDefault,
		})
	}

	return localizedLanguages, nil
}

func PrintLanguages() error {
	var languages []models.Language

	cursor, err := languageCollection.Find(context.Background(), bson.M{})
	if err != nil {
		return err
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var lang models.Language
		if err := cursor.Decode(&lang); err != nil {
			return err
		}
		languages = append(languages, lang)
	}

	// Değişkeni kullan
	for _, language := range languages {
		fmt.Println(language)
	}

	return nil
}

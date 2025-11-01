package services

import (
	"admin-panel/models"
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var sliderCollection *mongo.Collection

func InitSliderService(client *mongo.Client) {
	sliderCollection = client.Database("admin_panel").Collection("sliders")
}

func CreateSlider(slider *models.Slider) error {
	slider.ID = primitive.NewObjectID()
	slider.CreatedAt = primitive.NewDateTimeFromTime(time.Now())
	slider.UpdatedAt = primitive.NewDateTimeFromTime(time.Now())

	_, err := sliderCollection.InsertOne(context.Background(), slider)
	return err
}

func GetSliders() ([]models.Slider, error) {
	var sliders []models.Slider

	cursor, err := sliderCollection.Find(context.Background(), bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var slider models.Slider
		if err := cursor.Decode(&slider); err != nil {
			return nil, err
		}
		sliders = append(sliders, slider)
	}

	return sliders, nil
}

func UpdateSlider(id primitive.ObjectID, update bson.M) error {
	update["updated_at"] = primitive.NewDateTimeFromTime(time.Now())
	_, err := sliderCollection.UpdateOne(context.Background(), bson.M{"_id": id}, bson.M{"$set": update})
	return err
}

func DeleteSlider(id primitive.ObjectID) error {
	_, err := sliderCollection.DeleteOne(context.Background(), bson.M{"_id": id})
	return err
}

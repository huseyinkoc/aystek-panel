package services

import (
	"admin-panel/models"
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var contactCollection *mongo.Collection // Initialize in database setup

func InitContactService(client *mongo.Client) {
	contactCollection = client.Database("admin_panel").Collection("contacts")
}

func CreateContactMessage(ctx context.Context, message *models.ContactMessage) (*models.ContactMessage, error) {
	message.ID = primitive.NewObjectID()
	message.CreatedAt = time.Now()
	message.UpdatedAt = time.Now()
	message.Status = "new"

	_, err := contactCollection.InsertOne(ctx, message)
	if err != nil {
		return nil, err
	}
	return message, nil
}

func GetAllContactMessages(ctx context.Context) ([]models.ContactMessage, error) {
	var messages []models.ContactMessage
	cursor, err := contactCollection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var message models.ContactMessage
		if err := cursor.Decode(&message); err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	return messages, nil
}

func UpdateContactMessageStatus(ctx context.Context, id string, status string, resolvedBy string) error {
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	update := bson.M{
		"$set": bson.M{
			"status":      status,
			"updated_at":  time.Now(),
			"resolved_by": resolvedBy,
		},
	}

	_, err = contactCollection.UpdateOne(ctx, bson.M{"_id": objectID}, update)
	return err
}

func GetContactByID(ctx context.Context, contactID primitive.ObjectID) (*models.ContactMessage, error) {
	var contact models.ContactMessage

	// MongoDB sorgusu
	err := contactCollection.FindOne(ctx, bson.M{"_id": contactID}).Decode(&contact)
	if err != nil {
		return nil, err
	}

	return &contact, nil
}

func DeleteContactMessage(ctx context.Context, id string) error {
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	_, err = contactCollection.DeleteOne(ctx, bson.M{"_id": objectID})
	return err
}

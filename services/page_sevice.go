package services

import (
	"admin-panel/models"
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var pageCollection *mongo.Collection

func InitPageService(client *mongo.Client) {
	pageCollection = client.Database("admin_panel").Collection("pages")
}

// CreatePage inserts a new page into the database
func CreatePage(page models.Page) (*mongo.InsertOneResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	page.ID = primitive.NewObjectID()
	page.CreatedAt = primitive.NewDateTimeFromTime(time.Now())
	page.UpdatedAt = page.CreatedAt

	return pageCollection.InsertOne(ctx, page)
}

// GetAllPages retrieves all pages from the database
func GetAllPages() ([]models.Page, error) {
	var pages []models.Page
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := pageCollection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var page models.Page
		if err := cursor.Decode(&page); err != nil {
			return nil, err
		}
		pages = append(pages, page)
	}

	return pages, nil
}

func GetPageByID(ctx context.Context, pageID primitive.ObjectID) (*models.Page, error) {

	// Sayfayı ID'ye göre arayın
	var page models.Page
	err := pageCollection.FindOne(ctx, bson.M{"_id": pageID}).Decode(&page)
	if err != nil {
		return nil, err
	}

	return &page, nil
}

// UpdatePage updates an existing page
func UpdatePage(id primitive.ObjectID, update bson.M) (*mongo.UpdateResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Güncellenen alanlara `updated_at` ekleme
	update["updated_at"] = primitive.NewDateTimeFromTime(time.Now())
	return pageCollection.UpdateByID(ctx, id, bson.M{"$set": update})
}

// DeletePage deletes a page from the database
func DeletePage(id primitive.ObjectID) (*mongo.DeleteResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return pageCollection.DeleteOne(ctx, bson.M{"_id": id})
}

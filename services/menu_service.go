package services

import (
	"admin-panel/models"
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var menusCollection *mongo.Collection // Initialize this in your database setup

func InitMenuService(client *mongo.Client) {
	menusCollection = client.Database("admin_panel").Collection("menus")
}

// CreateMenu creates a new menu entry in the database
func CreateMenu(ctx context.Context, menu *models.Menu) (*models.Menu, error) {
	menu.ID = primitive.NewObjectID()
	menu.CreatedAt = time.Now()
	menu.UpdatedAt = time.Now()

	_, err := menusCollection.InsertOne(ctx, menu)
	if err != nil {
		return nil, err
	}
	return menu, nil
}

// UpdateMenu updates a menu by its ID
func UpdateMenu(ctx context.Context, menuID string, update bson.M) (*models.Menu, error) {
	id, err := primitive.ObjectIDFromHex(menuID)
	if err != nil {
		return nil, err
	}

	update["updated_at"] = time.Now()

	_, err = menusCollection.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": update})
	if err != nil {
		return nil, err
	}

	var updatedMenu models.Menu
	err = menusCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&updatedMenu)
	if err != nil {
		return nil, err
	}
	return &updatedMenu, nil
}

// DeleteMenu deletes a menu by its ID
func DeleteMenu(ctx context.Context, menuID string) error {
	id, err := primitive.ObjectIDFromHex(menuID)
	if err != nil {
		return err
	}

	_, err = menusCollection.DeleteOne(ctx, bson.M{"_id": id})
	return err
}

// GetMenusByRoles retrieves menus filtered by type and roles
func GetMenusByRoles(ctx context.Context, menuType string, roles []string) ([]models.Menu, error) {
	var menus []models.Menu
	filter := bson.M{
		"type": menuType,
		"$or": []bson.M{
			{"roles": "all"},
			{"roles": bson.M{"$in": roles}},
		},
	}

	cursor, err := menusCollection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var menu models.Menu
		if err := cursor.Decode(&menu); err != nil {
			return nil, err
		}
		menus = append(menus, menu)
	}
	return menus, nil
}

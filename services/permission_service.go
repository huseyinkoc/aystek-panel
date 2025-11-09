package services

import (
	"admin-panel/models"
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var permissionsCollection *mongo.Collection

func InitPermissionService(client *mongo.Client) {
	permissionsCollection = client.Database("admin_panel").Collection("permissions")
	// Modül isimleri benzersiz olsun
	_, _ = permissionsCollection.Indexes().CreateOne(context.TODO(),
		mongo.IndexModel{
			Keys:    bson.M{"module": 1},
			Options: nil,
		})
}

// ✅ Tüm modülleri getir
func GetAllPermissionModules(ctx context.Context) ([]models.PermissionModule, error) {
	cursor, err := permissionsCollection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var modules []models.PermissionModule
	if err := cursor.All(ctx, &modules); err != nil {
		return nil, err
	}
	return modules, nil
}

// ✅ Tek modül getir (ID ile)
func GetPermissionModuleByID(ctx context.Context, id primitive.ObjectID) (*models.PermissionModule, error) {
	var module models.PermissionModule
	err := permissionsCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&module)
	if err != nil {
		return nil, err
	}
	return &module, nil
}

// ✅ Yeni modül oluştur
func CreatePermissionModule(ctx context.Context, module models.PermissionModule) (*mongo.InsertOneResult, error) {
	if module.Module == "" {
		return nil, errors.New("module name is required")
	}
	if len(module.Actions) == 0 {
		return nil, errors.New("actions list cannot be empty")
	}

	module.ID = primitive.NewObjectID()
	module.CreatedAt = time.Now()
	module.UpdatedAt = time.Now()

	return permissionsCollection.InsertOne(ctx, module)
}

// ✅ Güncelle
func UpdatePermissionModule(ctx context.Context, id primitive.ObjectID, module models.PermissionModule) error {
	update := bson.M{
		"$set": bson.M{
			"module":     module.Module,
			"actions":    module.Actions,
			"updated_by": module.UpdatedBy,
			"updated_at": time.Now(),
		},
	}
	_, err := permissionsCollection.UpdateByID(ctx, id, update)
	return err
}

// ✅ Sil
func DeletePermissionModule(ctx context.Context, id primitive.ObjectID) error {
	_, err := permissionsCollection.DeleteOne(ctx, bson.M{"_id": id})
	return err
}

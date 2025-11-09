package services

import (
	"admin-panel/models"
	"context"
	"errors"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var permissionsCollection *mongo.Collection

// InitPermissionService — dinamik DB ismine göre koleksiyonu ayarla
func InitPermissionService(client *mongo.Client) {
	dbName := os.Getenv("MONGO_DBNAME")
	if dbName == "" {
		dbName = "admin_panel"
	}
	permissionsCollection = client.Database(dbName).Collection("permissions")

	_, _ = permissionsCollection.Indexes().CreateOne(context.TODO(), mongo.IndexModel{
		Keys: bson.M{"module": 1},
	})
}

// GetAllPermissions — tüm modül ve aksiyonları getir
func GetAllPermissions(ctx context.Context) ([]models.Permission, error) {
	cursor, err := permissionsCollection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var modules []models.Permission
	if err := cursor.All(ctx, &modules); err != nil {
		return nil, err
	}
	return modules, nil
}

// GetPermissionByID — tek kayıt getir
func GetPermissionByID(ctx context.Context, id primitive.ObjectID) (*models.Permission, error) {
	var module models.Permission
	err := permissionsCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&module)
	if err != nil {
		return nil, err
	}
	return &module, nil
}

// CreatePermission — yeni modül ekle
func CreatePermission(ctx context.Context, module models.Permission) (*mongo.InsertOneResult, error) {
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

// UpdatePermission — modül veya aksiyon güncelle
func UpdatePermission(ctx context.Context, id primitive.ObjectID, module models.Permission) error {
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

// DeletePermission — modül sil
func DeletePermission(ctx context.Context, id primitive.ObjectID) error {
	_, err := permissionsCollection.DeleteOne(ctx, bson.M{"_id": id})
	return err
}

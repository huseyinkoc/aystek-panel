package services

import (
	"admin-panel/models"
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var rolesCollection *mongo.Collection

func InitRolesService(client *mongo.Client) {
	rolesCollection = client.Database("admin_panel").Collection("roles")
}

// GetRolePermissions fetches permissions for a specific role and module
func GetRolePermissions(ctx context.Context, role string, module string) ([]string, error) {
	var roleData struct {
		Permissions map[string][]string `bson:"permissions"`
	}

	filter := bson.M{"_id": role}
	err := rolesCollection.FindOne(ctx, filter).Decode(&roleData)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("role not found")
		}
		return nil, err
	}

	permissions, exists := roleData.Permissions[module]
	if !exists {
		return nil, nil
	}

	return permissions, nil
}

// CreateRole creates a new role
func CreateRole(ctx context.Context, role models.Role) (*mongo.InsertOneResult, error) {
	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()

	return rolesCollection.InsertOne(ctx, role)
}

// ReadRole fetches a role by its ID
func ReadRole(ctx context.Context, roleID string) (*models.Role, error) {
	var role models.Role
	err := rolesCollection.FindOne(ctx, bson.M{"_id": roleID}).Decode(&role)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// UpdateRole updates a role by its ID
func UpdateRole(ctx context.Context, roleID string, update map[string]interface{}) (int64, error) {
	// Güncelleme işlemi
	filter := bson.M{"_id": roleID}
	updateData := bson.M{"$set": update}

	result, err := rolesCollection.UpdateOne(ctx, filter, updateData)
	if err != nil {
		return 0, err
	}

	return result.ModifiedCount, nil
}

// DeleteRole deletes a role by its ID
func DeleteRole(ctx context.Context, roleID string) (int64, error) {
	// Silme işlemi
	filter := bson.M{"_id": roleID}

	result, err := rolesCollection.DeleteOne(ctx, filter)
	if err != nil {
		return 0, err
	}

	return result.DeletedCount, nil
}

// GetAllRoles retrieves all roles
func GetAllRoles(ctx context.Context) ([]models.Role, error) {
	cursor, err := rolesCollection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var roles []models.Role
	for cursor.Next(ctx) {
		var role models.Role
		if err := cursor.Decode(&role); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, nil
}

func GetRoleByID(ctx context.Context, roleID string) (*models.Role, error) {
	var role models.Role
	err := rolesCollection.FindOne(ctx, bson.M{"_id": roleID}).Decode(&role)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

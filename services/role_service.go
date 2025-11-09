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

var rolesCollection *mongo.Collection

func InitRolesService(client *mongo.Client) {
	rolesCollection = client.Database("admin_panel").Collection("roles")
}

// GetRolePermissions fetches permissions for a specific role and module
func GetRolePermissions(ctx context.Context, roleID string, module string) ([]string, error) {
	var roleData struct {
		Permissions map[string][]string `bson:"permissions"`
	}

	oid, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		return nil, err
	}

	filter := bson.M{"_id": oid}
	err = rolesCollection.FindOne(ctx, filter).Decode(&roleData)
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
	if role.ID.IsZero() {
		role.ID = primitive.NewObjectID()
	}
	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()
	return rolesCollection.InsertOne(ctx, role)
}

// ReadRole fetches a role by its ID
func ReadRole(ctx context.Context, roleID string) (*models.Role, error) {
	oid, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		return nil, err
	}

	var role models.Role
	err = rolesCollection.FindOne(ctx, bson.M{"_id": oid}).Decode(&role)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// UpdateRole updates a role by its ID
func UpdateRole(ctx context.Context, id primitive.ObjectID, role models.Role) error {
	update := bson.M{
		"$set": bson.M{
			"name":        role.Name,
			"description": role.Description,
			"permissions": role.Permissions,
			"is_system":   role.IsSystem,
			"updated_by":  role.UpdatedBy,
			"updated_at":  time.Now(),
		},
	}
	_, err := rolesCollection.UpdateByID(ctx, id, update)
	return err
}

// DeleteRole deletes a role by its ID
func DeleteRole(ctx context.Context, id primitive.ObjectID) error {
	_, err := rolesCollection.DeleteOne(ctx, bson.M{"_id": id})
	return err
}

// GetAllRoles retrieves all roles
func GetAllRoles(ctx context.Context) ([]models.Role, error) {
	cursor, err := rolesCollection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var roles []models.Role
	if err := cursor.All(ctx, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

func GetRoleByID(ctx context.Context, id primitive.ObjectID) (*models.Role, error) {
	var role models.Role
	err := rolesCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&role)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// ✅ Rolleri izin detaylarıyla birlikte getir
func GetAllRolesWithPermissions(ctx context.Context) ([]bson.M, error) {
	pipeline := mongo.Pipeline{
		{{Key: "$lookup", Value: bson.M{
			"from":         "permissions",
			"localField":   "permissions",
			"foreignField": "_id",
			"as":           "permission_details",
		}}},
	}

	cursor, err := rolesCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var roles []bson.M
	if err := cursor.All(ctx, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

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

var rolesCollection *mongo.Collection

// InitRolesService initializes the roles collection dynamically (uses .env)
func InitRolesService(client *mongo.Client) {
	dbName := os.Getenv("MONGO_DBNAME")
	if dbName == "" {
		dbName = "admin_panel" // fallback default
	}
	rolesCollection = client.Database(dbName).Collection("roles")
}

// GetRolePermissions returns the list of permissions for a given role and module
func GetRolePermissions(ctx context.Context, roleID string, module string) ([]string, error) {
	if rolesCollection == nil {
		return nil, errors.New("roles service not initialized")
	}

	var roleData struct {
		Permissions map[string][]string `bson:"permissions"`
	}

	oid, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		return nil, errors.New("invalid role ID")
	}

	err = rolesCollection.FindOne(ctx, bson.M{"_id": oid}).Decode(&roleData)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("role not found")
		}
		return nil, err
	}

	perms, ok := roleData.Permissions[module]
	if !ok {
		return []string{}, nil
	}
	return perms, nil
}

// CreateRole creates a new role
func CreateRole(ctx context.Context, role models.Role) (*mongo.InsertOneResult, error) {
	if rolesCollection == nil {
		return nil, errors.New("roles service not initialized")
	}

	if role.ID.IsZero() {
		role.ID = primitive.NewObjectID()
	}
	now := time.Now()
	role.CreatedAt = now
	role.UpdatedAt = now

	return rolesCollection.InsertOne(ctx, role)
}

// ReadRole fetches a single role by ID
func ReadRole(ctx context.Context, roleID string) (*models.Role, error) {
	if rolesCollection == nil {
		return nil, errors.New("roles service not initialized")
	}

	oid, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		return nil, errors.New("invalid role ID")
	}

	var role models.Role
	if err := rolesCollection.FindOne(ctx, bson.M{"_id": oid}).Decode(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

// UpdateRole updates an existing role
func UpdateRole(ctx context.Context, id primitive.ObjectID, updated models.Role) error {
	if rolesCollection == nil {
		return errors.New("roles service not initialized")
	}

	update := bson.M{
		"$set": bson.M{
			"name":        updated.Name,
			"description": updated.Description,
			"permissions": updated.Permissions,
			"is_system":   updated.IsSystem,
			"updated_by":  updated.UpdatedBy,
			"updated_at":  time.Now(),
		},
	}

	_, err := rolesCollection.UpdateByID(ctx, id, update)
	return err
}

// DeleteRole removes a role by ID
func DeleteRole(ctx context.Context, id primitive.ObjectID) error {
	if rolesCollection == nil {
		return errors.New("roles service not initialized")
	}

	_, err := rolesCollection.DeleteOne(ctx, bson.M{"_id": id})
	return err
}

// GetAllRoles returns all roles
func GetAllRoles(ctx context.Context) ([]models.Role, error) {
	if rolesCollection == nil {
		return nil, errors.New("roles service not initialized")
	}

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

// GetRoleByID fetches role details by ObjectID
func GetRoleByID(ctx context.Context, id primitive.ObjectID) (*models.Role, error) {
	if rolesCollection == nil {
		return nil, errors.New("roles service not initialized")
	}

	var role models.Role
	err := rolesCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&role)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// GetAllRolesWithPermissions joins roles with permission details
func GetAllRolesWithPermissions(ctx context.Context) ([]bson.M, error) {
	if rolesCollection == nil {
		return nil, errors.New("roles service not initialized")
	}

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

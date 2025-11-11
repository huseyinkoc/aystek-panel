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
// Eğer module/action bazlı yetki istiyorsan:
func GetRolePermissions(ctx context.Context, roleID string) ([]primitive.ObjectID, error) {
	if rolesCollection == nil {
		return nil, errors.New("roles service not initialized")
	}

	var role models.Role
	oid, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		return nil, errors.New("invalid role ID")
	}

	err = rolesCollection.FindOne(ctx, bson.M{"_id": oid}).Decode(&role)
	if err != nil {
		return nil, err
	}

	return role.Permissions, nil
}

// GetRolePermissionsByName finds a role by its name and returns its permission IDs.
// This fixes the mismatch where helpers passed a roleName but existing GetRolePermissions expected an ObjectID hex.
func GetRolePermissionsByName(ctx context.Context, roleName string) ([]primitive.ObjectID, error) {
	if rolesCollection == nil {
		return nil, errors.New("roles service not initialized")
	}

	var role models.Role
	err := rolesCollection.FindOne(ctx, bson.M{"name": roleName}).Decode(&role)
	if err != nil {
		return nil, err
	}

	return role.Permissions, nil
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

// GetAllRoles returns all roles (raw documents)
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

// UpdateRoleByID — Rol güncelleme işlemi
func UpdateRoleByID(ctx context.Context, id primitive.ObjectID, update bson.M) error {
	_, err := rolesCollection.UpdateByID(ctx, id, update)
	return err
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

// GetRolesByIDs — Birden fazla Role ID üzerinden rolleri getir
func GetRolesByIDs(ctx context.Context, ids []primitive.ObjectID) ([]models.Role, error) {
	if len(ids) == 0 {
		return []models.Role{}, nil
	}
	filter := bson.M{"_id": bson.M{"$in": ids}}
	cursor, err := rolesCollection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	var roles []models.Role
	if err = cursor.All(ctx, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

// GetAllRolesWithPermissions joins roles with permission details.
// Handles case where roles.permissions are stored as hex strings by converting them to ObjectId for lookup.
func GetAllRolesWithPermissions(ctx context.Context) ([]bson.M, error) {
	if rolesCollection == nil {
		return nil, errors.New("roles service not initialized")
	}

	// Add stage to convert string hex permission ids to ObjectId if necessary, then lookup
	pipeline := mongo.Pipeline{
		// convert each element in permissions to ObjectId when it is a string
		{{Key: "$addFields", Value: bson.M{
			"__permissions_obj": bson.M{
				"$map": bson.M{
					"input": "$permissions",
					"as":    "p",
					"in": bson.M{
						"$cond": bson.A{
							bson.M{"$isString": "$$p"},
							bson.M{"$convert": bson.M{"input": "$$p", "to": "objectId", "onError": nil, "onNull": nil}},
							"$$p",
						},
					},
				},
			},
		}}},
		// lookup using converted array
		{{Key: "$lookup", Value: bson.M{
			"from":         "permissions",
			"localField":   "__permissions_obj",
			"foreignField": "_id",
			"as":           "permission_details",
		}}},
		// optional: remove helper field
		{{Key: "$project", Value: bson.M{"__permissions_obj": 0}}},
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

// GetRoleWithPermissions returns single role with permission_details resolved (handles hex strings)
func GetRoleWithPermissions(ctx context.Context, id primitive.ObjectID) (bson.M, error) {
	if rolesCollection == nil {
		return nil, errors.New("roles service not initialized")
	}

	matchStage := bson.D{{Key: "$match", Value: bson.M{"_id": id}}}
	addFieldsStage := bson.D{{Key: "$addFields", Value: bson.M{
		"__permissions_obj": bson.M{
			"$map": bson.M{
				"input": "$permissions",
				"as":    "p",
				"in": bson.M{
					"$cond": bson.A{
						bson.M{"$isString": "$$p"},
						bson.M{"$convert": bson.M{"input": "$$p", "to": "objectId", "onError": nil, "onNull": nil}},
						"$$p",
					},
				},
			},
		},
	}}}
	lookupStage := bson.D{{Key: "$lookup", Value: bson.M{
		"from":         "permissions",
		"localField":   "__permissions_obj",
		"foreignField": "_id",
		"as":           "permission_details",
	}}}
	projectStage := bson.D{{Key: "$project", Value: bson.M{"__permissions_obj": 0}}}

	pipeline := mongo.Pipeline{matchStage, addFieldsStage, lookupStage, projectStage}

	cursor, err := rolesCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, mongo.ErrNoDocuments
	}
	return results[0], nil
}

// GetRoleByName finds a role document by its name (case sensitive).
// Returns the role model or mongo.ErrNoDocuments if not found.
func GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	if rolesCollection == nil {
		return nil, errors.New("roles service not initialized")
	}
	var role models.Role
	err := rolesCollection.FindOne(ctx, bson.M{"name": name}).Decode(&role)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, err
		}
		return nil, err
	}
	return &role, nil
}

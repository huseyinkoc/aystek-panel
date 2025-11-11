package helpers

import (
	"admin-panel/services"
	"context"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// CheckUserAuthorization verifies if the user has at least one of the required roles.
func CheckUserAuthorization(ctx context.Context, userID primitive.ObjectID, module, action string) (bool, error) {
	roles, err := services.GetUserRoles(userID)
	if err != nil {
		return false, err
	}

	for _, role := range roles {
		ok, err := HasModulePermission(ctx, role.Name, module, action)
		if err != nil {
			continue
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

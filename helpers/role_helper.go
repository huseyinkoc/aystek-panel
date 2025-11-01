package helpers

import (
	"admin-panel/services"
	"context"
)

func HasModulePermission(ctx context.Context, role string, module string, action string) (bool, error) {
	permissions, err := services.GetRolePermissions(ctx, role, module)
	if err != nil {
		return false, err
	}

	for _, permission := range permissions {
		if permission == action {
			return true, err
		}
	}

	return false, nil
}

package helpers

import (
	"admin-panel/services"
	"context"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// HasModulePermission verilen rolün belirtilen module/action için yetkisini kontrol eder.
func HasModulePermission(ctx context.Context, roleName, module, action string) (bool, error) {
	if roleName == "" || action == "" {
		return false, nil
	}

	// roleName ile izin ID'lerini al
	permIDs, err := services.GetRolePermissionsByName(ctx, roleName)
	if err != nil {
		return false, err
	}

	for _, pid := range permIDs {
		perm, err := services.GetPermissionByID(ctx, pid)
		if err != nil {
			continue
		}
		if perm.Module == module {
			for _, act := range perm.Actions {
				if act == action || act == "*" {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// NormalizeRoles converts mixed-type roles (string/ObjectID/interface{}) into []string
func NormalizeRoles(roles []interface{}) []string {
	var normalized []string
	for _, r := range roles {
		switch v := r.(type) {
		case string:
			normalized = append(normalized, v)
		case primitive.ObjectID:
			normalized = append(normalized, v.Hex())
		default:
			continue
		}
	}
	return normalized
}

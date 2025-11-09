package helpers

import (
	"admin-panel/services"
	"context"
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

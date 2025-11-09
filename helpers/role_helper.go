package helpers

import (
	"admin-panel/services"
	"context"
)

// HasModulePermission verilen rolün belirtilen module/action için yetkisini kontrol eder.
// Not: burada service sadece roleName parametresi alıyor ve []primitive.ObjectID döndürüyor.
func HasModulePermission(ctx context.Context, roleName, module, action string) (bool, error) {
	if roleName == "" || action == "" {
		return false, nil
	}

	// Servisten rolün izin ObjectID'lerini çek
	permissions, err := services.GetRolePermissions(ctx, roleName)
	if err != nil {
		return false, err
	}

	// Her izin ID'sini Permission tablosundan detaylı çekip module/action karşılaştırması yap
	for _, permID := range permissions {
		perm, err := services.GetPermissionByID(ctx, permID)
		if err != nil {
			continue // biri hatalıysa atla
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

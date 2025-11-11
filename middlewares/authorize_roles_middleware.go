package middlewares

import (
	"admin-panel/services"
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// AuthorizePermissionMiddleware kontrolü:
// Örnek kullanım → AuthorizePermissionMiddleware("categories", "create")
func AuthorizePermissionMiddleware(module, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1️⃣ Token'dan kullanıcı ID'sini al
		userID := c.GetString("user_id")
		if userID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		// 2️⃣ Kullanıcıyı bul
		ctx := context.TODO()
		user, err := services.GetUserByID(ctx, userID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			return
		}

		// 3️⃣ Kullanıcının rollerini kontrol et
		if len(user.Roles) == 0 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "no roles assigned"})
			return
		}

		// 4️⃣ Rollerden izinleri topla
		roles, err := services.GetRolesByIDs(ctx, user.Roles)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch roles"})
			return
		}

		var permissionIDs []primitive.ObjectID
		for _, role := range roles {
			permissionIDs = append(permissionIDs, role.Permissions...)
		}

		// 5️⃣ İzin belgelerini çek
		perms, err := services.GetPermissionsByIDs(ctx, permissionIDs)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch permissions"})
			return
		}

		// 6️⃣ İstenen module/action izni var mı?
		allowed := false
		for _, p := range perms {
			if strings.EqualFold(p.Module, module) {
				for _, act := range p.Actions {
					if strings.EqualFold(act, action) {
						allowed = true
						break
					}
				}
			}
			if allowed {
				break
			}
		}

		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "permission denied",
				"module":  module,
				"action":  action,
				"message": "you do not have access to perform this action",
			})
			return
		}

		// 7️⃣ Devam et
		c.Next()
	}
}

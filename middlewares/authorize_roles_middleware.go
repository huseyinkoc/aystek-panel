package middlewares

import (
	"admin-panel/services"
	"net/http"

	"github.com/gin-gonic/gin"
)

// AuthorizeRolesMiddleware — belirli rollerin erişimine izin verir.
// Örnek: router.Use(AuthorizeRolesMiddleware("admin", "editor"))
func AuthorizeRolesMiddleware(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roles, exists := c.Get("roles") // AuthMiddleware'den gelen roller
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized - no roles found"})
			c.Abort()
			return
		}

		userRoles, ok := roles.([]string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid roles format"})
			c.Abort()
			return
		}

		// Kullanıcı rollerinden biri izin verilenler arasında mı kontrol et
		for _, userRole := range userRoles {
			for _, allowedRole := range allowedRoles {
				if userRole == allowedRole {
					c.Next()
					return
				}
			}
		}

		// Yetkisiz erişim
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Access denied",
			"roles": userRoles,
		})
		c.Abort()
	}
}

// ModulePermissionMiddleware — belirli modül ve aksiyona göre yetki kontrolü.
// Örnek: router.Use(ModulePermissionMiddleware("posts", "delete"))
func ModulePermissionMiddleware(module string, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roles, exists := c.Get("roles")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		userRoles, ok := roles.([]string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid roles format"})
			c.Abort()
			return
		}

		// Roller bazında izinleri kontrol et
		for _, role := range userRoles {
			permissions, err := services.GetRolePermissions(c.Request.Context(), role, module)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch permissions"})
				c.Abort()
				return
			}

			for _, permission := range permissions {
				if permission == action {
					c.Next()
					return
				}
			}
		}

		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		c.Abort()
	}
}

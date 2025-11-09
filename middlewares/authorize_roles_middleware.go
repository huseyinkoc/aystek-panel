package middlewares

import (
	"admin-panel/helpers"
	"net/http"

	"github.com/gin-gonic/gin"
)

// AuthorizeRolesMiddleware — belirli rollerin erişimine izin verir.
// Örnek: router.Use(AuthorizeRolesMiddleware("admin", "editor"))
func AuthorizeRolesMiddleware(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		rolesVal, exists := c.Get("roles") // AuthMiddleware tarafından konulmuş olmalı
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized - no roles found"})
			c.Abort()
			return
		}

		// roller string veya []string olabilir; ikisini de destekle
		var userRoles []string
		switch v := rolesVal.(type) {
		case []string:
			userRoles = v
		case string:
			if v != "" {
				userRoles = []string{v}
			}
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid roles format"})
			c.Abort()
			return
		}

		// Kullanıcı rollerinden biri izin verilenler arasında mı?
		for _, userRole := range userRoles {
			for _, allowed := range allowedRoles {
				if userRole == allowed {
					c.Next()
					return
				}
			}
		}

		c.JSON(http.StatusForbidden, gin.H{
			"error": "Access denied",
			"roles": userRoles,
		})
		c.Abort()
	}
}

// ModulePermissionMiddleware — belirli modül ve aksiyona göre izin kontrolü.
// Örnek: router.Use(ModulePermissionMiddleware("posts", "delete"))
func ModulePermissionMiddleware(module string, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		rolesVal, exists := c.Get("roles")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		// roller string veya []string olabilir; ikisini de destekle
		var userRoles []string
		switch v := rolesVal.(type) {
		case []string:
			userRoles = v
		case string:
			if v != "" {
				userRoles = []string{v}
			}
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid roles format"})
			c.Abort()
			return
		}

		// Roller bazında izinleri kontrol et — ilk yetkide geçir
		for _, role := range userRoles {
			ok, err := helpers.HasModulePermission(c.Request.Context(), role, module, action)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check permissions"})
				c.Abort()
				return
			}
			if ok {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		c.Abort()
	}
}

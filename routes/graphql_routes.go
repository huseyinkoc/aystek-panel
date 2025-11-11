package routes

import (
	"admin-panel/graphql" // schema.go içe aktarılıyor
	"admin-panel/middlewares"
	"net/http"

	"github.com/gin-gonic/gin"
	gql "github.com/graphql-go/graphql"
)

func GraphQLRoutes(router *gin.Engine) {
	gpqls := router.Group("/roles")

	// Genel middleware'ler
	gpqls.Use(middlewares.MaintenanceMiddleware()) // Bakım modu kontrolü
	gpqls.Use(middlewares.AuthMiddleware())        // JWT kimlik doğrulama

	{
		gpqls.POST("/graphql",
			middlewares.CSRFMiddleware(),
			middlewares.AuthorizePermissionMiddleware("graphql", "execute"),
			func(c *gin.Context) {
				var query struct {
					Query string `json:"query"`
				}

				if err := c.ShouldBindJSON(&query); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
					return
				}

				// 🔹 GraphQL sorgusunu çalıştır
				result := gql.Do(gql.Params{
					Schema:        graphql.Schema, // Şema burada kullanılıyor
					RequestString: query.Query,
				})

				if len(result.Errors) > 0 {
					c.JSON(http.StatusInternalServerError, gin.H{"errors": result.Errors})
					return
				}

				c.JSON(http.StatusOK, gin.H{"data": result.Data})
			},
		)
	}
}

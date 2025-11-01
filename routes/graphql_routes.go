package routes

import (
	"admin-panel/graphql" // schema.go içe aktarılıyor
	"admin-panel/middlewares"

	"github.com/gin-gonic/gin"
	gql "github.com/graphql-go/graphql"
)

func GraphQLRoutes(router *gin.Engine) {
	gpqls := router.Group("/roles")
	gpqls.Use(middlewares.MaintenanceMiddleware()) // Bakım modu kontrolü
	gpqls.Use(middlewares.AuthMiddleware())
	gpqls.Use(middlewares.AuthorizeRolesMiddleware("admin"))
	{
		gpqls.POST("/graphql", middlewares.CSRFMiddleware(), func(c *gin.Context) {
			var query struct {
				Query string `json:"query"`
			}

			if err := c.ShouldBindJSON(&query); err != nil {
				c.JSON(400, gin.H{"error": "Invalid request payload"})
				return
			}

			// Doğru şemayı kullanıyoruz
			result := gql.Do(gql.Params{
				Schema:        graphql.Schema, // Şema burada kullanılıyor
				RequestString: query.Query,
			})

			if len(result.Errors) > 0 {
				c.JSON(500, gin.H{"errors": result.Errors})
				return
			}

			c.JSON(200, gin.H{"data": result.Data})
		})
	}
}

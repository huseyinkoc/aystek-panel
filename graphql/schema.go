package graphql

import (
	"admin-panel/services"
	"context"

	"github.com/graphql-go/graphql"
	gql "github.com/graphql-go/graphql"
)

// RoleType defines the GraphQL schema for a role
var RoleType = gql.NewObject(graphql.ObjectConfig{
	Name: "Role",
	Fields: graphql.Fields{
		"id": &graphql.Field{
			Type: gql.String,
		},
		"permissions": &gql.Field{
			Type: gql.NewObject(gql.ObjectConfig{
				Name: "gql",
				Fields: graphql.Fields{
					"posts": &gql.Field{
						Type: gql.NewList(gql.String),
					},
					"comments": &gql.Field{
						Type: gql.NewList(gql.String),
					},
				},
			}),
		},
		"created_at": &gql.Field{
			Type: gql.String,
		},
		"updated_at": &gql.Field{
			Type: gql.String,
		},
		"created_by": &gql.Field{
			Type: gql.String,
		},
		"updated_by": &gql.Field{
			Type: gql.String,
		},
	},
})

// RootQuery defines the GraphQL root query
var RootQuery = gql.NewObject(gql.ObjectConfig{
	Name: "Query",
	Fields: gql.Fields{
		"roles": &gql.Field{
			Type: gql.NewList(RoleType),
			Resolve: func(p gql.ResolveParams) (interface{}, error) {
				ctx := context.Background()
				return services.GetAllRoles(ctx)
			},
		},
		"role": &gql.Field{
			Type: RoleType,
			Args: gql.FieldConfigArgument{
				"id": &gql.ArgumentConfig{
					Type: gql.String,
				},
			},
			Resolve: func(p gql.ResolveParams) (interface{}, error) {
				roleID, ok := p.Args["id"].(string)
				if !ok {
					return nil, nil
				}
				ctx := context.Background()
				return services.GetRoleByID(ctx, roleID)
			},
		},
	},
})

// Schema defines the GraphQL schema
var Schema, _ = gql.NewSchema(gql.SchemaConfig{
	Query: RootQuery,
})

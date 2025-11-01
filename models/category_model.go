package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Category struct {
	ID            primitive.ObjectID        `bson:"_id,omitempty" json:"id"`
	Localizations map[string]LocalizedField `bson:"localizations" json:"localizations"` // Dil koduna göre içerik
	Slug          map[string]string         `bson:"slug" json:"slug"`                   // Dil kodu ve slug
	CreatedAt     primitive.DateTime        `bson:"created_at" json:"created_at"`
	UpdatedAt     primitive.DateTime        `bson:"updated_at" json:"updated_at"`
	CreatedBy     string                    `bson:"created_by" json:"created_by"`
	UpdatedBy     string                    `bson:"updated_by" json:"updated_by"`
}

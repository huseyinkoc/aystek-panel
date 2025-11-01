package models

import "go.mongodb.org/mongo-driver/bson/primitive"

// Page represents a page structure with localized content
type Page struct {
	ID            primitive.ObjectID        `bson:"_id,omitempty" json:"id"`
	Localizations map[string]LocalizedField `bson:"localizations" json:"localizations"` // Dil kodu ve içerik
	Status        string                    `bson:"status" json:"status"`               // draft, published, scheduled
	PublishDate   *primitive.DateTime       `bson:"publish_date,omitempty" json:"publish_date,omitempty"`
	AuthorID      primitive.ObjectID        `bson:"author_id" json:"author_id"`
	MetaTags      map[string]MetaTag        `bson:"meta_tags" json:"meta_tags"` // Dil kodu ve SEO bilgileri
	CreatedAt     primitive.DateTime        `bson:"created_at" json:"created_at"`
	UpdatedAt     primitive.DateTime        `bson:"updated_at" json:"updated_at"`
	CreatedBy     string                    `bson:"created_by" json:"created_by"`
	UpdatedBy     string                    `bson:"updated_by" json:"updated_by"`
}

package models

import "go.mongodb.org/mongo-driver/bson/primitive"

// LocalizedContent represents a content structure with translations
type LocalizedContent struct {
	ID           primitive.ObjectID        `bson:"_id,omitempty" json:"id"`
	Translations map[string]LocalizedField `bson:"translations" json:"translations"` // Dil kodu ve içeriği
	CreatedAt    primitive.DateTime        `bson:"created_at" json:"created_at"`
	UpdatedAt    primitive.DateTime        `bson:"updated_at" json:"updated_at"`
	CreatedBy    string                    `bson:"created_by" json:"created_by"`
	UpdatedBy    string                    `bson:"updated_by" json:"updated_by"`
}

// LocalizedField represents a single translation field
type LocalizedField struct {
	Title   string `bson:"title" json:"title"`
	Content string `bson:"content" json:"content"`
	Slug    string `bson:"slug" json:"slug"`
}

// MetaTag represents SEO-related metadata
type MetaTag struct {
	Title       string   `bson:"title" json:"title"`
	Description string   `bson:"description" json:"description"`
	Keywords    []string `bson:"keywords" json:"keywords"` // Dizi olarak tanımlandı
}

package models

import "go.mongodb.org/mongo-driver/bson/primitive"

// Language represents a language configuration
type Language struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Code           string             `bson:"code" json:"code"`                       // Örnek: "en", "tr"
	LocalizedNames map[string]string  `bson:"localized_names" json:"localized_names"` // Dil koduna göre adlar
	IsDefault      bool               `bson:"is_default" json:"is_default"`           // Varsayılan dil mi?
	Enabled        bool               `bson:"enabled" json:"enabled"`                 // Aktif mi?
	CreatedAt      primitive.DateTime `bson:"created_at" json:"created_at"`
	UpdatedAt      primitive.DateTime `bson:"updated_at" json:"updated_at"`
}

package models

import "go.mongodb.org/mongo-driver/bson/primitive"

// Slider represents a collection of banners or images
type Slider struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name      string             `bson:"name" json:"name"`             // Slider adı
	Images    []string           `bson:"images" json:"images"`         // Görsellerin URL'leri
	Active    bool               `bson:"active" json:"active"`         // Slider aktif mi?
	CreatedAt primitive.DateTime `bson:"created_at" json:"created_at"` // Oluşturulma tarihi
	UpdatedAt primitive.DateTime `bson:"updated_at" json:"updated_at"` // Güncellenme tarihi
	CreatedBy string             `bson:"created_by" json:"created_by"` // Oluşturan kullanıcı
	UpdatedBy string             `bson:"updated_by" json:"updated_by"` // Güncelleyen kullanıcı
}

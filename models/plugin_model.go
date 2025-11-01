package models

import "go.mongodb.org/mongo-driver/bson/primitive"

// Plugin represents a plugin's metadata
type Plugin struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name        string             `bson:"name" json:"name"`               // Plugin adı
	Description string             `bson:"description" json:"description"` // Plugin açıklaması
	Version     string             `bson:"version" json:"version"`         // Plugin versiyonu
	Enabled     bool               `bson:"enabled" json:"enabled"`         // Aktif mi?
	CreatedAt   primitive.DateTime `bson:"created_at" json:"created_at"`   // Oluşturulma zamanı
	UpdatedAt   primitive.DateTime `bson:"updated_at" json:"updated_at"`   // Güncellenme zamanı
	CreatedBy   string             `bson:"created_by" json:"created_by"`   // Hangi kullanıcı ekledi
	UpdatedBy   string             `bson:"updated_by" json:"updated_by"`   // Son güncelleyen kullanıcı
}

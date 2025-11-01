package models

import "time"

type Role struct {
	ID          string              `bson:"_id" json:"id"`                          // Rol ID'si (örn: "admin")
	Permissions map[string][]string `bson:"permissions" json:"permissions"`         // Modül bazlı izinler
	CreatedAt   time.Time           `bson:"created_at" json:"created_at"`           // Oluşturulma tarihi
	UpdatedAt   time.Time           `bson:"updated_at" json:"updated_at"`           // Güncellenme tarihi
	CreatedBy   string              `bson:"created_by" json:"created_by"`           // Rolü oluşturan kullanıcı
	UpdatedBy   string              `bson:"updated_by" json:"updated_by,omitempty"` // Rolü güncelleyen son kullanıcı
}

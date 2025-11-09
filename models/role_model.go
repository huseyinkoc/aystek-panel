package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Role struct {
	ID          primitive.ObjectID   `bson:"_id,omitempty"      json:"id"`
	Name        string               `bson:"name"               json:"name"               binding:"required"`
	Description string               `bson:"description,omitempty" json:"description,omitempty"`
	Permissions []primitive.ObjectID `bson:"permissions"        json:"permissions"` // Permission referansları
	IsSystem    bool                 `bson:"is_system,omitempty" json:"is_system,omitempty"`
	CreatedAt   time.Time            `bson:"created_at"         json:"created_at"`
	UpdatedAt   time.Time            `bson:"updated_at"         json:"updated_at"`
	CreatedBy   primitive.ObjectID   `bson:"created_by"         json:"created_by"`
	UpdatedBy   primitive.ObjectID   `bson:"updated_by,omitempty" json:"updated_by,omitempty"`
}

// ---- DTO’lar (binding için temiz gövde) ----

type RoleCreateDTO struct {
	Name        string               `json:"name"        binding:"required,min=2,max=64"`
	Description string               `json:"description" binding:"max=512"`
	Permissions []primitive.ObjectID `json:"permissions"`
	// İstemci sistem rolü yaratamasın; service tarafında zorunlu olarak false ayarlanacak
}

type RoleUpdateDTO struct {
	Name        *string              `json:"name,omitempty"        binding:"omitempty,min=2,max=64"`
	Description *string              `json:"description,omitempty" binding:"omitempty,max=512"`
	Permissions []primitive.ObjectID `json:"permissions,omitempty"`
	// is_system güncellenemez (service’te engellenir)
}

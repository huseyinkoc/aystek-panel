package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Role struct {
	ID          primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Name        string               `bson:"name" json:"name"`
	Description string               `bson:"description" json:"description"`
	Permissions []primitive.ObjectID `bson:"permissions" json:"permissions"` // 🔗 Permission referansları
	IsSystem    bool                 `bson:"is_system" json:"is_system"`
	CreatedAt   time.Time            `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time            `bson:"updated_at" json:"updated_at"`
	CreatedBy   string               `bson:"created_by" json:"created_by"`
	UpdatedBy   string               `bson:"updated_by,omitempty" json:"updated_by,omitempty"`
}

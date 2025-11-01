package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Menu struct {
	ID        primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	Title     string              `bson:"title" json:"title" binding:"required"`
	URL       string              `bson:"url" json:"url"`
	Type      string              `bson:"type" json:"type" binding:"required"` // "frontend" veya "backend"
	ParentID  *primitive.ObjectID `bson:"parent_id,omitempty" json:"parent_id,omitempty"`
	Order     int                 `bson:"order" json:"order"`
	Visible   bool                `bson:"visible" json:"visible"`
	Roles     []string            `bson:"roles" json:"roles"` // "admin", "editor", "user", "all"
	CreatedAt time.Time           `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time           `bson:"updated_at" json:"updated_at"`
	CreatedBy string              `bson:"created_by" json:"created_by"`
	UpdatedBy string              `bson:"updated_by" json:"updated_by"`
}

package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ContactMessage struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name       string             `bson:"name" json:"name" binding:"required"`
	Email      string             `bson:"email" json:"email" binding:"required,email"`
	Subject    string             `bson:"subject" json:"subject"`
	Message    string             `bson:"message" json:"message" binding:"required"`
	Status     string             `bson:"status" json:"status"` // "new", "in_progress", "resolved"
	CreatedAt  time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt  time.Time          `bson:"updated_at" json:"updated_at"`
	ResolvedBy string             `bson:"resolved_by,omitempty" json:"resolved_by,omitempty"`
}

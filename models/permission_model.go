package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Permission struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Module    string             `bson:"module" json:"module"`
	Actions   []string           `bson:"actions" json:"actions"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
	CreatedBy string             `bson:"created_by" json:"created_by"`
	UpdatedBy string             `bson:"updated_by" json:"updated_by"`
}

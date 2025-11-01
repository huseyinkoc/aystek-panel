package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Comment struct {
	ID        primitive.ObjectID   `bson:"_id,omitempty" json:"id,omitempty"`
	PostID    primitive.ObjectID   `bson:"post_id,omitempty" json:"post_id,omitempty"`
	ParentID  *primitive.ObjectID  `bson:"parent_id,omitempty" json:"parent_id,omitempty"`
	UserID    primitive.ObjectID   `bson:"user_id,omitempty" json:"user_id,omitempty"`
	Content   string               `bson:"content,omitempty" json:"content,omitempty"`
	Likes     int                  `bson:"likes,omitempty" json:"likes,omitempty"`
	Reactions map[string]int       `bson:"reactions,omitempty" json:"reactions,omitempty"` // Reaksiyonlar (emoji ifadesi ve sayısı)
	Replies   []primitive.ObjectID `bson:"replies,omitempty" json:"replies,omitempty"`
	CreatedAt time.Time            `bson:"created_at,omitempty" json:"created_at,omitempty"`
	UpdatedAt time.Time            `bson:"updated_at,omitempty" json:"updated_at,omitempty"`
}

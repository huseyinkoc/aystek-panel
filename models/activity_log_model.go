package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ActivityLog represents a user activity log
type ActivityLog struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID    primitive.ObjectID `bson:"user_id" json:"user_id"`     // Aktiviteyi gerçekleştiren kullanıcı
	Username  string             `bson:"username" json:"username"`   // Kullanıcı adı
	Module    string             `bson:"module" json:"module"`       // Modül adı (örnek: posts, comments)
	Action    string             `bson:"action" json:"action"`       // Eylem türü (örnek: create, update, delete)
	Details   string             `bson:"details" json:"details"`     // Ek detaylar
	Timestamp time.Time          `bson:"timestamp" json:"timestamp"` // Zaman damgası
}

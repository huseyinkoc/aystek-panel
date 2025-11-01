package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Media struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	FileName   string             `bson:"file_name" json:"file_name"`
	FilePath   string             `bson:"file_path" json:"file_path"`
	FileType   string             `bson:"file_type" json:"file_type"`
	FileSize   int64              `json:"file_size" example:"102400"`
	UploadedAt int64              `bson:"uploaded_at" json:"uploaded_at"`
	UploadedBy string             `json:"uploaded_by" example:"admin"`
}

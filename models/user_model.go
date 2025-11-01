package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User represents the user schema
type User struct {
	ID                primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name              string             `bson:"name" json:"name" binding:"required"`       // Kullanıcının adı
	Surname           string             `bson:"surname" json:"surname" binding:"required"` // Kullanıcının soyadı
	FullName          string             `bson:"full_name" json:"full_name"`                // Otomatik oluşturulan tam ad
	Email             string             `bson:"email" json:"email" binding:"required,email"`
	PhoneNumber       string             `bson:"phone_number" json:"phone_number" binding:"omitempty,e164"`
	PreferredLanguage string             `bson:"preferred_language" json:"preferred_language"` // Kullanıcı tercihi
	Username          string             `bson:"username" json:"username" binding:"required"`
	Password          string             `bson:"password" json:"password" binding:"required"`
	Roles             []string           `bson:"roles" json:"roles" binding:"required"` // ["admin", "editor", "user"]
}

type ResetPasswordRequest struct {
	NewPassword string `json:"new_password" example:"newpassword123"`
}

type RequestPasswordReset struct {
	Email string `json:"email" example:"abc@mail.com"`
}

type LoginByUsername struct {
	Username string `json:"username" example:"mustafakemal"`
	Password string `json:"password" example:"ADsdsasWDD!!!8"`
}

type LoginByEmail struct {
	Email    string `json:"email" example:"mustafakemal@ataturk.tr"`
	Password string `json:"password" example:"ADsdsasWDD!!!8"`
}

type LoginByPhone struct {
	PhoneNumber string `json:"phone_number" example:"+905551112233"`
	Password    string `json:"password" example:"ADsdsasWDD!!!8"`
}

// PreferredLanguageRequest represents a request to update the preferred language
type PreferredLanguageRequest struct {
	LanguageCode string `json:"language_code" binding:"required" example:"en"`
}

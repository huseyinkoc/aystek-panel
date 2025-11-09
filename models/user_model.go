package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

// User represents the user schema
type User struct {
	ID                primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name              string             `bson:"name" json:"name" binding:"required"`
	Surname           string             `bson:"surname" json:"surname" binding:"required"`
	FullName          string             `bson:"full_name" json:"full_name"`
	Email             string             `bson:"email" json:"email" binding:"required,email"`
	PhoneNumber       string             `bson:"phone_number,omitempty" json:"phone_number,omitempty"`
	PreferredLanguage string             `bson:"preferred_language" json:"preferred_language"`
	Username          string             `bson:"username" json:"username" binding:"required"`
	Password          string             `bson:"password" json:"password"`
	Roles             []string           `bson:"roles" json:"roles"`
	IsEmailVerified   bool               `bson:"is_email_verified" json:"is_email_verified"`
	IsApprovedByAdmin bool               `bson:"is_approved_by_admin" json:"is_approved_by_admin"`
	CreatedAt         time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt         time.Time          `bson:"updated_at" json:"updated_at"`
}

type RegisterRequest struct {
	Username    string `json:"username" binding:"required,min=3,max=30"`
	Email       string `json:"email" binding:"required,email"`
	Password    string `json:"password" binding:"required,min=6"`
	FirstName   string `json:"first_name" binding:"required"`
	LastName    string `json:"last_name" binding:"required"`
	PhoneNumber string `json:"phone_number" binding:"required"` // YENİ
}

type ResetPasswordRequest struct {
	NewPassword string `json:"new_password" example:"newpassword123"`
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

type PreferredLanguageRequest struct {
	LanguageCode string `json:"language_code" binding:"required" example:"en"`
}

package services

import (
	"admin-panel/models"
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var passwordResetCollection *mongo.Collection

// InitPasswordResetService - diğer servislerle aynı imza
func InitPasswordResetService(client *mongo.Client) {
	passwordResetCollection = client.Database("admin_panel").Collection("password_reset_tokens")
}

// Token oluştur ve kaydet
func CreatePasswordResetToken(ctx context.Context, email string, token string, expiresAt time.Time) error {
	resetToken := models.PasswordResetToken{
		ID:        primitive.NewObjectID(),
		Email:     email,
		Token:     token,
		ExpiresAt: expiresAt,
		Used:      false,
		CreatedAt: time.Now(),
	}

	_, err := passwordResetCollection.InsertOne(ctx, resetToken)
	return err
}

// Token'ı doğrula
func ValidatePasswordResetToken(ctx context.Context, token string) (string, error) {
	var resetToken models.PasswordResetToken

	err := passwordResetCollection.FindOne(ctx, bson.M{
		"token":      token,
		"used":       false,
		"expires_at": bson.M{"$gt": time.Now()},
	}).Decode(&resetToken)

	if err != nil {
		return "", err
	}

	return resetToken.Email, nil
}

// Token'ı kullanıldı olarak işaretle
func MarkPasswordResetTokenAsUsed(ctx context.Context, token string) error {
	_, err := passwordResetCollection.UpdateOne(
		ctx,
		bson.M{"token": token},
		bson.M{"$set": bson.M{"used": true, "used_at": time.Now()}},

	)
	return err
}

// Süresi dolmuş tokenları temizle
func CleanupExpiredPasswordResetTokens(ctx context.Context) error {
	_, err := passwordResetCollection.DeleteMany(ctx, bson.M{
		"expires_at": bson.M{"$lt": time.Now()},
	})
	return err
}

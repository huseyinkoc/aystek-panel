package services

import (
	"admin-panel/models"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var passwordResetCollection *mongo.Collection

func InitPasswordResetService(client *mongo.Client) {
	passwordResetCollection = client.Database("admin_panel").Collection("password_resets")
}

func GeneratePasswordResetToken(ctx context.Context, userID primitive.ObjectID) (string, error) {
	// Rastgele token oluştur
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)

	// Token'ı kaydet
	resetToken := models.PasswordResetToken{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
	}

	_, err := passwordResetCollection.InsertOne(ctx, resetToken)
	if err != nil {
		return "", err
	}

	return token, nil
}

func VerifyPasswordResetToken(ctx context.Context, token string) (primitive.ObjectID, error) {
	// Token'ı bul
	var resetToken models.PasswordResetToken
	err := passwordResetCollection.FindOne(ctx, bson.M{"token": token}).Decode(&resetToken)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return primitive.NilObjectID, errors.New("invalid or expired token")
		}
		return primitive.NilObjectID, err
	}

	// Süresini kontrol et
	if time.Now().After(resetToken.ExpiresAt) {
		return primitive.NilObjectID, errors.New("token expired")
	}

	// Kullanıcı ID'sini döndür
	return resetToken.UserID, nil
}

func DeletePasswordResetToken(ctx context.Context, token string) error {
	_, err := passwordResetCollection.DeleteOne(ctx, bson.M{"token": token})
	return err
}

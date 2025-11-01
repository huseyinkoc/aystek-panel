package services

import (
	"admin-panel/models"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var emailVerificationCollection *mongo.Collection // MongoDB collection

func InitEmailVerificationService(client *mongo.Client) {
	emailVerificationCollection = client.Database("admin_panel").Collection("email_verifications")
}

func GenerateEmailVerificationToken(userID primitive.ObjectID) (string, error) {
	// Rastgele bir token oluştur
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)

	// Token veritabanına kaydet
	verificationToken := models.EmailVerificationToken{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	_, err := emailVerificationCollection.InsertOne(context.Background(), verificationToken)
	if err != nil {
		return "", err
	}

	return token, nil
}

// VerifyEmailToken verifies the email token and activates the user's account
func VerifyEmailToken(ctx context.Context, token string) error {
	var verificationToken models.EmailVerificationToken
	err := emailVerificationCollection.FindOne(ctx, bson.M{"token": token}).Decode(&verificationToken)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return errors.New("invalid or expired token")
		}
		return err
	}

	// Check if the token has expired
	if time.Now().After(verificationToken.ExpiresAt) {
		return errors.New("token expired")
	}

	// Call the user service to verify the account
	err = VerifyUserAccount(ctx, verificationToken.UserID)
	if err != nil {
		return err
	}

	// Delete the used token
	_, err = emailVerificationCollection.DeleteOne(ctx, bson.M{"_id": verificationToken.ID})
	if err != nil {
		return err
	}

	return nil
}

func SendVerificationEmail(ctx context.Context, userID primitive.ObjectID, token string) error {
	// Kullanıcı e-postasını al
	email, err := GetUserEmailByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to retrieve user email: %w", err)
	}

	// Doğrulama bağlantısını oluştur
	verificationURL := "http://localhost:8080/auth/verify?token=" + token
	subject := "Email Verification"
	body := "Click the following link to verify your email: " + verificationURL

	// E-posta gönder
	err = SendEmail([]string{email}, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	return nil
}
